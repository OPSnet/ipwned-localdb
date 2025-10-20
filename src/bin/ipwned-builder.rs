#[path = "../downloader.rs"]
mod downloader;
#[path = "../filter_builder.rs"]
mod filter_builder;
#[path = "../misc.rs"]
mod misc;
#[path = "../parse.rs"]
mod parse;
#[path = "../statedb.rs"]
mod statedb;

use crate::downloader::download_retry;
use crate::filter_builder::{FilterBuilder, FilterResult, HashList};
use crate::misc::{DownloadError, DownloadStatus, MAX_COUNT};
use crate::statedb::{State, StateDatabase};
use argh::FromArgs;
use chrono::{DateTime, FixedOffset, Local, NaiveDateTime, TimeDelta};
use futures;
use futures::{StreamExt, pin_mut, stream};
use indicatif;
use indicatif_log_bridge::LogWrapper;
use log::{LevelFilter, debug, error, info, warn};
use pretty_duration::pretty_duration;
use reqwest::Client;
use std::env::current_dir;
use std::fmt::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use tokio;
use tokio::sync::mpsc::Sender;

#[derive(FromArgs)]
/// Create or update a local lookup table for haveibeenpwned.com compromised passwords
struct CliArgs {
    /// base path to store filter and state db at. default: current directory
    #[argh(option, short = 'd', default = "current_dir().unwrap()")]
    base_path: PathBuf,

    /// file name of the state database file. default: ipwned_state.sqlite
    #[argh(option, short = 's', default = "String::from(\"ipwned_state.sqlite\")")]
    state_db_name: String,

    /// file name of the lookup filter file. default: ipwned_qfilter.cbor
    #[argh(option, short = 'f', default = "String::from(\"ipwned_qfilter.cbor\")")]
    filter_name: String,

    /// maximum age of a downloaded file before attempting an update. accepts a human-friendly string. default: 1 month
    #[argh(option, short = 'a', default = "String::from(\"1 month\")")]
    max_age: String,

    /// number of parallel download requests. default: 50
    #[argh(option, short = 'n', default = "50")]
    parallel: usize,

    /// update only ids starting from here. default: 0
    #[argh(option, default = "0")]
    start: u32,

    /// update only ids up to this id (inclusive). default: all (1048575)
    #[argh(option, default = "MAX_COUNT")]
    end: u32,

    /// maximum number of hashes to track in filter. If this number is exceeded a new filter must be built. This will influence the size of the filter. Only relevant when creating a new filter. default: 1_500_000_000
    #[argh(option, short = 'c', default = "1_500_000_000")]
    max_count: u64,

    /// maximum error rate (false positives) for filter. This will influence the size of the filter. Only relevant when creating a new filter. default: 0.000001
    #[argh(option, short = 'e', default = "0.000001")]
    max_error_rate: f64,

    /// override base url for downloading hash lists. default: https://api.pwnedpasswords.com/range/
    #[argh(
        option,
        short = 'b',
        default = "String::from(\"https://api.pwnedpasswords.com/range/\")"
    )]
    base_url: String,

    /// maximum number of retries when downloading a hash list in case of errors. default: 10
    #[argh(option, short = 'r', default = "10")]
    max_retries: u16,

    /// log level. allowed options: off error warn info debug trace. default: warn
    #[argh(option, short = 'l', default = "String::from(\"warn\")")]
    log: String,
}

impl CliArgs {
    pub fn state_db_path(&self) -> PathBuf {
        let mut path = self.base_path.to_owned();
        path.push(&self.state_db_name);
        path
    }

    pub fn filter_path(&self) -> PathBuf {
        let mut path = self.base_path.to_owned();
        path.push(&self.filter_name);
        path
    }

    pub fn log_level(&self) -> LevelFilter {
        LevelFilter::from_str(&self.log).unwrap()
    }
}

#[derive(Debug)]
struct Status {
    pub total: u32,
    pub skipped: u32,
    pub downloaded: u32,
    pub downloaded_bytes: u64,
    pub hashes: u32,
    pub hashes_new: u32,
    pub error: u32,
    pub processed: u32,
}

impl Status {
    pub fn new(total: u32) -> Status {
        Status {
            total: total,
            skipped: 0,
            downloaded: 0,
            downloaded_bytes: 0,
            hashes: 0,
            hashes_new: 0,
            error: 0,
            processed: 0,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: CliArgs = argh::from_env();

    if args.start > args.end || args.end > MAX_COUNT {
        println!("bad start/end parameters");
        return ExitCode::from(255);
    }

    let mut status = Status::new(args.end - args.start + 1);
    let bars = build_progress_meter(&status);

    init_logger(args.log_level(), bars.multi.clone());
    let state_db = StateDatabase::open(&args.state_db_path()).await;
    if state_db.is_err() {
        error!(
            "Failed to open sqlite database: {}",
            state_db.err().unwrap()
        );
        return ExitCode::from(1);
    }
    let state_db = state_db.unwrap();
    if state_db.is_readonly().await {
        error!("Failed to open sqlite database with write permissions.");
        return ExitCode::from(1);
    }

    let mut exit_code: u8 = 0;
    let client = Client::new();

    let parsed_duration: Duration = parse_duration::parse(&args.max_age).unwrap();
    let min_file_age_duration: TimeDelta = TimeDelta::from_std(parsed_duration).unwrap();
    let now = Local::now().fixed_offset();
    let max_age = now - min_file_age_duration;

    {
        let mut filter_builder =
            FilterBuilder::new(args.filter_path(), args.max_count, args.max_error_rate);
        let schedule_downloads = stream::iter(args.start..=args.end)
            .map(|i| {
                schedule_download(
                    i,
                    &client,
                    &args.base_url,
                    args.max_retries,
                    &filter_builder.in_tx,
                    &state_db,
                    max_age,
                )
            })
            .buffer_unordered(args.parallel);
        pin_mut!(schedule_downloads);

        let mut do_exit = false;
        loop {
            let mut update = false;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    do_exit = true;
                    break;
                },
                x = schedule_downloads.next() => {
                    if x.is_some() {
                        let result = x.unwrap();
                        if !handle_download_status(&result, &mut status, &filter_builder.in_tx).await {
                            exit_code = 2;
                            break;
                        }
                        update = true;
                    }
                },
                x = filter_builder.out_rx.recv() => {
                    match x {
                        Some(Some(x)) => {
                            handle_result(x, &mut status, &state_db).await;
                            update = true;
                        },
                        _ => break,
                    }
                }
            }
            if update {
                bars.update(&status);
            }
        }

        if do_exit {
            // we received a ctrl+c, process all downloaded files and terminate
            warn!("received ctrl+c, waiting for workers to finish");
            // signal our worker threads to exit
            if filter_builder.in_tx.send(None).await.is_ok() {
                // if something went wrong we can just quit, otherwise wait for everything to finish
                loop {
                    match filter_builder.out_rx.recv().await {
                        Some(Some(x)) => {
                            handle_result(x, &mut status, &state_db).await;
                            bars.update(&status);
                        }
                        _ => break,
                    }
                }
            }
        }
    }

    bars.update(&status);
    bars.finish();

    if state_db.close().await.is_err() {
        error!("Failed to update state database.");
        exit_code = 3;
    }
    ExitCode::from(exit_code)
}

struct ProgressBars {
    pub multi: indicatif::MultiProgress,
    overview: indicatif::ProgressBar,
    bar: indicatif::ProgressBar,
}

impl ProgressBars {
    pub fn update(&self, status: &Status) {
        let msg = format!(
            "{}/{},  skipped: {}, downloaded: {}, errors: {}",
            status.hashes_new, status.hashes, status.skipped, status.downloaded, status.error
        );
        self.overview.set_length(status.downloaded_bytes);
        self.overview.set_position(status.downloaded_bytes);
        self.overview.set_message(msg);
        self.bar.set_position(status.processed as u64);
    }

    pub fn finish(&self) {
        self.overview.finish();
        self.bar.finish();
    }
}

fn build_progress_meter(status: &Status) -> ProgressBars {
    let m = indicatif::MultiProgress::new();
    let overview = m.add(indicatif::ProgressBar::new(0));
    let bar = m.add(indicatif::ProgressBar::new(status.total as u64));
    let overview_style = indicatif::ProgressStyle::with_template(
        "{spinner} new hashes: {msg}, DL size: {bytes} ({binary_bytes_per_sec})",
    )
    .unwrap();
    let bar_style = indicatif::ProgressStyle::with_template(
        "[{elapsed_precise}] [{percent}%] [{wide_bar:.cyan/blue}] {pos:>7}/{len} ({per_sec}) ({eta})",
    )
    .unwrap()
    .with_key(
        "eta",
        |state: &indicatif::ProgressState, w: &mut dyn Write| {
            write!(w, "{}", pretty_duration(&state.eta(), None)).unwrap()
        },
    );
    bar.set_style(bar_style);
    overview.set_style(overview_style);
    ProgressBars {
        multi: m,
        overview: overview,
        bar: bar,
    }
}

fn init_logger(level: LevelFilter, multibar: indicatif::MultiProgress) {
    let logger = simplelog::SimpleLogger::new(level, simplelog::Config::default());
    LogWrapper::new(multibar.clone(), logger)
        .try_init()
        .unwrap();
}

async fn schedule_download(
    hash_list_id: u32,
    client: &Client,
    base_url: &String,
    max_retries: u16,
    hash_list_chan: &Sender<Option<HashList>>,
    state_db: &StateDatabase,
    max_age: DateTime<FixedOffset>,
) -> Result<usize, DownloadStatus> {
    let state = state_db.fetch(hash_list_id).await;
    let mut etag: Option<String> = None;
    let need_update = check_db_state(max_age, &mut etag, state);
    if !need_update {
        return Err(DownloadStatus::Skipped {});
    }
    let hash_prefix = format!("{:0>5X}", hash_list_id);
    let res = download_retry(client, base_url, &hash_prefix, etag, max_retries)
        .await
        .map_err(|err: DownloadError| {
            if err.status_code.unwrap_or(0_u16) == 304_u16 {
                return DownloadStatus::NotOutdated {};
            }
            DownloadStatus::HTTPError(err)
        })?;
    let data_len = res.data.len();
    if hash_list_chan
        .send(Some(HashList {
            id: hash_list_id,
            data: res.data,
            etag: res.etag,
        }))
        .await
        .is_err()
    {
        error!("INTERNAL: unexpectedly terminated FilterBuilder main channel");
        return Err(DownloadStatus::InternalError {});
    }
    Ok(data_len)
}

fn check_db_state(
    max_age: DateTime<FixedOffset>,
    etag: &mut Option<String>,
    state: Result<Option<State>, tokio_rusqlite::Error>,
) -> bool {
    let mut need_update = true;
    if state.is_ok() {
        if let Some(state) = state.unwrap() {
            if let Ok(time) = NaiveDateTime::parse_from_str(&state.last_update, "%Y-%m-%d %H:%M:%S") {
                let time = time.and_utc().fixed_offset();
                need_update = max_age > time;
            }
            if state.etag.is_some() {
                *etag = Some(state.etag.unwrap());
            }
        }
    }
    need_update
}

async fn handle_download_status(
    result: &Result<usize, DownloadStatus>,
    status: &mut Status,
    done_channel: &Sender<Option<HashList>>,
) -> bool {
    status.processed += 1;
    match result {
        Ok(size) => {
            status.downloaded += 1;
            status.downloaded_bytes += *size as u64;
        }
        Err(DownloadStatus::Skipped()) => status.skipped += 1,
        Err(DownloadStatus::NotOutdated()) => status.skipped += 1,
        Err(_) => status.error += 1,
    }
    if status.processed == status.total {
        if done_channel.send(None).await.is_err() {
            error!("INTERNAL: channel to FilterBuilder thread unexpectedly closed");
            // exit, the handle_result branch will likely never finish
            return false;
        }
        debug!("successfully scheduled all downloads");
    }
    true
}

async fn handle_result(result: FilterResult, status: &mut Status, state_db: &StateDatabase) {
    status.hashes += result.total;
    status.hashes_new += result.added;
    if !state_db.update(result.id, result.etag).await {
        error!("failed to update state db for id {}", result.id);
    }
}

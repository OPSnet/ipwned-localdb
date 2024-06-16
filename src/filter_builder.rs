use crate::parse::parse_file;
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use qfilter;
use ciborium;
use std::fs::File;
use std::io::ErrorKind::NotFound;
use std::path::PathBuf;
use std::thread;
use tokio::sync::mpsc;

const CHANNEL_BUFF_SIZE: usize = 50;

#[derive(Debug)]
pub struct HashList {
    pub id: u32,
    pub data: Bytes,
    pub etag: Option<String>,
}

#[derive(Debug)]
pub struct FilterResult {
    pub id: u32,
    pub total: u32,
    pub added: u32,
    pub etag: Option<String>,
}

#[derive(Debug)]
struct ParseResult {
    pub id: u32,
    pub hashes: Vec<Bytes>,
    pub etag: Option<String>,
}

pub struct FilterBuilder {
    pub in_tx: mpsc::Sender<Option<HashList>>,
    pub out_rx: mpsc::Receiver<Option<FilterResult>>,
}

fn work_parse(
    in_rx: &mut mpsc::Receiver<Option<HashList>>,
    out_tx: mpsc::Sender<Option<ParseResult>>,
) {
    loop {
        let list = match in_rx.blocking_recv() {
            Some(Some(x)) => x,
            _ => break,
        };
        let hashes = parse_file(list.id, &list.data);
        if hashes.is_err() {
            warn!("failed to parse hash list for id {}", list.id);
            continue;
        }
        let (remainder, hashes) = hashes.unwrap();
        if remainder.len() > 2 {
            // at most there should be \r\n left
            warn!(
                "problem parsing hash list for id {}: {} unparsed characters",
                list.id,
                remainder.len()
            );
        }
        trace!("work_parse: {:?}", &hashes);
        let res = ParseResult {
            id: list.id,
            hashes: hashes,
            etag: list.etag,
        };
        if out_tx.blocking_send(Some(res)).is_err() {
            error!("INTERNAL: unexpectedly terminated parser thread channel");
            in_rx.close();
            return;
        }
        trace!(
            "work_parse weak: {}, strong: {}, cap: {}",
            out_tx.weak_count(),
            out_tx.strong_count(),
            out_tx.capacity()
        );
    }
    debug!("cleanly exiting parser thread");
    let _ = out_tx.blocking_send(None);
    in_rx.close();
}

fn work_build(
    in_rx: &mut mpsc::Receiver<Option<ParseResult>>,
    out_tx: mpsc::Sender<Option<FilterResult>>,
    file_name: PathBuf,
    filter: &mut qfilter::Filter,
) {
    let mut changed = false;
    'mainloop:  loop {
        let mut added: u32 = 0;
        let parsed = match in_rx.blocking_recv() {
            Some(Some(x)) => x,
            _ => break,
        };
        for hash in &parsed.hashes {
            match filter.insert(hash) {
                Ok(true) => added += 1,
                Ok(false) => {}
                Err(_) => {
                    error!("unable to add more items to filter");
                    break 'mainloop;
                }
            }
        }
        let res = FilterResult {
            id: parsed.id,
            total: parsed.hashes.len() as u32,
            added: added,
            etag: parsed.etag,
        };
        if added > 0 {
            changed = true;
        }
        if out_tx.blocking_send(Some(res)).is_err() {
            error!("INTERNAL: unexpectedly terminated builder thread channel");
            in_rx.close();
            break;
        }
        trace!(
            "work_build weak: {}, strong: {}, cap: {}",
            out_tx.weak_count(),
            out_tx.strong_count(),
            out_tx.capacity()
        );
    }
    debug!("cleanly exiting builder thread");
    if changed {
        'write: {
            let file_name_str = file_name.to_str().unwrap();
            let mut tmp_name = String::from(file_name_str);
            tmp_name.push_str(".new");
            let mut writer = match File::create(&tmp_name) {
                Ok(x) => x,
                Err(e) => {
                    error!("failed to open new filter file: {:?}", e);
                    break 'write;
                }
            };
            match ciborium::into_writer(filter, &mut writer) {
                Err(e) => {
                    error!("failed to write new filter file: {:?}", e);
                    break 'write;
                }
                _ => (),
            }
            match std::fs::rename(&tmp_name, &file_name) {
                Err(e) => error!(
                    "failed to rename {} to {}: {:?}",
                    tmp_name, file_name_str, e
                ),
                _ => info!("successfully created new filter file at {}", file_name_str),
            }
        }
    }
    let _ = out_tx.blocking_send(None);
    in_rx.close();
}

impl FilterBuilder {
    pub fn new(file_name: PathBuf, max_entries: u64, max_error_rate: f64) -> FilterBuilder {
        let mut filter = Self::open_filter_maybe(&file_name, max_entries, max_error_rate);
        let (in_tx, mut in_rx) = mpsc::channel::<Option<HashList>>(CHANNEL_BUFF_SIZE);
        let (tx_mid, mut rx_mid) = mpsc::channel::<Option<ParseResult>>(CHANNEL_BUFF_SIZE);
        let (out_tx, out_rx) = mpsc::channel::<Option<FilterResult>>(CHANNEL_BUFF_SIZE);
        thread::Builder::new()
            .name(String::from("Parser"))
            .spawn(move || work_parse(&mut in_rx, tx_mid))
            .unwrap();
        thread::Builder::new()
            .name(String::from("FilterBuilder"))
            .spawn(move || work_build(&mut rx_mid, out_tx, file_name, &mut filter))
            .unwrap();
        FilterBuilder {
            in_tx: in_tx,
            out_rx: out_rx,
        }
    }

    fn open_filter_maybe(file_name: &PathBuf, max_entries: u64, max_er: f64) -> qfilter::Filter {
        let filter_file = File::open(file_name);
        match filter_file {
            Err(ref e) if e.kind() == NotFound => qfilter::Filter::new(max_entries, max_er),
            Err(e) => panic!("unable to open filter file: {:?}", e),
            Ok(ref fh) => {
                let filter_maybe = ciborium::from_reader(fh);
                if filter_maybe.is_err() {
                    panic!("failed to read filter file: {:?}", filter_maybe.err());
                }
                filter_maybe.unwrap()
            }
        }
    }
}

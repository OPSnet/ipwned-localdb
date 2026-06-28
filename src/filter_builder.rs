use crate::parse::parse_file;
use bytes::Bytes;
use hasher::U64TruncateBuildHasher;
use log::{debug, error, info, trace, warn};
use memmap2::Mmap;
use postcard;
use qfilter::Filter;
use std::fs::File;
use std::io::ErrorKind::NotFound;
use std::path::PathBuf;
use std::thread;
use tokio::sync::mpsc;

mod hasher;

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
        let Some(Some(list)) = in_rx.blocking_recv() else {
            break;
        };
        let res = match parse_hash_list(&list) {
            Some(value) => value,
            None => continue,
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

fn parse_hash_list(list: &HashList) -> Option<ParseResult> {
    let Ok((remainder, hashes)) = parse_file(list.id, &list.data) else {
        warn!("failed to parse hash list for id {}", list.id);
        return None;
    };
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
        etag: list.etag.clone(),
    };
    Some(res)
}

fn work_build(
    in_rx: &mut mpsc::Receiver<Option<ParseResult>>,
    out_tx: mpsc::Sender<Option<FilterResult>>,
    file_name: PathBuf,
    filter: &mut Filter<Box<[u8]>, U64TruncateBuildHasher>,
) {
    let mut changed = false;
    loop {
        let Some(Some(parsed)) = in_rx.blocking_recv() else {
            break;
        };
        let res = match process_hash_list(filter, &parsed) {
            Some(value) => value,
            None => break,
        };
        changed |= res.added > 0;
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
        write_filter_file(&file_name, filter);
    }
    let _ = out_tx.blocking_send(None);
    in_rx.close();
}

fn write_filter_file(file_name: &PathBuf, filter: &mut Filter<Box<[u8]>, U64TruncateBuildHasher>) {
    let tmp_name = file_name.with_added_extension("new");
    let mut writer = match File::create(&tmp_name) {
        Ok(x) => x,
        Err(e) => {
            error!("failed to open new filter file: {:?}", e);
            return;
        }
    };
    debug!("writing filter to {}", tmp_name.display());
    if let Err(e) = postcard::to_io(filter, &mut writer) {
        error!("failed to write new filter file: {:?}", e);
        return;
    }
    debug!("renaming filter from {} to {}", tmp_name.display(), file_name.display());
    if let Err(e) = std::fs::rename(&tmp_name, &file_name) {
        error!(
            "failed to rename {} to {}: {:?}",
            tmp_name.display(), file_name.display(), e
        );
        return;
    }
    info!("successfully created new filter file at {}", file_name.display());
}

fn process_hash_list(
    filter: &mut Filter<Box<[u8]>, U64TruncateBuildHasher>,
    parsed: &ParseResult,
) -> Option<FilterResult> {
    let mut added = 0;
    for hash in &parsed.hashes {
        match filter.insert(hash) {
            Ok(true) => added += 1,
            Ok(false) => {}
            Err(_) => {
                error!("unable to add more items to filter");
                return None;
            }
        }
    }
    let res = FilterResult {
        id: parsed.id,
        total: parsed.hashes.len() as u32,
        added: added,
        etag: parsed.etag.clone(),
    };
    Some(res)
}

impl FilterBuilder {
    pub fn new(file_name: PathBuf, max_entries: u64) -> FilterBuilder {
        let mut filter = Self::open_filter_maybe(&file_name, max_entries);
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
        FilterBuilder { in_tx, out_rx }
    }

    fn open_filter_maybe(
        file_name: &PathBuf,
        max_entries: u64
    ) -> Filter<Box<[u8]>, U64TruncateBuildHasher> {
        let filter_file = File::open(file_name);
        match filter_file {
            Err(ref e) if e.kind() == NotFound => {
                Filter::with_fingerprint_size_and_hasher(max_entries.checked_div(2).unwrap(), 64, U64TruncateBuildHasher {})
                    .expect("failed to initialize new filter")
            }
            Err(e) => panic!("unable to open filter file: {:?}", e),
            Ok(fh) => {
                let mmap = unsafe { Mmap::map(&fh) }
                    .unwrap_or_else(|e| panic!("mmap failed: {:?}", e));
                let filter =
                    postcard::from_bytes::<Filter<Box<[u8]>, U64TruncateBuildHasher>>(&mmap)
                        .unwrap_or_else(|e| panic!("failed to load filter file: {:?}", e));
                filter
            }
        }
    }
}

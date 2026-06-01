use argh::FromArgs;
use hasher::U64TruncateBuildHasher;
use memmap2::Mmap;
use qfilter::FilterRef;
use rocket::http::Status;
use rocket::shield::Shield;
use std::fs::File;
use std::path::PathBuf;

#[path = "../hasher.rs"]
mod hasher;

#[derive(FromArgs)]
/// run an HTTP server for querying a local haveibeenpwned.com password lookup table
struct CliArgs {
    /// file name of the lookup filter file. default: ipwned_qfilter.data
    #[argh(option, short = 'f', default = "String::from(\"ipwned_qfilter.data\")")]
    filter_path: String,
}

struct FilterHandle<'a> {
    _mmap: Mmap,
    filter: FilterRef<'a, U64TruncateBuildHasher>,
}

#[rocket::post("/", data = "<hash>")]
fn check_hash(hash: &[u8], filter_handle: &rocket::State<FilterHandle>) -> Status {
    let mut status = 204;
    if hash.len() != 20 {
        status = 400;
    } else if filter_handle.filter.contains(hash) {
        status = 205;
    }
    Status { code: status }
}

#[rocket::launch]
fn rocket_launch() -> _ {
    let args: CliArgs = argh::from_env();
    let filter = open_filter(PathBuf::from(args.filter_path));
    rocket::build()
        .attach(Shield::new())
        .manage(filter)
        .mount("/", rocket::routes![check_hash])
}

fn open_filter<'a>(file_name: PathBuf) -> FilterHandle<'a> {
    let filter_file = File::open(file_name)
        .unwrap_or_else(|e| panic!("unable to open filter file: {:?}", e));
    let mmap = unsafe { Mmap::map(&filter_file) }
        .unwrap_or_else(|e| panic!("unable to mmap filter file: {:?}", e));
    let filter: FilterRef<'_, U64TruncateBuildHasher> = postcard::from_bytes(&mmap)
        .unwrap_or_else(|e| panic!("failed to read filter file: {:?}", e));
    let filter: FilterRef<'a, U64TruncateBuildHasher> =
        unsafe { std::mem::transmute(filter) };
    FilterHandle {
        _mmap: mmap,
        filter,
    }
}

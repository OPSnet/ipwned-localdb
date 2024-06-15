use argh::FromArgs;
use rocket::http::Status;
use rocket::shield::Shield;
use std::fs::File;
use std::path::PathBuf;

#[derive(FromArgs)]
/// run an HTTP server for querying a local haveibeenpwned.com password lookup table
struct CliArgs {
    /// file name of the lookup filter file. default: ./ipwned_qfilter.cbor
    #[argh(option, short = 'f', default = "String::from(\"ipwned_qfilter.cbor\")")]
    filter_path: String,
}

#[rocket::post("/", data = "<hash>")]
fn check_hash(hash: &[u8], filter: &rocket::State<qfilter::Filter>) -> Status {
    let mut status = 204;
    if hash.len() != 20 {
        status = 400;
    } else if filter.contains(hash) {
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

fn open_filter(file_name: PathBuf) -> qfilter::Filter {
    let filter_file = File::open(file_name);
    if filter_file.is_err() {
        panic!("unable to open filter file: {:?}", filter_file.err());
    }

    let filter_maybe = ciborium::from_reader(filter_file.unwrap());
    if filter_maybe.is_err() {
        panic!("failed to read filter file: {:?}", filter_maybe.err());
    }
    filter_maybe.unwrap()
}

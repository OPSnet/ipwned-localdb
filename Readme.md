# ipwned-localdb

A program to download and efficiently store the hashed password lists offered by haveibeenpwned.com for local queries.

## Features

* multithreaded downloading of hash lists
* storing hashes in a RSQF lookup table (comparable to bloom, cuckoo but more efficient) [1]
* allows periodically updating lists without full filter rebuild
* query interface is exposed through an HTTP service

[1] see https://docs.rs/qfilter/latest/qfilter/

## Notes

With default settings the filter table will be a bit larger than 3gb. The HTTP server is serving this table from RAM,
meaning the service will require at least that much RAM to run.

As of June 13th 2024 there are 936_494_661 compromised passwords in the HIBP database. Downloading and building the
filter table on my test system took about 20 minutes, network-limited at 30 MiB/s on average, with 500 parallel requests.

## build

    git clone https://github.com/OPSnet/ipwned-localdb
    cd ipwned-localdb
    cargo build --release

Requires rust 1.85.0 or newer. You may need to install openssl and sqlite3 devel packages and pkg-config on your system.
On debian this corresponds to `libssl-dev` and `libsqlite3-dev`.

## run

### create lookup table

for creating or updating your local filter run

    ./target/release/ipwned-builder

settings can be adjusted, see `--help`, but the defaults should work for most people

### serve lookup table

    ./target/release/ipwned-server

see `Rocket.toml.example` for adjusting the HTTP server settings. The `Rocket.toml` is expected in the current directory.

## Usage

### ipwned-builder

    Usage: ipwned-builder [-d <base-path>] [-s <state-db-name>] [-f <filter-name>] [-a <max-age>] [-n <parallel>] [--start <start>] [--end <end>] [-c <max-count>] [-e <max-error-rate>] [-b <base-url>] [-r <max-retries>] [-l <log>]

    Create or update a local lookup table for haveibeenpwned.com compromised passwords

    Options:
    -d, --base-path   base path to store filter and state db at. default: current
                      directory
    -s, --state-db-name
                      file name of the state database file. default:
                      ipwned_state.sqlite
    -f, --filter-name file name of the lookup filter file. default:
                      ipwned_qfilter.cbor
    -a, --max-age     maximum age of a downloaded file before attempting an
                      update. accepts a human-friendly string. default: 1 month
    -n, --parallel    number of parallel download requests. default: 50
    --start           update only ids starting from here. default: 0
    --end             update only ids up to this id (inclusive). default: all
                      (1048575)
    -c, --max-count   maximum number of hashes to track in filter. If this number
                      is exceeded a new filter must be built. This will influence
                      the size of the filter. Only relevant when creating a new
                      filter. default: 1_000_000_000
    -e, --max-error-rate
                      maximum error rate (false positives) for filter. This will
                      influence the size of the filter. Only relevant when
                      creating a new filter. default: 0.0000001
    -b, --base-url    override base url for downloading hash lists. default:
                      https://api.pwnedpasswords.com/range/
    -r, --max-retries maximum number of retries when downloading a hash list in
                      case of errors. default: 10
    -l, --log         log level. allowed options: off error warn info debug trace.
                      default: warn
    --help            display usage information




### ipwned-server

    Usage: ipwned-server [-f <filter-path>]
    
    run an HTTP server for querying a local haveibeenpwned.com password lookup table
    
    Options:
    -f, --filter-path file name of the lookup filter file. default:
                      ./ipwned_qfilter.cbor
    --help            display usage information


## HTTP API

POST requests are expected on `/` with the request body being the binary SHA1 hash (20 bytes) of the password to check.

Response is encoded in the HTTP status code:

    204 -> not found, good password
    205 -> found, bad password

for testing:

    echo -n test | sha1sum | cut -c-40 | tr -d "\n" | xxd -r -p | curl -v http://127.0.0.1:7660/ --data-binary @-

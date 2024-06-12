use reqwest::header::ToStrError;
use std::fmt;
use std::fmt::Debug;

pub const MAX_COUNT: u32 = 16_u32.pow(5) - 1;

#[derive(Debug)]
pub enum DownloadStatus {
    Skipped(),
    NotOutdated(),
    InternalError(),
    HTTPError(DownloadError),
}

#[derive(Clone)]
pub struct DownloadError {
    pub status_code: Option<u16>,
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Failed to download hash list. HTTP status: {}",
            self.status_code
                .map_or(String::from("connection error"), |x| x.to_string())
        )
    }
}

impl fmt::Debug for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ file: {}, line: {} }}, {}", file!(), line!(), self)
    }
}

impl From<reqwest::Error> for DownloadError {
    fn from(value: reqwest::Error) -> Self {
        if value.status().is_some() {
            return DownloadError {
                status_code: Some(value.status().unwrap().as_u16()),
            };
        }
        DownloadError { status_code: None }
    }
}

impl From<ToStrError> for DownloadError {
    fn from(_: ToStrError) -> Self {
        DownloadError { status_code: None }
    }
}

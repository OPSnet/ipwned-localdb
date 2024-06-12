use crate::misc::DownloadError;
use bytes::Bytes;
use reqwest::Client;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct DownloadResult {
    pub data: Bytes,
    pub etag: Option<String>,
}

pub async fn download_retry(
    client: &Client,
    base_url: &String,
    prefix: &String,
    etag: Option<String>,
    max_retries: u16,
) -> Result<DownloadResult, DownloadError> {
    let mut timeout: f32 = 0.5;
    let mut res = Err(DownloadError { status_code: None });
    let mut url = base_url.to_owned();
    url.push_str(prefix);
    for i in 0..max_retries {
        res = download_remote_hashlist(client, &url, &etag).await;
        if res.is_ok() {
            return res;
        }
        let res_ref = res.clone();
        if res_ref.err().unwrap().status_code.unwrap_or(0) == 304 {
            return res;
        }
        if i < max_retries - 1 {
            sleep(Duration::from_secs_f32(timeout)).await;
            timeout *= 2.;
        }
    }
    res
}

pub async fn download_remote_hashlist(
    client: &Client,
    url: &String,
    etag: &Option<String>,
) -> Result<DownloadResult, DownloadError> {
    let mut req = client.get(url);
    if etag.is_some() {
        req = req.header("If-None-Match", etag.clone().unwrap());
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    if status == 200 {
        // FIXME: etag may have leading W/ - strip?
        let etag = resp
            .headers()
            .get("etag")
            .map_or(None, |x| Some(x.to_str().ok()?.to_string()));
        let body = resp.bytes().await?;
        return Ok(DownloadResult {
            data: body.clone(),
            etag: etag,
        });
    }
    Err(DownloadError {
        status_code: Some(status),
    })
}

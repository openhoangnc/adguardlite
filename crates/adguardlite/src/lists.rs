//! Downloading filter lists.
//!
//! The list *store* lives in `agl_filter::lists`; only fetching lives here, so
//! the filtering crate stays free of an HTTP client.

use std::time::Duration;

use agl_config::Paths;
use agl_filter::lists::{RefreshError, is_remote, local_list_path};

/// Fetches a list's contents from its URL or local path.
pub async fn fetch(
    paths: &Paths,
    url: &str,
    max_bytes: u64,
    timeout: Duration,
) -> Result<String, RefreshError> {
    if is_remote(url) {
        let body = crate::fetch::get(url, max_bytes, timeout)
            .await
            .map_err(|e| RefreshError::Download(e.to_string()))?;

        return String::from_utf8(body).map_err(|e| RefreshError::Download(e.to_string()));
    }

    let p = local_list_path(paths, url)?;

    std::fs::read_to_string(p).map_err(|e| RefreshError::Io(e.to_string()))
}

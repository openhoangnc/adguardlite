//! A small HTTPS client for downloading filter lists.
//!
//! Deliberately hand-rolled rather than pulling in a full HTTP client: the
//! needs here are narrow — GET, follow redirects, cap the body — and every
//! dependency added here shows up in build time and binary size.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, Uri};

/// A download failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL could not be parsed or is unsupported.
    #[error("bad url {0:?}: {1}")]
    Url(String, String),

    /// The connection failed.
    #[error("connecting to {0}: {1}")]
    Connect(String, String),

    /// The HTTP exchange failed.
    #[error("http: {0}")]
    Http(String),

    /// The server answered with a non-success status.
    #[error("server returned {0}")]
    Status(StatusCode),

    /// The body exceeded the configured limit.
    #[error("body larger than {0} bytes")]
    TooLarge(u64),

    /// Too many redirects were followed.
    #[error("too many redirects")]
    TooManyRedirects,
}

/// The most redirects that will be followed.
const MAX_REDIRECTS: usize = 5;

/// Builds the shared TLS configuration.
fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(cfg)
}

/// Downloads `url`, following redirects, and returns the body.
///
/// The body is capped at `max_bytes`; a larger response fails rather than
/// being silently truncated.
pub async fn get(url: &str, max_bytes: u64, timeout: Duration) -> Result<Vec<u8>, Error> {
    let mut current = url.to_string();

    for _ in 0..=MAX_REDIRECTS {
        let (status, location, body) = get_once(&current, max_bytes, timeout).await?;

        if status.is_redirection() {
            let Some(loc) = location else {
                return Err(Error::Http(format!("{status} without a location header")));
            };
            current = resolve_redirect(&current, &loc)?;

            continue;
        }

        if !status.is_success() {
            return Err(Error::Status(status));
        }

        return Ok(body);
    }

    Err(Error::TooManyRedirects)
}

/// Performs one request without following redirects.
async fn get_once(
    url: &str,
    max_bytes: u64,
    timeout: Duration,
) -> Result<(StatusCode, Option<String>, Vec<u8>), Error> {
    let uri: Uri = url
        .parse()
        .map_err(|e| Error::Url(url.into(), format!("{e}")))?;
    let host = uri
        .host()
        .ok_or_else(|| Error::Url(url.into(), "no host".into()))?
        .to_string();
    let scheme = uri.scheme_str().unwrap_or("https");
    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "http" { 80 } else { 443 });

    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    let tcp = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| Error::Connect(host.clone(), "timed out".into()))?
    .map_err(|e| Error::Connect(host.clone(), e.to_string()))?;
    tcp.set_nodelay(true).ok();

    let req = |h: &str, p: &str| {
        Request::builder()
            .method("GET")
            .uri(p)
            .header("host", h)
            // Named for what this is.  Hostlist servers key nothing off it,
            // and GitHub's API refuses a request that sends none at all.
            .header("user-agent", concat!("Sift/", env!("CARGO_PKG_VERSION")))
            .header("accept", "text/plain, */*")
            .body(Empty::<bytes::Bytes>::new())
            .map_err(|e| Error::Http(e.to_string()))
    };

    if scheme == "http" {
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = tokio::time::timeout(timeout, sender.send_request(req(&host, &path)?))
            .await
            .map_err(|_| Error::Http("timed out".into()))?
            .map_err(|e| Error::Http(e.to_string()))?;
        let out = collect(resp, max_bytes, timeout).await;
        task.abort();

        return out;
    }

    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let name = rustls_pki_types::ServerName::try_from(host.clone())
        .map_err(|e| Error::Url(url.into(), e.to_string()))?;
    let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| Error::Connect(host.clone(), "tls handshake timed out".into()))?
        .map_err(|e| Error::Connect(host.clone(), e.to_string()))?;

    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = hyper_util::rt::TokioIo::new(tls);

    if is_h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let full = format!("https://{host}{path}");
        let resp = tokio::time::timeout(timeout, sender.send_request(req(&host, &full)?))
            .await
            .map_err(|_| Error::Http("timed out".into()))?
            .map_err(|e| Error::Http(e.to_string()))?;
        let out = collect(resp, max_bytes, timeout).await;
        task.abort();

        out
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = tokio::time::timeout(timeout, sender.send_request(req(&host, &path)?))
            .await
            .map_err(|_| Error::Http("timed out".into()))?
            .map_err(|e| Error::Http(e.to_string()))?;
        let out = collect(resp, max_bytes, timeout).await;
        task.abort();

        out
    }
}

/// Reads a response, enforcing the size cap.
async fn collect<B>(
    resp: hyper::Response<B>,
    max_bytes: u64,
    timeout: Duration,
) -> Result<(StatusCode, Option<String>, Vec<u8>), Error>
where
    B: hyper::body::Body + Unpin,
    B::Error: std::fmt::Display,
{
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Reject early when the server declares an oversized body.
    if let Some(len) = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && len > max_bytes
    {
        return Err(Error::TooLarge(max_bytes));
    }

    let collected = tokio::time::timeout(timeout, resp.into_body().collect())
        .await
        .map_err(|_| Error::Http("body read timed out".into()))?
        .map_err(|e| Error::Http(e.to_string()))?;

    let bytes = collected.to_bytes();
    if bytes.len() as u64 > max_bytes {
        return Err(Error::TooLarge(max_bytes));
    }

    Ok((status, location, bytes.to_vec()))
}

/// Resolves a `Location` header against the URL it came from.
fn resolve_redirect(base: &str, location: &str) -> Result<String, Error> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }

    let base_uri: Uri = base
        .parse()
        .map_err(|e| Error::Url(base.into(), format!("{e}")))?;
    let scheme = base_uri.scheme_str().unwrap_or("https");
    let authority = base_uri
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| Error::Url(base.into(), "no authority".into()))?;

    if let Some(abs) = location.strip_prefix('/') {
        return Ok(format!("{scheme}://{authority}/{abs}"));
    }

    // A relative path: replace the last segment of the base path.
    let path = base_uri.path();
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");

    Ok(format!("{scheme}://{authority}{dir}/{location}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_redirects_are_used_as_is() {
        assert_eq!(
            resolve_redirect("https://a.example/x", "https://b.example/y").unwrap(),
            "https://b.example/y"
        );
    }

    #[test]
    fn root_relative_redirects_keep_the_authority() {
        assert_eq!(
            resolve_redirect("https://a.example/x/y", "/z").unwrap(),
            "https://a.example/z"
        );
    }

    #[test]
    fn path_relative_redirects_resolve_against_the_directory() {
        assert_eq!(
            resolve_redirect("https://a.example/x/y", "z").unwrap(),
            "https://a.example/x/z"
        );
    }

    #[tokio::test]
    async fn refuses_a_body_over_the_cap() {
        // Serve a body larger than the cap from a local listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let body = "x".repeat(10_000);
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });

        let url = format!("http://127.0.0.1:{}/list.txt", addr.port());
        let err = get(&url, 100, Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(err, Error::TooLarge(100)), "got {err:?}");
    }

    #[tokio::test]
    async fn downloads_a_small_body_over_plain_http() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let body = "||ads.example.com^\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });

        let url = format!("http://127.0.0.1:{}/list.txt", addr.port());
        let body = get(&url, 1_000_000, Duration::from_secs(5)).await.unwrap();
        assert_eq!(String::from_utf8(body).unwrap(), "||ads.example.com^\n");
    }

    #[tokio::test]
    async fn reports_a_failing_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                .await;
        });

        let url = format!("http://127.0.0.1:{}/missing.txt", addr.port());
        let err = get(&url, 1_000_000, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Status(StatusCode::NOT_FOUND)),
            "got {err:?}"
        );
    }
}

//! Serving the embedded web interface.
//!
//! The assets are stored gzip-compressed, which keeps ~9.7 MB of JavaScript
//! and CSS down to ~2.5 MB in the binary.  A client that accepts gzip gets the
//! stored bytes untouched; anything else is decompressed on the way out.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

/// The built web interface.
#[derive(RustEmbed)]
#[folder = "../../web/build"]
struct Assets;

/// Serves an asset by request path.
///
/// An unknown path falls back to `index.html` so the single-page app can
/// handle its own routing, which is what upstream's file server does.
pub fn serve(path: &str, headers: &HeaderMap) -> Response {
    let clean = path.trim_start_matches('/');
    let candidate = if clean.is_empty() {
        "index.html"
    } else {
        clean
    };

    if let Some(r) = lookup(candidate, headers) {
        return r;
    }

    // Only fall back for paths that look like navigation, not for a missing
    // asset: answering a missing script with HTML hides real problems.
    if candidate.contains('.') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    lookup("index.html", headers)
        .unwrap_or_else(|| (StatusCode::NOT_FOUND, "not found").into_response())
}

/// Looks an asset up, preferring the stored compressed form.
fn lookup(name: &str, headers: &HeaderMap) -> Option<Response> {
    let mime = mime_for(name);

    // Stored compressed.
    if let Some(f) = Assets::get(&format!("{name}.gz")) {
        let accepts_gzip = headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("gzip"));

        if accepts_gzip {
            return Some(
                (
                    [
                        (header::CONTENT_TYPE, mime),
                        (header::CONTENT_ENCODING, "gzip"),
                        (header::VARY, "Accept-Encoding"),
                    ],
                    Body::from(f.data.into_owned()),
                )
                    .into_response(),
            );
        }

        let plain = decompress(&f.data)?;

        return Some(
            (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::VARY, "Accept-Encoding"),
                ],
                Body::from(plain),
            )
                .into_response(),
        );
    }

    // Stored as-is.
    let f = Assets::get(name)?;

    Some(
        (
            [(header::CONTENT_TYPE, mime)],
            Body::from(f.data.into_owned()),
        )
            .into_response(),
    )
}

/// Decompresses a stored asset.
fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .ok()?;

    Some(out)
}

/// The media type for an asset name.
fn mime_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Reports whether the web interface was embedded in this build.
pub fn is_embedded() -> bool {
    Assets::get("index.html.gz").is_some() || Assets::get("index.html").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        h
    }

    #[test]
    fn the_interface_is_embedded() {
        assert!(
            is_embedded(),
            "the built web interface should be compiled in"
        );
    }

    #[test]
    fn the_root_serves_the_app_shell() {
        let r = serve("/", &gzip_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(r.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
    }

    #[test]
    fn a_client_without_gzip_gets_plain_bytes() {
        let r = serve("/", &HeaderMap::new());
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[test]
    fn the_login_and_install_pages_are_present() {
        for p in ["/login.html", "/install.html"] {
            assert_eq!(
                serve(p, &gzip_headers()).status(),
                StatusCode::OK,
                "missing {p}"
            );
        }
    }

    #[test]
    fn unknown_routes_fall_back_to_the_app_shell() {
        // The UI routes client-side, so a bare path must return index.html.
        let r = serve("/dashboard", &gzip_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn a_missing_asset_is_a_404_not_the_app_shell() {
        let r = serve("/nope.js", &gzip_headers());
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn media_types_cover_the_shipped_assets() {
        assert_eq!(mime_for("a.js"), "text/javascript; charset=utf-8");
        assert_eq!(mime_for("a.css"), "text/css; charset=utf-8");
        assert_eq!(mime_for("a.png"), "image/png");
        assert_eq!(mime_for("a.svg"), "image/svg+xml");
        assert_eq!(mime_for("a.unknown"), "application/octet-stream");
    }

    #[test]
    fn binary_assets_are_served_uncompressed() {
        let r = serve("/assets/favicon.png", &gzip_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers().get(header::CONTENT_TYPE).unwrap(), "image/png");
        assert!(r.headers().get(header::CONTENT_ENCODING).is_none());
    }
}

//! The DNS-over-HTTPS listener.
//!
//! Served from the same router as the web interface, because upstream serves
//! both on the HTTPS port. Queries go through [`agl_dns::server::Server`]
//! rather than straight to the resolver, so DoH is subject to the same rate
//! limits, access control, query log and statistics as plain DNS.

use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::state::Shared;

/// The media type a DNS message is carried in.
const DNS_MESSAGE: &str = "application/dns-message";

/// The largest query this will accept.
const MAX_QUERY: usize = 64 * 1024;

/// Marks whether the connection a request arrived on was encrypted.
///
/// Injected per listener: the TLS listener sets it, the plain one does not.
#[derive(Clone, Copy, Debug)]
pub struct Secure(pub bool);

/// The `?dns=` parameter of a GET query.
#[derive(Deserialize)]
pub struct DnsParam {
    /// The query, base64url-encoded without padding.
    #[serde(default)]
    pub dns: Option<String>,
}

/// `GET /dns-query`
pub async fn get(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(p): Query<DnsParam>,
) -> Response {
    let Some(encoded) = p.dns else {
        return bad_request("missing the dns parameter");
    };
    let Some(wire) = decode_query(&encoded) else {
        return bad_request("the dns parameter is not valid base64url");
    };

    answer(state, secure, conn, headers, None, wire).await
}

/// `GET /dns-query/{client_id}`
pub async fn get_with_client(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Query(p): Query<DnsParam>,
) -> Response {
    let Some(encoded) = p.dns else {
        return bad_request("missing the dns parameter");
    };
    let Some(wire) = decode_query(&encoded) else {
        return bad_request("the dns parameter is not valid base64url");
    };

    answer(state, secure, conn, headers, Some(client_id), wire).await
}

/// `POST /dns-query`
pub async fn post(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = check_content_type(&headers) {
        return r;
    }

    answer(state, secure, conn, headers, None, body.to_vec()).await
}

/// `POST /dns-query/{client_id}`
pub async fn post_with_client(
    state: State<Shared>,
    secure: axum::Extension<Secure>,
    conn: ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = check_content_type(&headers) {
        return r;
    }

    answer(state, secure, conn, headers, Some(client_id), body.to_vec()).await
}

/// Rejects a POST that does not carry a DNS message.
fn check_content_type(headers: &HeaderMap) -> Option<Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());

    match ct {
        Some(v) if v.starts_with(DNS_MESSAGE) => None,
        _ => Some(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("the body must be {DNS_MESSAGE}"),
            )
                .into_response(),
        ),
    }
}

/// Decodes the base64url form a GET query carries.
///
/// RFC 8484 specifies base64url without padding, but some clients send it
/// padded, so both are accepted.
pub fn decode_query(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

    if s.len() > MAX_QUERY {
        return None;
    }

    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .ok()
}

/// Builds a 400 with a plain-text reason.
fn bad_request(why: &str) -> Response {
    (StatusCode::BAD_REQUEST, why.to_string()).into_response()
}

/// The client address to attribute a request to.
///
/// When the connection comes from a trusted proxy, the left-most address in
/// `X-Forwarded-For` is the real client; from anywhere else the header is
/// attacker-controlled and is ignored, which is the whole point of the
/// `trusted_proxies` list.
pub fn real_client(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[agl_config::types::Prefix],
) -> SocketAddr {
    if !trusted.iter().any(|p| p.contains(peer.ip())) {
        return peer;
    }

    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .and_then(|v| v.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok());

    match forwarded {
        Some(ip) => SocketAddr::new(ip, peer.port()),
        None => peer,
    }
}

/// Resolves a query and renders the reply.
async fn answer(
    State(s): State<Shared>,
    axum::Extension(Secure(encrypted)): axum::Extension<Secure>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    client_id: Option<String>,
    wire: Vec<u8>,
) -> Response {
    // Serving DNS over plain HTTP exposes queries to the network, so it is off
    // unless the operator asked for it.
    if !encrypted && !s.config.read().http.doh.insecure_enabled {
        return (
            StatusCode::NOT_FOUND,
            "DNS-over-HTTPS is not served over plain HTTP; set http.doh.insecure_enabled to allow it",
        )
            .into_response();
    }

    if wire.len() > MAX_QUERY {
        return bad_request("the query is too large");
    }

    let client = real_client(peer, &headers, &s.config.read().dns.trusted_proxies);

    let Some(resp) = s
        .dns_server
        .handle_as(
            &wire,
            client,
            agl_dns::resolver::Proto::Https,
            client_id.filter(|c| !c.is_empty()),
        )
        .await
    else {
        // The query was refused or dropped: rate limited, blocked by access
        // control, or malformed.
        return (StatusCode::BAD_REQUEST, "the query was not answered").into_response();
    };

    ([(header::CONTENT_TYPE, DNS_MESSAGE)], resp).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_padded_and_unpadded_base64url() {
        // "hello" in both forms.
        assert_eq!(decode_query("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_query("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn decodes_the_url_safe_alphabet() {
        // Bytes that encode to `-` and `_` rather than `+` and `/`.
        let raw = [0xFBu8, 0xFF, 0xBF];
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        assert!(enc.contains('-') || enc.contains('_'), "got {enc}");
        assert_eq!(decode_query(&enc).as_deref(), Some(&raw[..]));
    }

    #[test]
    fn rejects_nonsense_and_oversized_input() {
        assert!(decode_query("!!!not base64!!!").is_none());
        assert!(decode_query(&"A".repeat(MAX_QUERY + 1)).is_none());
    }

    #[test]
    fn an_untrusted_forwarded_header_is_ignored() {
        // Anyone can send X-Forwarded-For; honouring it from an arbitrary
        // peer would let a client claim any address, and with it any other
        // client's per-client settings.
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());

        assert_eq!(real_client(peer, &h, &[]), peer);
    }

    #[test]
    fn a_trusted_proxy_supplies_the_real_client() {
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "198.51.100.7, 203.0.113.1".parse().unwrap(),
        );

        let trusted = vec![agl_config::types::Prefix {
            addr: "192.0.2.0".parse().unwrap(),
            bits: 24,
        }];
        assert_eq!(
            real_client(peer, &h, &trusted).ip(),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap(),
            "the left-most address is the client"
        );
    }

    #[test]
    fn a_trusted_proxy_without_the_header_keeps_the_peer() {
        let peer: SocketAddr = "192.0.2.9:5000".parse().unwrap();
        let trusted = vec![agl_config::types::Prefix {
            addr: "192.0.2.0".parse().unwrap(),
            bits: 24,
        }];

        assert_eq!(real_client(peer, &HeaderMap::new(), &trusted), peer);
    }

    #[test]
    fn a_post_must_carry_a_dns_message() {
        let mut h = HeaderMap::new();
        assert!(
            check_content_type(&h).is_some(),
            "a missing type is refused"
        );

        h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(
            check_content_type(&h).is_some(),
            "the wrong type is refused"
        );

        h.insert(header::CONTENT_TYPE, DNS_MESSAGE.parse().unwrap());
        assert!(check_content_type(&h).is_none());

        // A charset parameter is tolerated.
        h.insert(
            header::CONTENT_TYPE,
            format!("{DNS_MESSAGE}; charset=utf-8").parse().unwrap(),
        );
        assert!(check_content_type(&h).is_none());
    }
}

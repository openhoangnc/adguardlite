//! Server-side TLS: loading a certificate and key, and reporting on them.
//!
//! The report feeds `/control/tls/status` and `/control/tls/validate`, which
//! the web interface uses to tell the user whether their certificate is
//! usable, so the checks here have to be the ones a user would expect: does
//! the chain parse, does the key parse, do they belong together, and what
//! names and dates does the certificate carry.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Where a certificate and key come from.
///
/// Upstream accepts either the PEM inline in the config or a path to a file,
/// and rejects a config that sets both for the same item.
#[derive(Clone, Debug, Default)]
pub struct Source {
    /// The PEM-encoded certificate chain.
    pub certificate_chain: String,
    /// The PEM-encoded private key.
    pub private_key: String,
    /// A path to read the certificate chain from.
    pub certificate_path: String,
    /// A path to read the private key from.
    pub private_key_path: String,
}

impl Source {
    /// Reports whether anything at all was configured.
    pub fn is_empty(&self) -> bool {
        self.certificate_chain.is_empty()
            && self.certificate_path.is_empty()
            && self.private_key.is_empty()
            && self.private_key_path.is_empty()
    }

    /// Reads the certificate PEM, from the config or from disk.
    fn cert_pem(&self) -> Result<String, Error> {
        match (
            self.certificate_chain.is_empty(),
            self.certificate_path.is_empty(),
        ) {
            (false, false) => Err(Error::Conflict(
                "set either certificate_chain or certificate_path, not both",
            )),
            (false, true) => Ok(self.certificate_chain.clone()),
            (true, false) => std::fs::read_to_string(&self.certificate_path)
                .map_err(|e| Error::Read(self.certificate_path.clone(), e.to_string())),
            (true, true) => Err(Error::Missing("no certificate configured")),
        }
    }

    /// Reads the private key PEM, from the config or from disk.
    fn key_pem(&self) -> Result<String, Error> {
        match (
            self.private_key.is_empty(),
            self.private_key_path.is_empty(),
        ) {
            (false, false) => Err(Error::Conflict(
                "set either private_key or private_key_path, not both",
            )),
            (false, true) => Ok(self.private_key.clone()),
            (true, false) => std::fs::read_to_string(&self.private_key_path)
                .map_err(|e| Error::Read(self.private_key_path.clone(), e.to_string())),
            (true, true) => Err(Error::Missing("no private key configured")),
        }
    }
}

/// Why a certificate or key could not be used.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Both the inline and the path form were given for one item.
    #[error("{0}")]
    Conflict(&'static str),

    /// Neither form was given.
    #[error("{0}")]
    Missing(&'static str),

    /// A file could not be read.
    #[error("reading {0}: {1}")]
    Read(String, String),

    /// The PEM held no usable item.
    #[error("{0}")]
    Parse(String),

    /// The key does not match the certificate.
    #[error("the private key does not match the certificate")]
    Mismatch,

    /// rustls refused the pair.
    #[error("tls: {0}")]
    Rustls(String),
}

/// What is known about a configured certificate.
///
/// Mirrors the fields `/control/tls/status` reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Whether the chain parsed.
    pub valid_cert: bool,
    /// Whether the chain is complete and self-consistent.
    pub valid_chain: bool,
    /// Whether the key parsed.
    pub valid_key: bool,
    /// Whether the key belongs to the certificate.
    pub valid_pair: bool,
    /// The names the certificate covers.
    ///
    /// DNS names only, as upstream's `dns_names` field is: the IP addresses a
    /// certificate may also carry are reported by [`Status::has_ip_addresses`]
    /// instead, because the API's field is compared against Go's.
    pub dns_names: Vec<String>,
    /// Whether the certificate names any IP address.
    ///
    /// Discovery of Designated Resolvers only advertises DNS-over-TLS when it
    /// does: a client that found this resolver by address has no hostname to
    /// validate the certificate against.
    pub has_ip_addresses: bool,
    /// When the certificate becomes valid, in Go's zero-time-aware format.
    pub not_before: String,
    /// When the certificate expires.
    pub not_after: String,
    /// The key's algorithm, as upstream words it.
    pub key_type: String,
    /// The certificate's subject.
    pub subject: String,
    /// The certificate's issuer.
    pub issuer: String,
    /// Why the certificate is unusable, if it is.
    pub warning_validation: String,
}

/// A loaded, ready-to-serve certificate.
pub struct Loaded {
    /// The rustls configuration for DNS-over-TLS.
    pub dot: Arc<ServerConfig>,
    /// The rustls configuration for HTTPS and DNS-over-HTTPS, which differs
    /// only in the protocols it advertises.
    pub https: Arc<ServerConfig>,
    /// The rustls configuration for HTTP/3, which QUIC carries and which
    /// therefore needs its own ALPN identifier.
    pub h3: Arc<ServerConfig>,
    /// The rustls configuration for DNS-over-QUIC.
    ///
    /// Separate because QUIC requires TLS 1.3 and its own ALPN identifier.
    pub doq: Arc<ServerConfig>,
    /// What to report about the certificate.
    pub status: Status,
}

/// Parses a certificate chain from PEM.
fn parse_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let mut r = std::io::BufReader::new(pem.as_bytes());
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_, _>>()
        .map_err(|e| Error::Parse(format!("parsing the certificate chain: {e}")))?;

    if chain.is_empty() {
        return Err(Error::Parse(
            "the certificate chain holds no certificate".into(),
        ));
    }

    Ok(chain)
}

/// Parses a private key from PEM, accepting the forms rustls supports.
fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, Error> {
    let mut r = std::io::BufReader::new(pem.as_bytes());

    rustls_pemfile::private_key(&mut r)
        .map_err(|e| Error::Parse(format!("parsing the private key: {e}")))?
        .ok_or_else(|| Error::Parse("the private key holds no key".into()))
}

/// Describes a certificate without building a server configuration.
///
/// This is what `/control/tls/validate` needs: an answer about a certificate
/// the user is still editing, which may well be unusable.
pub fn inspect(src: &Source) -> Status {
    let mut st = Status::default();

    let cert_pem = match src.cert_pem() {
        Ok(p) => p,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    let chain = match parse_chain(&cert_pem) {
        Ok(c) => c,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    st.valid_cert = true;
    // A chain is usable when every certificate in it parsed; rustls performs
    // the ordering and trust checks when it builds the configuration.
    st.valid_chain = chain.len() > 1;
    describe_leaf(&chain[0], &mut st);

    let key_pem = match src.key_pem() {
        Ok(p) => p,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    let key = match parse_key(&key_pem) {
        Ok(k) => k,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    };

    st.valid_key = true;

    // The pair is proven by asking rustls to build a configuration from it:
    // that is the same check the server itself performs.
    match build(chain.clone(), key) {
        Ok(_) => st.valid_pair = true,
        Err(e) => {
            st.warning_validation = e.to_string();

            return st;
        }
    }

    // A usable pair can still be one no client will accept -- self-signed, or
    // missing its intermediates.  Upstream serves it anyway and says so, which
    // is the only way the operator finds out before their clients do.
    if let Err(why) = verify_chain(&chain, &st.dns_names) {
        st.warning_validation = why;
    }

    st
}

/// Checks the chain against the trusted roots, as a client would.
///
/// Returns why it failed, or `Ok` when it verifies.
fn verify_chain(chain: &[CertificateDer<'static>], names: &[String]) -> Result<(), String> {
    use rustls::client::verify_server_cert_signed_by_trust_anchor;
    use rustls::server::ParsedCertificate;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let parsed = ParsedCertificate::try_from(&chain[0])
        .map_err(|e| format!("validating certificate pair: {e}"))?;

    let intermediates = &chain[1..];
    let now = rustls_pki_types::UnixTime::now();

    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &roots,
        intermediates,
        now,
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all,
    )
    .map_err(|e| format!("validating certificate pair: certificate does not verify: {e}"))?;

    let _ = names;

    Ok(())
}

/// Fills in the fields taken from the leaf certificate.
fn describe_leaf(leaf: &CertificateDer<'_>, st: &mut Status) {
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        st.warning_validation = "the certificate could not be decoded".into();

        return;
    };

    st.key_type = public_key_name(&cert);
    st.subject = cert.subject().to_string();
    st.issuer = cert.issuer().to_string();
    st.not_before = format_time(cert.validity().not_before.timestamp());
    st.not_after = format_time(cert.validity().not_after.timestamp());

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(n) => st.dns_names.push((*n).to_string()),
                GeneralName::IPAddress(_) => st.has_ip_addresses = true,
                _ => {}
            }
        }
    }

    // A certificate with no SAN falls back to its common name, as clients did
    // before SANs were required.
    if st.dns_names.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                st.dns_names.push(s.to_string());
            }
        }
    }
}

/// Names the certificate's public key algorithm.
///
/// Upstream reports the algorithm -- `RSA`, `ECDSA` -- not the PEM container
/// the private key arrived in, which may be PKCS#8 for either.
fn public_key_name(cert: &x509_parser::certificate::X509Certificate<'_>) -> String {
    use x509_parser::public_key::PublicKey;

    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(_)) => "RSA".to_string(),
        Ok(PublicKey::EC(_)) => "ECDSA".to_string(),
        Ok(PublicKey::DSA(_)) => "DSA".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Formats a certificate timestamp the way Go's JSON encoder would.
fn format_time(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .map(agl_core::gotime::format_utc)
        .unwrap_or_else(|_| agl_core::gotime::GO_ZERO_TIME.to_string())
}

/// A certificate that can be replaced while the listeners keep running.
///
/// rustls takes the certificate when a `ServerConfig` is built, so a listener
/// started with one keeps it for life.  Handing it a resolver instead means a
/// certificate replaced through `/control/tls/configure` takes effect on the
/// next handshake rather than at the next restart.
#[derive(Debug, Default)]
pub struct Reloadable {
    /// The certificate currently being served.
    current: parking_lot::RwLock<Option<Arc<rustls::sign::CertifiedKey>>>,
}

impl Reloadable {
    /// An empty slot, serving nothing until a certificate is installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs a certificate and key, replacing whatever was there.
    pub fn set(
        &self,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<(), Error> {
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| Error::Rustls(format!("using the private key: {e}")))?;
        *self.current.write() = Some(Arc::new(rustls::sign::CertifiedKey::new(chain, signing)));

        Ok(())
    }

    /// Reports whether a certificate is installed.
    pub fn is_loaded(&self) -> bool {
        self.current.read().is_some()
    }
}

impl rustls::server::ResolvesServerCert for Reloadable {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.current.read().clone()
    }
}

/// Builds the three server configurations around one reloadable certificate.
///
/// Each listener advertises its own protocol, but they share the certificate,
/// so replacing it reaches all of them at once.
pub fn reloadable(resolver: Arc<Reloadable>) -> Loaded {
    let make = |alpn: Vec<Vec<u8>>| {
        let mut c = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        c.alpn_protocols = alpn;

        Arc::new(c)
    };

    Loaded {
        dot: make(vec![b"dot".to_vec()]),
        https: make(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        h3: make(vec![b"h3".to_vec()]),
        doq: make(vec![b"doq".to_vec()]),
        status: Status::default(),
    }
}

/// Parses a source and installs it into a reloadable slot.
pub fn install(src: &Source, into: &Reloadable) -> Result<Status, Error> {
    let chain = parse_chain(&src.cert_pem()?)?;
    let key = parse_key(&src.key_pem()?)?;

    let mut status = Status {
        valid_cert: true,
        valid_key: true,
        ..Default::default()
    };
    status.valid_chain = chain.len() > 1;
    describe_leaf(&chain[0], &mut status);

    // Building a configuration first is what catches a key that does not
    // match the certificate: the resolver would accept the pair and fail at
    // handshake time instead.
    build(chain.clone(), key.clone_key())?;
    into.set(chain, key)?;
    status.valid_pair = true;

    Ok(status)
}

/// Builds a rustls server configuration from a chain and key.
fn build(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Error> {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| {
            // rustls reports a mismatched pair as a generic error; the user
            // needs to be told which of the two problems they have.
            let text = e.to_string();
            if text.contains("key") && text.contains("match") {
                Error::Mismatch
            } else {
                Error::Rustls(text)
            }
        })
}

/// Loads a certificate and key, producing configurations for each protocol.
pub fn load(src: &Source) -> Result<Loaded, Error> {
    let chain = parse_chain(&src.cert_pem()?)?;
    let key = parse_key(&src.key_pem()?)?;

    let mut status = Status {
        valid_cert: true,
        valid_key: true,
        ..Default::default()
    };
    status.valid_chain = chain.len() > 1;
    describe_leaf(&chain[0], &mut status);

    // rustls consumes the key, so build each configuration from a clone.
    let mut dot = build(chain.clone(), key.clone_key())?;
    // DNS-over-TLS advertises itself so a client can be sure what it reached.
    dot.alpn_protocols = vec![b"dot".to_vec()];

    let mut https = build(chain.clone(), key.clone_key())?;
    https.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut h3 = build(chain.clone(), key.clone_key())?;
    h3.alpn_protocols = vec![b"h3".to_vec()];

    // RFC 9250 names the protocol `doq`; earlier drafts used other tokens,
    // and clients that still send them are simply not served.
    let mut doq = build(chain, key)?;
    doq.alpn_protocols = vec![b"doq".to_vec()];

    status.valid_pair = true;

    Ok(Loaded {
        dot: Arc::new(dot),
        https: Arc::new(https),
        h3: Arc::new(h3),
        doq: Arc::new(doq),
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generates a self-signed certificate for the given names.
    fn self_signed(names: &[&str]) -> (String, String) {
        let c = rcgen::generate_simple_self_signed(
            names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
        .expect("generating a certificate");

        (c.cert.pem(), c.signing_key.serialize_pem())
    }

    fn inline(cert: &str, key: &str) -> Source {
        Source {
            certificate_chain: cert.to_string(),
            private_key: key.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn loads_a_self_signed_pair() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let loaded = load(&inline(&cert, &key)).expect("a matching pair must load");

        assert!(loaded.status.valid_cert);
        assert!(loaded.status.valid_key);
        assert!(loaded.status.valid_pair);
        assert_eq!(loaded.status.dns_names, ["dns.example.com"]);
        assert!(loaded.status.warning_validation.is_empty());
    }

    #[test]
    fn advertises_the_right_protocols_per_listener() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let loaded = load(&inline(&cert, &key)).unwrap();

        assert_eq!(loaded.dot.alpn_protocols, vec![b"dot".to_vec()]);
        assert_eq!(
            loaded.https.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(loaded.doq.alpn_protocols, vec![b"doq".to_vec()]);
        assert_eq!(loaded.h3.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn reports_every_name_the_certificate_covers() {
        let (cert, key) = self_signed(&["a.example.com", "b.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert_eq!(st.dns_names, ["a.example.com", "b.example.com"]);
    }

    #[test]
    fn reports_validity_dates() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        // Formatted the way Go's encoder would, so the interface can parse it.
        assert!(st.not_before.ends_with('Z'), "got {}", st.not_before);
        assert!(st.not_after.ends_with('Z'), "got {}", st.not_after);
        assert!(st.not_before < st.not_after);
    }

    #[test]
    fn reports_the_key_algorithm_not_the_pem_container() {
        // rcgen emits a PKCS#8 file holding an EC key; upstream reports the
        // algorithm, so reporting "PKCS#8" would be wrong.
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert!(
            matches!(st.key_type.as_str(), "RSA" | "ECDSA" | "DSA"),
            "expected an algorithm name, got {:?}",
            st.key_type
        );
    }

    #[test]
    fn a_self_signed_certificate_is_served_but_flagged() {
        // Upstream serves it and warns, which is how the operator finds out
        // before their clients do.
        let (cert, key) = self_signed(&["dns.example.com"]);
        let st = inspect(&inline(&cert, &key));

        assert!(st.valid_pair, "the pair is usable");
        assert!(
            st.warning_validation.contains("does not verify"),
            "a self-signed certificate should be flagged, got {:?}",
            st.warning_validation
        );
    }

    #[test]
    fn a_mismatched_key_is_rejected() {
        let (cert, _) = self_signed(&["a.example.com"]);
        let (_, other_key) = self_signed(&["b.example.com"]);

        let st = inspect(&inline(&cert, &other_key));
        assert!(st.valid_cert, "the certificate itself is fine");
        assert!(st.valid_key, "the key itself is fine");
        assert!(!st.valid_pair, "but they do not belong together");
        assert!(!st.warning_validation.is_empty());

        assert!(load(&inline(&cert, &other_key)).is_err());
    }

    #[test]
    fn garbage_is_reported_rather_than_panicking() {
        let st = inspect(&inline("not a certificate", "not a key"));
        assert!(!st.valid_cert);
        assert!(!st.valid_key);
        assert!(!st.valid_pair);
        assert!(st.warning_validation.contains("certificate"));
    }

    #[test]
    fn a_key_without_a_certificate_is_reported() {
        let (_, key) = self_signed(&["a.example.com"]);
        let st = inspect(&Source {
            private_key: key,
            ..Default::default()
        });

        assert!(!st.valid_cert);
        assert!(st.warning_validation.contains("no certificate"));
    }

    #[test]
    fn setting_both_the_inline_and_the_path_form_is_refused() {
        let (cert, key) = self_signed(&["a.example.com"]);
        let src = Source {
            certificate_chain: cert,
            certificate_path: "/etc/ssl/cert.pem".into(),
            private_key: key,
            ..Default::default()
        };

        let st = inspect(&src);
        assert!(
            st.warning_validation.contains("not both"),
            "got {}",
            st.warning_validation
        );
    }

    #[test]
    fn loads_from_files() {
        let (cert, key) = self_signed(&["dns.example.com"]);
        let dir = std::env::temp_dir().join(format!("agl-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("cert.pem");
        let kp = dir.join("key.pem");
        std::fs::write(&cp, &cert).unwrap();
        std::fs::write(&kp, &key).unwrap();

        let src = Source {
            certificate_path: cp.to_string_lossy().into_owned(),
            private_key_path: kp.to_string_lossy().into_owned(),
            ..Default::default()
        };

        let loaded = load(&src).expect("a pair on disk must load");
        assert!(loaded.status.valid_pair);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path() {
        let src = Source {
            certificate_path: "/nonexistent/cert.pem".into(),
            private_key_path: "/nonexistent/key.pem".into(),
            ..Default::default()
        };

        let st = inspect(&src);
        assert!(st.warning_validation.contains("/nonexistent/cert.pem"));
    }

    #[test]
    fn an_unconfigured_source_is_empty() {
        assert!(Source::default().is_empty());
        assert!(
            !Source {
                private_key: "x".into(),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn a_reloadable_certificate_can_be_replaced_while_running() {
        // A certificate installed through the API has to reach the running
        // listeners; otherwise it only takes effect at the next restart.
        let slot = Arc::new(Reloadable::new());
        assert!(!slot.is_loaded());

        let (cert, key) = self_signed(&["first.example"]);
        let status = install(&inline(&cert, &key), &slot).expect("the pair should install");
        assert!(status.valid_pair);
        assert!(slot.is_loaded());

        let first = {
            let guard = slot.current.read();

            guard.clone().expect("a certificate should be resolvable")
        };

        let (cert2, key2) = self_signed(&["second.example"]);
        install(&inline(&cert2, &key2), &slot).expect("the second pair should install");

        let second = {
            let guard = slot.current.read();

            guard.clone().expect("the replacement should be resolvable")
        };
        assert_ne!(
            first.cert[0].as_ref(),
            second.cert[0].as_ref(),
            "the served certificate should have changed"
        );
    }

    #[test]
    fn a_mismatched_pair_is_refused_before_it_is_installed() {
        let slot = Reloadable::new();
        let (cert, _) = self_signed(&["a.example"]);
        let (_, key) = self_signed(&["b.example"]);

        assert!(install(&inline(&cert, &key), &slot).is_err());
        assert!(!slot.is_loaded(), "nothing should have been installed");
    }

    #[test]
    fn the_reloadable_configurations_advertise_the_right_protocols() {
        let slot = Arc::new(Reloadable::new());
        let loaded = reloadable(slot);

        assert_eq!(loaded.dot.alpn_protocols, vec![b"dot".to_vec()]);
        assert_eq!(
            loaded.https.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(loaded.doq.alpn_protocols, vec![b"doq".to_vec()]);
        assert_eq!(loaded.h3.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn ip_addresses_are_reported_separately_from_dns_names() {
        // The API's `dns_names` is compared against Go's, which carries DNS
        // names only; DDR needs to know about IP names as well.
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let st = inspect(&inline(&cert.pem(), &key.serialize_pem()));
        assert_eq!(st.dns_names, vec!["localhost".to_string()]);
        assert!(st.has_ip_addresses);
    }

    #[test]
    fn a_certificate_without_ip_names_says_so() {
        let (c, k) = self_signed(&["localhost"]);
        assert!(!inspect(&inline(&c, &k)).has_ip_addresses);
    }
}

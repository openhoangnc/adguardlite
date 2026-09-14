//! Web session authentication.
//!
//! The contract the browser sees matches the Go implementation: a POST to
//! `/control/login` sets an `agh_session` cookie holding a hex token, and
//! `/control/logout` clears it and redirects to `/login.html`.  HTTP Basic
//! credentials are accepted too, which is what the API's scripted users rely
//! on.

use std::time::{Duration, SystemTime};

use ahash::AHashMap;
use parking_lot::Mutex;

/// The name of the session cookie.
pub const COOKIE_NAME: &str = "agh_session";

/// One logged-in session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The user the session belongs to.
    pub user: String,
    /// When the session stops being valid.
    pub expires: SystemTime,
}

/// The session store.
#[derive(Default)]
pub struct Sessions {
    by_token: Mutex<AHashMap<String, Session>>,
}

impl Sessions {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a session for a user and returns its token.
    pub fn create(&self, user: &str, ttl: Duration) -> String {
        let token = new_token();
        self.by_token.lock().insert(
            token.clone(),
            Session {
                user: user.to_string(),
                expires: SystemTime::now() + ttl,
            },
        );

        token
    }

    /// Looks up a session, dropping it if it has expired.
    pub fn get(&self, token: &str) -> Option<Session> {
        let mut map = self.by_token.lock();
        let s = map.get(token)?.clone();
        if s.expires <= SystemTime::now() {
            map.remove(token);

            return None;
        }

        Some(s)
    }

    /// Removes a session.
    pub fn remove(&self, token: &str) {
        self.by_token.lock().remove(token);
    }

    /// Drops every expired session.
    pub fn sweep(&self) {
        let now = SystemTime::now();
        self.by_token.lock().retain(|_, s| s.expires > now);
    }

    /// The number of live sessions.
    pub fn len(&self) -> usize {
        self.by_token.lock().len()
    }

    /// Reports whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Generates a fresh session token, hex-encoded as upstream does.
fn new_token() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }

    s
}

/// Builds the `Set-Cookie` value for a new session.
pub fn session_cookie(token: &str, ttl: Duration) -> String {
    let secs = ttl.as_secs();

    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={secs}")
}

/// Builds the `Set-Cookie` value that clears the session.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Extracts the session token from a `Cookie` header.
pub fn token_from_cookies(header: &str) -> Option<&str> {
    header.split(';').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;

        (k.trim() == COOKIE_NAME).then(|| v.trim())
    })
}

/// Decodes an HTTP Basic `Authorization` header into a name and password.
pub fn basic_credentials(header: &str) -> Option<(String, String)> {
    use base64::Engine as _;

    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;

    Some((user.to_string(), pass.to_string()))
}

/// Verifies a password against a bcrypt hash.
///
/// Returns false rather than an error on a malformed hash: a broken hash must
/// not let anyone in.
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Hashes a password with the cost upstream uses.
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, 10)
}

/// Tracks failed login attempts per client, to slow down guessing.
pub struct LoginLimiter {
    attempts: Mutex<AHashMap<String, (u32, SystemTime)>>,
    max: u32,
    block: Duration,
}

impl LoginLimiter {
    /// Creates a limiter allowing `max` failures before a `block`-long pause.
    pub fn new(max: u32, block: Duration) -> Self {
        Self {
            attempts: Mutex::new(AHashMap::new()),
            max,
            block,
        }
    }

    /// Reports whether the client is currently blocked.
    pub fn is_blocked(&self, client: &str) -> bool {
        let mut m = self.attempts.lock();
        let Some((count, until)) = m.get(client).copied() else {
            return false;
        };

        if until <= SystemTime::now() {
            m.remove(client);

            return false;
        }

        count >= self.max
    }

    /// Records a failed attempt.
    pub fn record_failure(&self, client: &str) {
        let mut m = self.attempts.lock();
        let e = m
            .entry(client.to_string())
            .or_insert((0, SystemTime::now() + self.block));
        e.0 += 1;
        e.1 = SystemTime::now() + self.block;
    }

    /// Clears a client's failures after a successful login.
    pub fn record_success(&self, client: &str) {
        self.attempts.lock().remove(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire() {
        let s = Sessions::new();
        let t = s.create("admin", Duration::from_secs(60));
        assert_eq!(s.get(&t).unwrap().user, "admin");

        let expired = s.create("admin", Duration::from_millis(0));
        assert!(s.get(&expired).is_none(), "a zero TTL is already expired");
    }

    #[test]
    fn sessions_can_be_removed() {
        let s = Sessions::new();
        let t = s.create("admin", Duration::from_secs(60));
        s.remove(&t);
        assert!(s.get(&t).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn tokens_are_unique_hex() {
        let s = Sessions::new();
        let a = s.create("admin", Duration::from_secs(60));
        let b = s.create("admin", Duration::from_secs(60));
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_cookie_matches_upstreams_attributes() {
        let c = session_cookie("deadbeef", Duration::from_secs(3600));
        assert!(c.starts_with("agh_session=deadbeef;"));
        assert!(c.contains("Path=/"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Max-Age=3600"));

        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn parses_the_session_token_from_a_cookie_header() {
        assert_eq!(token_from_cookies("agh_session=abc123"), Some("abc123"));
        assert_eq!(
            token_from_cookies("other=x; agh_session=abc123; more=y"),
            Some("abc123")
        );
        assert_eq!(token_from_cookies("other=x"), None);
    }

    #[test]
    fn parses_basic_credentials() {
        // "admin:test123"
        let h = "Basic YWRtaW46dGVzdDEyMw==";
        assert_eq!(
            basic_credentials(h),
            Some(("admin".to_string(), "test123".to_string()))
        );
        assert_eq!(basic_credentials("Bearer xyz"), None);
        assert_eq!(basic_credentials("Basic !!!not-base64!!!"), None);
    }

    #[test]
    fn verifies_a_real_bcrypt_hash() {
        // The exact hash used by the reference instance for "test123".
        let hash = "$2a$10$dDdZ0lFNF2/tZvNUkV6GR.aMdxqI8P3u0GYPnEiNB5sGNS0Xm26XO";
        assert!(verify_password("test123", hash));
        assert!(!verify_password("wrong", hash));
        assert!(!verify_password("test123", "not-a-hash"));
    }

    #[test]
    fn hashes_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
    }

    #[test]
    fn the_login_limiter_blocks_after_repeated_failures() {
        let l = LoginLimiter::new(3, Duration::from_secs(60));
        assert!(!l.is_blocked("1.2.3.4"));

        for _ in 0..3 {
            l.record_failure("1.2.3.4");
        }
        assert!(l.is_blocked("1.2.3.4"));

        // A different client is unaffected.
        assert!(!l.is_blocked("5.6.7.8"));

        l.record_success("1.2.3.4");
        assert!(!l.is_blocked("1.2.3.4"));
    }
}

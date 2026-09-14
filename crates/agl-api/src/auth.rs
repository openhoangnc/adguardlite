//! Web session authentication.
//!
//! The contract the browser sees matches the Go implementation: a POST to
//! `/control/login` sets an `agh_session` cookie holding a hex token, and
//! `/control/logout` clears it and redirects to `/login.html`.  HTTP Basic
//! credentials are accepted too, which is what the API's scripted users rely
//! on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ahash::AHashMap;
use parking_lot::Mutex;

/// The name of the session cookie.
pub const COOKIE_NAME: &str = "agh_session";

/// The bucket `sessions.db` stores sessions in.
///
/// The name carries a version: upstream changed the record layout once and
/// used a new bucket rather than migrating.
const BUCKET: &[u8] = b"sessions-2";

/// One logged-in session.
#[derive(Clone, Debug)]
pub struct Session {
    /// The user the session belongs to.
    pub user: String,
    /// When the session stops being valid.
    pub expires: SystemTime,
}

/// The session store.
///
/// Sessions are persisted to `sessions.db` in the layout the Go build uses, so
/// a restart does not sign everyone out and either build can read the other's
/// file: a 16-byte token as the key, and a four-byte expiry, a two-byte name
/// length and the name as the value.
#[derive(Default)]
pub struct Sessions {
    /// The live sessions, by token.
    by_token: Mutex<AHashMap<String, Session>>,
    /// Where the sessions are stored, if anywhere.
    path: Option<PathBuf>,
}

impl Sessions {
    /// Creates an empty, unsaved store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the store backed by a file, loading whatever it holds.
    ///
    /// A missing or unreadable file starts an empty store: losing sessions is
    /// an inconvenience, while refusing to start is an outage.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let by_token = load(&path).unwrap_or_default();

        Self {
            by_token: Mutex::new(by_token),
            path: Some(path),
        }
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
        self.persist();

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
        self.persist();
    }

    /// Drops every expired session.
    pub fn sweep(&self) {
        let now = SystemTime::now();
        let before = self.by_token.lock().len();
        self.by_token.lock().retain(|_, s| s.expires > now);
        if self.by_token.lock().len() != before {
            self.persist();
        }
    }

    /// The number of live sessions.
    pub fn len(&self) -> usize {
        self.by_token.lock().len()
    }

    /// Reports whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writes the store out, if it is backed by a file.
    ///
    /// A write failure is logged rather than propagated: a session that is
    /// only in memory still works until the next restart.
    pub fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let mut bucket: agl_bolt::write::BucketData = BTreeMap::new();
        for (token, s) in self.by_token.lock().iter() {
            let Some(key) = token_bytes(token) else {
                continue;
            };
            bucket.insert(key, encode(s));
        }

        let mut buckets = BTreeMap::new();
        buckets.insert(BUCKET.to_vec(), bucket);

        if let Err(e) = agl_bolt::write_file(path, &buckets, agl_bolt::DEFAULT_PAGE_SIZE) {
            tracing::warn!(path = %path.display(), error = %e, "saving sessions");
        }
    }
}

/// Reads the stored sessions, dropping the expired ones.
fn load(path: &Path) -> Option<AHashMap<String, Session>> {
    let db = agl_bolt::Db::open(path).ok()?;
    let buckets = db.buckets().ok()?;
    let bucket = buckets.get(BUCKET)?;

    let now = SystemTime::now();
    let mut out = AHashMap::new();
    for (key, value) in bucket {
        let Some(s) = decode(value) else {
            continue;
        };
        if s.expires <= now {
            continue;
        }

        out.insert(hex(key), s);
    }

    Some(out)
}

/// Encodes a session the way the Go build stores it.
fn encode(s: &Session) -> Vec<u8> {
    let expire = s
        .expires
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .min(u64::from(u32::MAX)) as u32;

    let name = s.user.as_bytes();
    let mut out = Vec::with_capacity(6 + name.len());
    out.extend_from_slice(&expire.to_be_bytes());
    out.extend_from_slice(&(name.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    out.extend_from_slice(name);

    out
}

/// Decodes a stored session.
fn decode(data: &[u8]) -> Option<Session> {
    if data.len() < 6 {
        return None;
    }

    let expire = u32::from_be_bytes(data[..4].try_into().ok()?);
    let name_len = usize::from(u16::from_be_bytes(data[4..6].try_into().ok()?));
    let name = data.get(6..6 + name_len)?;

    Some(Session {
        user: String::from_utf8_lossy(name).into_owned(),
        expires: UNIX_EPOCH + Duration::from_secs(u64::from(expire)),
    })
}

/// Parses a hex token back into the raw bytes used as the database key.
fn token_bytes(token: &str) -> Option<Vec<u8>> {
    if !token.len().is_multiple_of(2) {
        return None;
    }

    (0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(token.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Renders raw token bytes as the hex form the cookie carries.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }

    s
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
    #[test]
    fn sessions_survive_a_restart() {
        // A restart that signs everyone out is a visible regression, and the
        // file has to be the one the Go build reads.
        let dir = std::env::temp_dir().join(format!("agl-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.db");

        let token = {
            let s = Sessions::open(&path);
            let t = s.create("admin", Duration::from_secs(3600));
            assert_eq!(s.len(), 1);

            t
        };

        let again = Sessions::open(&path);
        assert_eq!(again.len(), 1, "the session should be read back");
        assert_eq!(again.get(&token).map(|s| s.user).as_deref(), Some("admin"));

        again.remove(&token);
        let third = Sessions::open(&path);
        assert!(third.is_empty(), "a logout is persisted too");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_expired_session_is_not_loaded() {
        let dir = std::env::temp_dir().join(format!("agl-sessions-exp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sessions.db");

        {
            let s = Sessions::open(&path);
            // A zero TTL is already in the past by the time it is written.
            s.create("admin", Duration::from_secs(0));
        }

        assert!(Sessions::open(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_database_starts_empty_rather_than_failing() {
        let path = std::env::temp_dir().join("agl-sessions-does-not-exist.db");
        std::fs::remove_file(&path).ok();

        assert!(Sessions::open(&path).is_empty());
    }

    #[test]
    fn the_stored_record_matches_the_go_layout() {
        // Four bytes of expiry, two of name length, then the name.
        let s = Session {
            user: "admin".into(),
            expires: UNIX_EPOCH + Duration::from_secs(0x1234_5678),
        };
        let data = encode(&s);

        assert_eq!(&data[..4], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&data[4..6], &[0x00, 0x05]);
        assert_eq!(&data[6..], b"admin");

        let back = decode(&data).unwrap();
        assert_eq!(back.user, "admin");
        assert_eq!(back.expires, s.expires);
    }

    #[test]
    fn a_short_record_is_rejected() {
        assert!(decode(&[0, 0, 0]).is_none());
        assert!(
            decode(&[0, 0, 0, 0, 0, 9, b'a']).is_none(),
            "name too short"
        );
    }

    #[test]
    fn tokens_round_trip_between_hex_and_bytes() {
        let t = new_token();
        let bytes = token_bytes(&t).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(hex(&bytes), t);
        assert!(token_bytes("abc").is_none(), "an odd length is not hex");
    }

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

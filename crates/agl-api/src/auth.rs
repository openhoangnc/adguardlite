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

/// How long a failed attempt is remembered before the count lapses.
///
/// Upstream's `failedAuthTTL`.  The window runs from the *first* failure, not
/// the last, so a slow trickle of guesses never accumulates into a block.
const FAILED_AUTH_TTL: Duration = Duration::from_secs(60);

/// One client's failed attempts.
#[derive(Clone, Copy)]
struct Failed {
    /// How many there have been.
    count: u32,
    /// When the record lapses -- and, once the count is spent, when the block
    /// lifts.  The two share a field because upstream's do.
    until: SystemTime,
}

/// Tracks failed login attempts per client, to slow down guessing.
///
/// Upstream's `authRateLimiter`, including the part that reads like a bug and
/// is not: until the count reaches the threshold, every failure keeps the
/// *first* one's deadline, so the attempts have to arrive within a minute of
/// each other to add up.  Reaching the threshold replaces that deadline with
/// the full block.
pub struct LoginLimiter {
    /// The clients that have failed recently, by address.
    attempts: Mutex<AHashMap<String, Failed>>,
    /// Failures allowed before the block starts.
    max: u32,
    /// How long the block lasts.
    block: Duration,
}

impl LoginLimiter {
    /// Creates a limiter allowing `max` failures before a `block`-long pause.
    ///
    /// A zero in either switches it off, as upstream's `emptyRateLimiter`
    /// does when `auth_attempts` or `block_auth_min` is zero.
    pub fn new(max: u32, block: Duration) -> Self {
        Self {
            attempts: Mutex::new(AHashMap::new()),
            max,
            block,
        }
    }

    /// Builds the limiter the configuration asks for.
    pub fn from_config(cfg: &agl_config::Config) -> Self {
        Self::new(
            cfg.auth_attempts,
            Duration::from_secs(u64::from(cfg.block_auth_min) * 60),
        )
    }

    /// Reports whether this limiter throttles anything at all.
    pub fn is_enabled(&self) -> bool {
        self.max > 0 && !self.block.is_zero()
    }

    /// How long the client must wait before trying again.
    ///
    /// Zero means it may try now, which covers every client that has not yet
    /// spent its attempts.
    pub fn blocked_for(&self, client: &str) -> Duration {
        if !self.is_enabled() {
            return Duration::ZERO;
        }

        let now = SystemTime::now();
        let mut m = self.attempts.lock();
        m.retain(|_, f| f.until > now);

        let Some(f) = m.get(client) else {
            return Duration::ZERO;
        };
        if f.count < self.max {
            return Duration::ZERO;
        }

        f.until.duration_since(now).unwrap_or(Duration::ZERO)
    }

    /// Records a failed attempt.
    pub fn record_failure(&self, client: &str) {
        if !self.is_enabled() {
            return;
        }

        let now = SystemTime::now();
        let mut m = self.attempts.lock();
        let f = m.entry(client.to_string()).or_insert(Failed {
            count: 0,
            until: now + FAILED_AUTH_TTL,
        });
        f.count += 1;

        // Spending the last attempt is what starts the block; the failures
        // before it only set how long they have to arrive within.
        if f.count >= self.max {
            f.until = now + self.block;
        }
    }

    /// Clears a client's failures after a successful login.
    pub fn record_success(&self, client: &str) {
        self.attempts.lock().remove(client);
    }
}

/// The refusal a client that has spent its attempts gets.
///
/// `Retry-After` is whole seconds, and `left` is truncated to them rather
/// than rounded, which is what upstream's `int(left.Seconds())` does too.
pub fn too_many_attempts(left: Duration) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, left.as_secs().to_string())],
        "too many login attempts",
    )
        .into_response()
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
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        assert!(l.blocked_for("1.2.3.4").is_zero());

        // The attempts themselves are allowed; spending the last one is what
        // starts the block.
        for _ in 0..2 {
            l.record_failure("1.2.3.4");
            assert!(l.blocked_for("1.2.3.4").is_zero());
        }
        l.record_failure("1.2.3.4");

        let left = l.blocked_for("1.2.3.4");
        assert!(
            left > Duration::from_secs(890) && left <= Duration::from_secs(900),
            "the block should run for about the configured time, not {left:?}"
        );

        // A different client is unaffected.
        assert!(l.blocked_for("5.6.7.8").is_zero());

        l.record_success("1.2.3.4");
        assert!(l.blocked_for("1.2.3.4").is_zero());
    }

    #[test]
    fn failures_short_of_the_threshold_lapse_on_their_own() {
        // Upstream keeps the *first* failure's one-minute deadline until the
        // count is spent, so a trickle of guesses never adds up. Reaching
        // back past that deadline is what a slow attacker does, and the
        // record has to be gone by then.
        let l = LoginLimiter::new(3, Duration::from_secs(900));
        l.record_failure("1.2.3.4");

        let lapsed = SystemTime::now() - Duration::from_secs(1);
        l.attempts.lock().get_mut("1.2.3.4").unwrap().until = lapsed;

        assert!(l.blocked_for("1.2.3.4").is_zero());
        assert!(
            l.attempts.lock().is_empty(),
            "a lapsed record should be swept, not counted towards a block"
        );
    }

    #[test]
    fn a_zero_in_either_bound_switches_the_limiter_off() {
        // Upstream's `emptyRateLimiter`, which it installs when
        // `auth_attempts` or `block_auth_min` is zero.
        for l in [
            LoginLimiter::new(0, Duration::from_secs(900)),
            LoginLimiter::new(3, Duration::ZERO),
        ] {
            assert!(!l.is_enabled());
            for _ in 0..10 {
                l.record_failure("1.2.3.4");
            }
            assert!(l.blocked_for("1.2.3.4").is_zero());
        }
    }

    #[test]
    fn the_limiter_takes_its_bounds_from_the_configuration() {
        let mut cfg = agl_config::Config::default();
        assert_eq!(cfg.auth_attempts, 5, "upstream's default");
        assert_eq!(cfg.block_auth_min, 15, "upstream's default, in minutes");

        let l = LoginLimiter::from_config(&cfg);
        assert!(l.is_enabled());
        for _ in 0..5 {
            l.record_failure("1.2.3.4");
        }
        assert!(l.blocked_for("1.2.3.4") > Duration::from_secs(890));

        cfg.auth_attempts = 0;
        assert!(!LoginLimiter::from_config(&cfg).is_enabled());
    }

    #[test]
    fn the_refusal_carries_the_seconds_left() {
        let r = too_many_attempts(Duration::from_millis(899_900));
        assert_eq!(r.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            // Truncated, as upstream's `int(left.Seconds())` truncates.
            Some("899")
        );
    }
}

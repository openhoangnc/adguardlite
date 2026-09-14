//! A YAML emitter that reproduces Go `yaml.v3`'s output style byte for byte.
//!
//! The style points that matter for a drop-in config file:
//!
//!   * two-space indent;
//!   * sequence items are indented one level under their key
//!     (`key:\n  - item`), unlike most Rust YAML emitters;
//!   * empty sequences and maps render inline as `[]` and `{}`;
//!   * scalars stay plain unless quoting is required to preserve their type.

use super::value::Yaml;

/// Renders `v` as a YAML document, including the trailing newline.
pub fn to_string(v: &Yaml) -> String {
    let mut out = String::with_capacity(4096);
    match v {
        Yaml::Map(m) if !m.is_empty() => emit_map(&mut out, m, 0),
        Yaml::Seq(s) if !s.is_empty() => emit_seq(&mut out, s, 0),
        other => {
            out.push_str(&scalar(other));
            out.push('\n');
        }
    }

    out
}

/// Emits a mapping's entries at `indent` columns.
fn emit_map(out: &mut String, m: &[(String, Yaml)], indent: usize) {
    for (k, v) in m {
        push_indent(out, indent);
        out.push_str(&quote_key(k));
        out.push(':');
        emit_value_after_key(out, v, indent);
    }
}

/// Emits the value that follows a `key:` that has already been written.
fn emit_value_after_key(out: &mut String, v: &Yaml, indent: usize) {
    match v {
        Yaml::Seq(s) if s.is_empty() => out.push_str(" []\n"),
        Yaml::Map(m) if m.is_empty() => out.push_str(" {}\n"),
        Yaml::Seq(s) => {
            out.push('\n');
            emit_seq(out, s, indent + 2);
        }
        Yaml::Map(m) => {
            out.push('\n');
            emit_map(out, m, indent + 2);
        }
        scalar_node => {
            out.push(' ');
            out.push_str(&scalar(scalar_node));
            out.push('\n');
        }
    }
}

/// Emits a sequence's items at `indent` columns.
fn emit_seq(out: &mut String, s: &[Yaml], indent: usize) {
    for item in s {
        push_indent(out, indent);
        out.push_str("- ");
        match item {
            Yaml::Seq(inner) if inner.is_empty() => out.push_str("[]\n"),
            Yaml::Map(inner) if inner.is_empty() => out.push_str("{}\n"),
            Yaml::Map(inner) => {
                // The first key sits on the dash line; the rest align under it.
                let (k0, v0) = &inner[0];
                out.push_str(&quote_key(k0));
                out.push(':');
                emit_value_after_key(out, v0, indent + 2);
                if inner.len() > 1 {
                    emit_map(out, &inner[1..], indent + 2);
                }
            }
            Yaml::Seq(inner) => {
                out.push('\n');
                emit_seq(out, inner, indent + 2);
            }
            scalar_node => {
                out.push_str(&scalar(scalar_node));
                out.push('\n');
            }
        }
    }
}

/// Appends `n` spaces.
fn push_indent(out: &mut String, n: usize) {
    out.extend(std::iter::repeat_n(' ', n));
}

/// Renders a scalar node.
fn scalar(v: &Yaml) -> String {
    match v {
        Yaml::Null => "null".to_string(),
        Yaml::Bool(b) => b.to_string(),
        Yaml::Int(i) => i.to_string(),
        Yaml::UInt(u) => u.to_string(),
        Yaml::Float(f) => format_float(*f),
        Yaml::Str(s) => quote_str(s),
        // Collections are handled by the callers; reaching here means an empty
        // one nested where a scalar was expected.
        Yaml::Seq(_) => "[]".to_string(),
        Yaml::Map(_) => "{}".to_string(),
    }
}

/// Formats a float the way Go's YAML encoder does.
fn format_float(f: f64) -> String {
    if f.is_nan() {
        return ".nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { ".inf" } else { "-.inf" }.to_string();
    }
    if f == f.trunc() && f.abs() < 1e15 {
        return format!("{f:.0}");
    }

    format!("{f}")
}

/// Quotes a mapping key if required.
fn quote_key(k: &str) -> String {
    quote_str(k)
}

/// Renders a string, quoting only when a plain scalar would not round-trip.
fn quote_str(s: &str) -> String {
    if needs_quoting(s) {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');

        out
    } else {
        s.to_string()
    }
}

/// Reports whether `s` must be quoted to survive a parse as a string.
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }

    // Leading or trailing whitespace would be stripped.
    if s.starts_with(|c: char| c.is_whitespace()) || s.ends_with(|c: char| c.is_whitespace()) {
        return true;
    }

    // A leading indicator character changes the node's meaning.
    let b = s.as_bytes();
    let first = b[0];
    if matches!(
        first,
        b',' | b'[' | b']' | b'{' | b'}' | b'#' | b'&' | b'*' | b'!' | b'|' | b'>'
            | b'\'' | b'"' | b'%' | b'@' | b'`'
    ) {
        return true;
    }

    // `-`, `?` and `:` only act as indicators when a space follows, so
    // `::1/128` and `-foo` stay plain, matching upstream.
    if matches!(first, b'-' | b'?' | b':')
        && (b.len() == 1 || matches!(b[1], b' ' | b'\t'))
    {
        return true;
    }

    // These sequences end a plain scalar mid-string.
    if s.contains(": ") || s.contains(" #") || s.ends_with(':') {
        return true;
    }

    // Control characters cannot appear plain.
    if s.chars().any(|c| c.is_control()) {
        return true;
    }

    // Anything a parser would resolve to a non-string type must be quoted.
    resolves_to_non_string(s)
}

/// Reports whether a plain scalar `s` would be resolved as a bool, null, or
/// number rather than a string, and therefore has to be quoted.
///
/// This mirrors Go `yaml.v3`'s `resolve()`.  Note it detects types by parsing,
/// not by character class: `127.0.0.1` contains only digits and dots but is
/// not a number, and upstream emits it unquoted.
fn resolves_to_non_string(s: &str) -> bool {
    // Nulls and booleans.  The YAML 1.1 spellings (`yes`, `on`, ...) are not
    // bools in yaml.v3, but quoting them is the safe choice.
    const RESERVED: &[&str] = &[
        "true", "True", "TRUE", "false", "False", "FALSE", "null", "Null", "NULL", "~",
        "yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF",
    ];
    if RESERVED.contains(&s) {
        return true;
    }

    if is_yaml_int(s) || is_yaml_float(s) {
        return true;
    }

    // Timestamps resolve to `!!timestamp` in yaml.v3.
    is_yaml_timestamp(s)
}

/// Reports whether `s` parses as a YAML integer in any supported base.
fn is_yaml_int(s: &str) -> bool {
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if body.is_empty() {
        return false;
    }

    let cleaned = body.replace('_', "");
    if cleaned.is_empty() {
        return false;
    }

    if let Some(hex) = cleaned.strip_prefix("0x").or_else(|| cleaned.strip_prefix("0X")) {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some(oct) = cleaned.strip_prefix("0o").or_else(|| cleaned.strip_prefix("0O")) {
        return !oct.is_empty() && oct.bytes().all(|b| (b'0'..=b'7').contains(&b));
    }
    if let Some(bin) = cleaned.strip_prefix("0b").or_else(|| cleaned.strip_prefix("0B")) {
        return !bin.is_empty() && bin.bytes().all(|b| b == b'0' || b == b'1');
    }

    cleaned.bytes().all(|b| b.is_ascii_digit())
}

/// Reports whether `s` parses as a YAML float.
fn is_yaml_float(s: &str) -> bool {
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if matches!(body, ".inf" | ".Inf" | ".INF" | ".nan" | ".NaN" | ".NAN") {
        return true;
    }

    let cleaned = body.replace('_', "");
    // Reject things Rust's parser accepts but YAML does not treat as floats,
    // such as "inf" and "NaN" without the leading dot.
    if cleaned
        .bytes()
        .any(|b| !(b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')))
    {
        return false;
    }
    if !cleaned.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }

    cleaned.parse::<f64>().is_ok()
}

/// Reports whether `s` looks like a YAML timestamp, which yaml.v3 resolves to
/// a non-string type.  Only the leading `YYYY-MM-DD` needs checking: a plain
/// scalar starting that way is always resolved as a timestamp.
fn is_yaml_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 10 {
        return false;
    }

    b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: Vec<(&str, Yaml)>) -> Yaml {
        Yaml::Map(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    fn s(v: &str) -> Yaml {
        Yaml::Str(v.to_string())
    }

    #[test]
    fn indents_sequences_under_their_key_like_go() {
        let y = m(vec![("bind_hosts", Yaml::Seq(vec![s("127.0.0.1")]))]);
        assert_eq!(to_string(&y), "bind_hosts:\n  - 127.0.0.1\n");
    }

    #[test]
    fn renders_empty_collections_inline() {
        let y = m(vec![
            ("ratelimit_whitelist", Yaml::Seq(vec![])),
            ("opts", Yaml::Map(vec![])),
        ]);
        assert_eq!(to_string(&y), "ratelimit_whitelist: []\nopts: {}\n");
    }

    #[test]
    fn sequence_of_maps_puts_first_key_on_the_dash_line() {
        let y = m(vec![(
            "users",
            Yaml::Seq(vec![m(vec![("name", s("admin")), ("password", s("$2a$10$x"))])]),
        )]);
        assert_eq!(
            to_string(&y),
            "users:\n  - name: admin\n    password: $2a$10$x\n"
        );
    }

    #[test]
    fn quotes_only_what_must_be_quoted() {
        assert_eq!(quote_str("auto"), "auto");
        assert_eq!(quote_str("load_balance"), "load_balance");
        assert_eq!(quote_str("30d"), "30d");
        assert_eq!(quote_str("256MB"), "256MB");
        assert_eq!(quote_str("127.0.0.1:13000"), "127.0.0.1:13000");
        assert_eq!(quote_str("GET /dns-query/{ClientID}"), "GET /dns-query/{ClientID}");
        assert_eq!(quote_str("family-block.dns.adguard.com"), "family-block.dns.adguard.com");
        assert_eq!(quote_str("$2a$10$dDdZ"), "$2a$10$dDdZ");

        // Must be quoted: type-confusable or structurally unsafe.
        assert_eq!(quote_str(""), r#""""#);
        assert_eq!(quote_str("true"), r#""true""#);
        assert_eq!(quote_str("123"), r#""123""#);
        assert_eq!(quote_str("null"), r#""null""#);
        assert_eq!(quote_str("yes"), r#""yes""#);
        assert_eq!(quote_str("- x"), r#""- x""#);
        assert_eq!(quote_str("a: b"), r#""a: b""#);
        assert_eq!(quote_str("{inline}"), r#""{inline}""#);
        assert_eq!(quote_str(" pad"), r#"" pad""#);
    }

    #[test]
    fn nests_maps() {
        let y = m(vec![(
            "http",
            m(vec![("pprof", m(vec![("port", Yaml::Int(6060))]))]),
        )]);
        assert_eq!(to_string(&y), "http:\n  pprof:\n    port: 6060\n");
    }

    #[test]
    fn renders_null_and_bools() {
        let y = m(vec![
            ("protection_disabled_until", Yaml::Null),
            ("enabled", Yaml::Bool(false)),
        ]);
        assert_eq!(
            to_string(&y),
            "protection_disabled_until: null\nenabled: false\n"
        );
    }
}

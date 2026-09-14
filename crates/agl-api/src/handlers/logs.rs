//! The query log and statistics endpoints.

use agl_querylog::entry::Entry;
use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{ApiError, ApiResult};
use crate::state::Shared;

/// One answer record, as the query log API reports it.
#[derive(Serialize)]
pub struct AnswerJson {
    /// The record type.
    #[serde(rename = "type")]
    pub rtype: String,
    /// The record's value.
    pub value: String,
    /// The record's TTL.
    pub ttl: u32,
}

/// The question a log entry recorded.
#[derive(Serialize)]
pub struct QuestionJson {
    /// The query class.
    pub class: String,
    /// The queried name.
    pub name: String,
    /// The query type.
    #[serde(rename = "type")]
    pub qtype: String,
}

/// A matched rule, as the query log API reports it.
#[derive(Serialize)]
pub struct RuleJson {
    /// The list the rule came from.
    pub filter_list_id: i64,
    /// The rule's text.
    pub text: String,
}

/// One entry of the query log API response.
#[derive(Serialize)]
pub struct LogEntryJson {
    /// The answer records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<Vec<AnswerJson>>,
    /// Whether the answer was DNSSEC-authenticated.
    pub answer_dnssec: bool,
    /// Whether the answer came from the cache.
    pub cached: bool,
    /// The client's address.
    pub client: String,
    /// What is known about the client.
    pub client_info: serde_json::Value,
    /// The transport the query arrived on.
    pub client_proto: String,
    /// How long handling took, in milliseconds, as a string.
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: String,
    /// The winning rule's list.
    #[serde(rename = "filterId", skip_serializing_if = "Option::is_none")]
    pub filter_id: Option<i64>,
    /// The question.
    pub question: QuestionJson,
    /// Why the query was filtered, allowed or rewritten.
    pub reason: String,
    /// The winning rule's text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Every matching rule.
    pub rules: Vec<RuleJson>,
    /// The response code.
    pub status: String,
    /// When the query was handled.
    pub time: String,
    /// The upstream that answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// The `/control/querylog` query parameters.
#[derive(Deserialize, Default)]
pub struct QueryLogParams {
    /// How many entries to return.
    #[serde(default)]
    pub limit: Option<usize>,
    /// How many entries to skip.
    #[serde(default)]
    pub offset: Option<usize>,
    /// A substring to match against the host or client.
    #[serde(default)]
    pub search: Option<String>,
    /// Which outcomes to include.
    #[serde(default)]
    pub response_status: Option<String>,
    /// Return entries older than this timestamp.
    #[serde(default)]
    pub older_than: Option<String>,
}

/// `GET /control/querylog`
pub async fn querylog(
    State(s): State<Shared>,
    Query(p): Query<QueryLogParams>,
) -> Json<serde_json::Value> {
    let limit = p.limit.unwrap_or(500).min(5_000);
    let offset = p.offset.unwrap_or(0);

    // Over-read so filtering still fills a page.
    let raw = s.querylog.read(offset, limit.saturating_mul(4).max(limit));

    let search = p.search.as_deref().map(str::to_ascii_lowercase);
    let status = p.response_status.as_deref().unwrap_or("all");

    let filtered: Vec<&Entry> = raw
        .iter()
        .filter(|e| matches_search(e, search.as_deref()))
        .filter(|e| matches_status(e, status))
        .take(limit)
        .collect();

    let oldest = filtered.last().map(|e| e.time.clone()).unwrap_or_default();
    let data: Vec<LogEntryJson> = filtered.iter().map(|e| to_json(e)).collect();

    Json(json!({ "data": data, "oldest": oldest }))
}

/// Reports whether an entry matches a search term.
fn matches_search(e: &Entry, term: Option<&str>) -> bool {
    let Some(t) = term else {
        return true;
    };
    if t.is_empty() {
        return true;
    }

    e.question_host.to_ascii_lowercase().contains(t) || e.ip.to_ascii_lowercase().contains(t)
}

/// Reports whether an entry matches a response-status filter.
fn matches_status(e: &Entry, status: &str) -> bool {
    use agl_core::Reason as R;

    let r = e.result.reason;
    match status {
        "all" | "" => true,
        "filtered" => r.matched() && r != R::NotFilteredNotFound,
        "blocked" => r.is_filtered(),
        "blocked_safebrowsing" => r == R::FilteredSafeBrowsing,
        "blocked_parental" => r == R::FilteredParental,
        "whitelisted" => r == R::NotFilteredAllowList,
        "rewritten" => matches!(r, R::Rewritten | R::RewrittenAutoHosts | R::RewrittenRule),
        "safe_search" => r == R::FilteredSafeSearch,
        "processed" => !r.is_filtered(),
        _ => true,
    }
}

/// Converts a stored entry into its API form.
fn to_json(e: &Entry) -> LogEntryJson {
    let (status, answers, dnssec) = decode_answer(e);

    let first = e.result.rules.first();

    LogEntryJson {
        answer: answers,
        answer_dnssec: dnssec || e.authenticated_data,
        cached: e.cached,
        client: e.ip.clone(),
        client_info: json!({ "whois": {}, "name": "", "disallowed_rule": "", "disallowed": false }),
        client_proto: e.client_proto.as_str().to_string(),
        // Upstream sends this as a string, not a number.
        elapsed_ms: format!("{}", e.elapsed as f64 / 1_000_000.0),
        filter_id: first.map(|r| r.filter_list_id),
        question: QuestionJson {
            class: e.question_class.clone(),
            name: e.question_host.clone(),
            qtype: e.question_type.clone(),
        },
        reason: e.result.reason.as_str().to_string(),
        rule: first.map(|r| r.text.clone()),
        rules: e
            .result
            .rules
            .iter()
            .map(|r| RuleJson {
                filter_list_id: r.filter_list_id,
                text: r.text.clone(),
            })
            .collect(),
        status,
        time: e.time.clone(),
        upstream: (!e.upstream.is_empty()).then(|| e.upstream.clone()),
    }
}

/// Decodes the stored answer into a response code and record list.
fn decode_answer(e: &Entry) -> (String, Option<Vec<AnswerJson>>, bool) {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    let Some(wire) = e.answer.as_deref().and_then(Entry::decode_answer) else {
        return ("NOERROR".to_string(), None, false);
    };
    let Ok(msg) = Message::from_bytes(&wire) else {
        return ("NOERROR".to_string(), None, false);
    };

    let status = format!("{:?}", msg.metadata.response_code).to_uppercase();
    let status = normalise_rcode(&status);

    let answers: Vec<AnswerJson> = msg
        .answers
        .iter()
        .map(|r| AnswerJson {
            rtype: r.record_type().to_string(),
            value: rdata_text(&r.data),
            ttl: r.ttl,
        })
        .collect();

    (
        status,
        (!answers.is_empty()).then_some(answers),
        msg.metadata.authentic_data,
    )
}

/// Renders a record's value the way the UI expects.
fn rdata_text(d: &hickory_proto::rr::RData) -> String {
    use hickory_proto::rr::RData;

    match d {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(c) => c.0.to_ascii(),
        RData::PTR(p) => p.0.to_ascii(),
        RData::NS(n) => n.0.to_ascii(),
        other => other.to_string(),
    }
}

/// Maps hickory's response-code spelling onto the wire names the UI shows.
fn normalise_rcode(s: &str) -> String {
    match s {
        "NOERROR" => "NOERROR",
        "NXDOMAIN" => "NXDOMAIN",
        "SERVFAIL" => "SERVFAIL",
        "REFUSED" => "REFUSED",
        "FORMERR" => "FORMERR",
        "NOTIMP" => "NOTIMP",
        other => return other.to_string(),
    }
    .to_string()
}

/// `GET /control/querylog_info` and `/control/querylog/config`
pub async fn querylog_info(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();

    Json(json!({
        "interval": cfg.querylog.interval.as_days(),
        "enabled": cfg.querylog.enabled,
        "anonymize_client_ip": cfg.dns.anonymize_client_ip,
    }))
}

/// `GET /control/querylog/config`
///
/// Note the interval here is in **milliseconds**, unlike the legacy
/// `/control/querylog_info`, which reports days.
pub async fn querylog_config(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();

    Json(json!({
        "ignored": cfg.querylog.ignored,
        "interval": cfg.querylog.interval.as_millis(),
        "enabled": cfg.querylog.enabled,
        "ignored_enabled": cfg.querylog.ignored_enabled,
        "anonymize_client_ip": cfg.dns.anonymize_client_ip,
    }))
}

/// The `/control/querylog/config/update` request.
#[derive(Deserialize, Default)]
pub struct QueryLogConfigReq {
    /// Whether the log is collected.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// The rotation interval, in milliseconds.
    #[serde(default)]
    pub interval: Option<i64>,
    /// Whether client addresses are anonymised.
    #[serde(default)]
    pub anonymize_client_ip: Option<bool>,
    /// Hosts excluded from the log.
    #[serde(default)]
    pub ignored: Option<Vec<String>>,
}

/// `PUT /control/querylog/config/update`
pub async fn querylog_config_update(
    State(s): State<Shared>,
    Json(req): Json<QueryLogConfigReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        if let Some(v) = req.enabled {
            cfg.querylog.enabled = v;
        }
        if let Some(v) = req.interval {
            cfg.querylog.interval = agl_core::GoDuration::from_millis(v);
        }
        if let Some(v) = req.anonymize_client_ip {
            cfg.dns.anonymize_client_ip = v;
        }
        if let Some(v) = req.ignored {
            cfg.querylog.ignored_enabled = !v.is_empty();
            cfg.querylog.ignored = v;
        }
    }

    apply_querylog_config(&s);

    s.save_config().map_err(ApiError::internal)
}

/// The legacy `/control/querylog_config` request.
#[derive(Deserialize)]
pub struct LegacyQueryLogConfigReq {
    /// Whether the log is collected.
    pub enabled: bool,
    /// The rotation interval, in days.
    pub interval: u64,
    /// Whether client addresses are anonymised.
    pub anonymize_client_ip: bool,
}

/// `POST /control/querylog_config`
pub async fn querylog_config_legacy(
    State(s): State<Shared>,
    Json(req): Json<LegacyQueryLogConfigReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        cfg.querylog.enabled = req.enabled;
        cfg.querylog.interval = agl_core::GoDuration::from_days(req.interval as i64);
        cfg.dns.anonymize_client_ip = req.anonymize_client_ip;
    }

    apply_querylog_config(&s);

    s.save_config().map_err(ApiError::internal)
}

/// Pushes the stored settings into the running log.
fn apply_querylog_config(s: &Shared) {
    let cfg = s.config.read();
    s.querylog.set_config(agl_querylog::log::Config {
        enabled: cfg.querylog.enabled,
        file_enabled: cfg.querylog.file_enabled,
        size_memory: cfg.querylog.size_memory as usize,
        ignored: cfg.querylog.ignored.clone(),
        ignored_enabled: cfg.querylog.ignored_enabled,
        anonymize_client_ip: cfg.dns.anonymize_client_ip,
    });
}

/// `POST /control/querylog_clear`
pub async fn querylog_clear(State(s): State<Shared>) -> ApiResult<()> {
    s.querylog
        .clear()
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// `GET /control/stats`
pub async fn stats(State(s): State<Shared>) -> Json<agl_stats::stats::StatsResp> {
    Json(s.stats.data())
}

/// `GET /control/stats_info`
pub async fn stats_info(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();

    Json(json!({ "interval": cfg.statistics.interval.as_days() }))
}

/// `GET /control/stats/config`
///
/// The interval is in **milliseconds** here, unlike the legacy
/// `/control/stats_info`, which reports days.
pub async fn stats_config(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();

    Json(json!({
        "ignored": cfg.statistics.ignored,
        "interval": cfg.statistics.interval.as_millis(),
        "enabled": cfg.statistics.enabled,
        "ignored_enabled": cfg.statistics.ignored_enabled,
    }))
}

/// The `/control/stats/config/update` request.
#[derive(Deserialize, Default)]
pub struct StatsConfigReq {
    /// Whether statistics are collected.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// The retention window, in milliseconds.
    #[serde(default)]
    pub interval: Option<i64>,
    /// Hosts excluded from the top lists.
    #[serde(default)]
    pub ignored: Option<Vec<String>>,
}

/// `PUT /control/stats/config/update`
pub async fn stats_config_update(
    State(s): State<Shared>,
    Json(req): Json<StatsConfigReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        if let Some(v) = req.enabled {
            cfg.statistics.enabled = v;
        }
        if let Some(v) = req.interval {
            cfg.statistics.interval = agl_core::GoDuration::from_millis(v);
        }
        if let Some(v) = req.ignored {
            cfg.statistics.ignored_enabled = !v.is_empty();
            cfg.statistics.ignored = v;
        }
    }

    apply_stats_config(&s);

    s.save_config().map_err(ApiError::internal)
}

/// The legacy `/control/stats_config` request.
#[derive(Deserialize)]
pub struct LegacyStatsConfigReq {
    /// The retention window, in days.
    pub interval: u64,
}

/// `POST /control/stats_config`
pub async fn stats_config_legacy(
    State(s): State<Shared>,
    Json(req): Json<LegacyStatsConfigReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        cfg.statistics.interval = agl_core::GoDuration::from_days(req.interval as i64);
        cfg.statistics.enabled = req.interval != 0;
    }

    apply_stats_config(&s);

    s.save_config().map_err(ApiError::internal)
}

/// Pushes the stored settings into the running collector.
fn apply_stats_config(s: &Shared) {
    let cfg = s.config.read();
    s.stats.set_config(agl_stats::stats::Config {
        enabled: cfg.statistics.enabled,
        limit_hours: cfg.statistics.interval.as_hours().max(0) as u32,
        ignored: cfg.statistics.ignored.clone(),
        ignored_enabled: cfg.statistics.ignored_enabled,
    });
}

/// `POST /control/stats_reset`
pub async fn stats_reset(State(s): State<Shared>) -> ApiResult<()> {
    s.stats.clear();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agl_core::Reason;
    use agl_querylog::entry::Result as EntryResult;

    fn entry(host: &str, reason: Reason) -> Entry {
        Entry {
            time: "2026-09-14T17:41:53.85+07:00".into(),
            question_host: host.into(),
            question_type: "A".into(),
            question_class: "IN".into(),
            ip: "192.168.1.5".into(),
            elapsed: 1_500_000,
            result: EntryResult {
                reason,
                is_filtered: reason.is_filtered(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn search_matches_host_and_client() {
        let e = entry("ads.example.com", Reason::FilteredBlockList);
        assert!(matches_search(&e, Some("example")));
        assert!(matches_search(&e, Some("192.168")));
        assert!(!matches_search(&e, Some("nothing")));
        assert!(matches_search(&e, None), "no term matches everything");
        assert!(
            matches_search(&e, Some("")),
            "an empty term matches everything"
        );
    }

    #[test]
    fn status_filters_select_the_right_entries() {
        let blocked = entry("a.com", Reason::FilteredBlockList);
        let allowed = entry("b.com", Reason::NotFilteredAllowList);
        let plain = entry("c.com", Reason::NotFilteredNotFound);
        let rewritten = entry("d.com", Reason::RewrittenRule);

        assert!(matches_status(&blocked, "blocked"));
        assert!(!matches_status(&allowed, "blocked"));

        assert!(matches_status(&allowed, "whitelisted"));
        assert!(!matches_status(&blocked, "whitelisted"));

        assert!(matches_status(&rewritten, "rewritten"));
        assert!(!matches_status(&plain, "rewritten"));

        assert!(matches_status(&plain, "processed"));
        assert!(!matches_status(&blocked, "processed"));

        for e in [&blocked, &allowed, &plain] {
            assert!(matches_status(e, "all"));
        }
    }

    #[test]
    fn elapsed_is_reported_in_milliseconds_as_a_string() {
        let e = entry("a.com", Reason::NotFilteredNotFound);
        let j = to_json(&e);
        assert_eq!(j.elapsed_ms, "1.5", "1,500,000 ns is 1.5 ms");
    }

    #[test]
    fn the_api_entry_carries_the_winning_rule() {
        let mut e = entry("a.com", Reason::FilteredBlockList);
        e.result.rules = vec![agl_querylog::entry::ResultRule {
            text: "||a.com^".into(),
            ip: None,
            filter_list_id: 7,
        }];

        let j = to_json(&e);
        assert_eq!(j.rule.as_deref(), Some("||a.com^"));
        assert_eq!(j.filter_id, Some(7));
        assert_eq!(j.rules.len(), 1);
        assert_eq!(j.reason, "FilteredBlackList");
    }

    #[test]
    fn an_entry_without_rules_omits_them() {
        let j = to_json(&entry("a.com", Reason::NotFilteredNotFound));
        assert!(j.rule.is_none());
        assert!(j.filter_id.is_none());
        assert!(j.rules.is_empty());
        assert!(j.upstream.is_none());
    }
}

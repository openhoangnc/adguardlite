//! Filter lists, custom rules, rewrites, blocked services and safe search.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sift_config::model::{FilterYaml, Rewrite};

use crate::error::{ApiError, ApiResult};
use crate::state::Shared;

/// A filter list as the API reports it.
#[derive(Serialize)]
pub struct FilterJson {
    /// Where the list is fetched from.
    pub url: String,
    /// The list's display name.
    pub name: String,
    /// When the list was last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
    /// The list's identifier.
    pub id: i64,
    /// How many rules the list holds.
    pub rules_count: usize,
    /// Whether the list is applied.
    pub enabled: bool,
}

/// The `/control/filtering/status` response.
#[derive(Serialize)]
pub struct FilteringStatus {
    /// Blocklists.
    pub filters: Option<Vec<FilterJson>>,
    /// Allowlists.
    pub whitelist_filters: Option<Vec<FilterJson>>,
    /// The user's own rules.
    pub user_rules: Option<Vec<String>>,
    /// Hours between refreshes.
    pub interval: u32,
    /// Whether filtering is on.
    pub enabled: bool,
}

/// Converts a loaded list into its API form.
fn to_json(l: &sift_filter::lists::List) -> FilterJson {
    FilterJson {
        url: l.url.clone(),
        name: l.name.clone(),
        last_updated: l.last_updated.map(sift_core::gotime::format_local),
        id: l.id,
        rules_count: l.rules_count,
        enabled: l.enabled,
    }
}

/// Renders an empty list as `null`, which is what Go's encoder does for a nil
/// slice and what the web UI expects.
fn or_null<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() { None } else { Some(v) }
}

/// `GET /control/filtering/catalogue`
///
/// The known blocklists the interface offers to add without typing an
/// address.  **Not one of upstream's paths**: AdGuard Home bundles this
/// catalogue in its client instead of serving it, and this build keeps it on
/// the server so the frontend carries nothing of AdGuard's.  Adding a path is
/// safe for the drop-in contract -- the two builds are never asked to serve
/// the same interface -- and the interface degrades to the custom-address form
/// if it ever answers 404.
pub async fn catalogue() -> Json<&'static sift_filter::blocklists::Catalogue> {
    Json(sift_filter::blocklists::catalogue())
}

/// `GET /control/filtering/status`
pub async fn status(State(s): State<Shared>) -> Json<FilteringStatus> {
    let filters = s.filters.read();
    let cfg = s.config.read();

    Json(FilteringStatus {
        filters: or_null(filters.blocklists.iter().map(to_json).collect()),
        whitelist_filters: or_null(filters.allowlists.iter().map(to_json).collect()),
        user_rules: or_null(filters.user_rules.clone()),
        interval: cfg.filtering.filters_update_interval,
        enabled: cfg.filtering.filtering_enabled,
    })
}

/// The `/control/filtering/config` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct FilteringConfigReq {
    /// Whether filtering is on.
    pub enabled: bool,
    /// Hours between refreshes.
    pub interval: u32,
}

/// `POST /control/filtering/config`
pub async fn set_config(
    State(s): State<Shared>,
    Json(req): Json<FilteringConfigReq>,
) -> ApiResult<()> {
    const ALLOWED: [u32; 6] = [0, 1, 12, 24, 72, 168];
    if !ALLOWED.contains(&req.interval) {
        return Err(ApiError::bad_request(format!(
            "unsupported refresh interval {}; expected one of {ALLOWED:?}",
            req.interval
        )));
    }

    {
        let mut cfg = s.config.write();
        cfg.filtering.filtering_enabled = req.enabled;
        cfg.filtering.filters_update_interval = req.interval;
    }

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/filtering/add_url` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct AddUrlReq {
    /// The list's display name.
    pub name: String,
    /// Where to fetch the list from.
    pub url: String,
    /// Whether this is an allowlist.
    #[serde(default)]
    pub whitelist: bool,
}

/// `POST /control/filtering/add_url`
pub async fn add_url(State(s): State<Shared>, Json(req): Json<AddUrlReq>) -> ApiResult<()> {
    if req.url.trim().is_empty() {
        return Err(ApiError::bad_request("the list url must not be empty"));
    }

    let id = {
        let mut filters = s.filters.write();
        if filters
            .blocklists
            .iter()
            .chain(&filters.allowlists)
            .any(|l| l.url == req.url)
        {
            return Err(ApiError::bad_request(
                "a filter with this url already exists",
            ));
        }

        let id = filters.next_id();
        let cfg = FilterYaml {
            enabled: true,
            url: req.url.clone(),
            name: req.name.clone(),
            id,
        };
        let list = sift_filter::lists::List::from_config(&cfg, req.whitelist);
        if req.whitelist {
            filters.allowlists.push(list);
        } else {
            filters.blocklists.push(list);
        }

        id
    };

    // Fetch the contents now so the UI can show a rule count straight away.
    // A download failure leaves the list configured but empty, which is what
    // upstream does too.
    if let Ok(text) = s.fetcher.fetch(req.url.clone()).await {
        let mut filters = s.filters.write();
        let _ = filters.apply_fetched(&s.paths, id, text);
    }

    s.save_filters().map_err(ApiError::internal)
}

/// The `/control/filtering/remove_url` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct RemoveUrlReq {
    /// The list to remove.
    pub url: String,
    /// Whether it is an allowlist.
    #[serde(default)]
    pub whitelist: bool,
}

/// `POST /control/filtering/remove_url`
pub async fn remove_url(State(s): State<Shared>, Json(req): Json<RemoveUrlReq>) -> ApiResult<()> {
    {
        let mut filters = s.filters.write();
        let target = if req.whitelist {
            &mut filters.allowlists
        } else {
            &mut filters.blocklists
        };
        target.retain(|l| l.url != req.url);
    }

    s.save_filters().map_err(ApiError::internal)
}

/// The `/control/filtering/set_url` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SetUrlReq {
    /// The list to change.
    pub url: String,
    /// Whether it is an allowlist.
    #[serde(default)]
    pub whitelist: bool,
    /// The new settings.
    pub data: SetUrlData,
}

/// The new settings for a list.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SetUrlData {
    /// The new display name.
    pub name: String,
    /// The new URL.
    pub url: String,
    /// Whether the list is applied.
    pub enabled: bool,
}

/// `POST /control/filtering/set_url`
pub async fn set_url(State(s): State<Shared>, Json(req): Json<SetUrlReq>) -> ApiResult<()> {
    let changed_url = {
        let mut filters = s.filters.write();
        let target = if req.whitelist {
            &mut filters.allowlists
        } else {
            &mut filters.blocklists
        };
        let Some(l) = target.iter_mut().find(|l| l.url == req.url) else {
            return Err(ApiError::not_found("no filter with that url"));
        };

        let url_changed = l.url != req.data.url;
        l.name = req.data.name.clone();
        l.url = req.data.url.clone();
        l.enabled = req.data.enabled;

        url_changed.then_some(l.id)
    };

    if let Some(id) = changed_url
        && let Ok(text) = s.fetcher.fetch(req.data.url.clone()).await
    {
        let mut filters = s.filters.write();
        let _ = filters.apply_fetched(&s.paths, id, text);
    }

    s.save_filters().map_err(ApiError::internal)
}

/// The `/control/filtering/refresh` request.
#[derive(Deserialize)]
pub struct RefreshReq {
    /// Whether to refresh allowlists instead of blocklists.
    #[serde(default)]
    pub whitelist: bool,
}

/// `POST /control/filtering/refresh`
pub async fn refresh(
    State(s): State<Shared>,
    Json(_req): Json<RefreshReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let ids = s.filters.read().enabled_ids();

    let mut updated = 0;
    for id in ids {
        let Some(url) = s.filters.read().url_of(id) else {
            continue;
        };
        if let Ok(text) = s.fetcher.fetch(url).await {
            let mut filters = s.filters.write();
            if filters
                .apply_fetched(&s.paths, id, text)
                .is_ok_and(sift_filter::lists::Fetched::changed)
            {
                updated += 1;
            }
        }
    }

    // Nothing to write and nothing to rebuild when every list came back the
    // same, which is what upstream's `refreshFiltersIntl` decides on the same
    // count before it calls `EnableFilters`.
    if updated > 0 {
        s.save_filters().map_err(ApiError::internal)?;
    }

    Ok(Json(json!({ "updated": updated })))
}

/// The `/control/filtering/set_rules` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct SetRulesReq {
    /// The user's own rules, one per entry.
    pub rules: Vec<String>,
}

/// `POST /control/filtering/set_rules`
pub async fn set_rules(State(s): State<Shared>, Json(req): Json<SetRulesReq>) -> ApiResult<()> {
    s.filters.write().user_rules = req.rules;

    s.save_filters().map_err(ApiError::internal)
}

/// The `/control/filtering/check_host` query parameters.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CheckHostReq {
    /// The host to check.
    pub name: String,
    /// The query type to check as.
    #[serde(default)]
    pub qtype: Option<String>,
    /// The client to check as.
    #[serde(default)]
    pub client: Option<String>,
}

/// A matched rule as the API reports it.
#[derive(Serialize)]
pub struct CheckHostRule {
    /// The rule's text.
    pub text: String,
    /// The list it came from.
    pub filter_list_id: i64,
}

/// The `/control/filtering/check_host` response.
#[derive(Serialize)]
pub struct CheckHostResp {
    /// Why the host was filtered, allowed or rewritten.
    pub reason: String,
    /// The winning rule's text.
    pub rule: String,
    /// Every matching rule.
    pub rules: Vec<CheckHostRule>,
    /// The blocked service's name.
    pub service_name: String,
    /// The canonical name a rewrite produced.
    pub cname: String,
    /// Addresses a rewrite produced.
    pub ip_addrs: Option<Vec<String>>,
    /// The winning rule's list.
    pub filter_id: i64,
}

/// `GET /control/filtering/check_host`
pub async fn check_host(
    State(s): State<Shared>,
    Query(req): Query<CheckHostReq>,
) -> Json<CheckHostResp> {
    let host = sift_core::name::normalize(&req.name).into_owned();
    let qtype = req
        .qtype
        .as_deref()
        .and_then(sift_filter::rule::rr_type_from_str)
        .unwrap_or(1);

    let engine = s.resolver.engine();
    let m = engine.match_request(&sift_filter::engine::Request {
        hostname: &host,
        qtype,
        client_ip: req.client.as_deref().and_then(|c| c.parse().ok()),
        client_name: req.client.as_deref(),
        client_tags: &[],
    });

    let rules: Vec<CheckHostRule> = m
        .rules
        .iter()
        .map(|r| CheckHostRule {
            text: r.text.clone(),
            filter_list_id: r.list_id,
        })
        .collect();

    let (rule, filter_id) = m
        .rules
        .first()
        .map(|r| (r.text.clone(), r.list_id))
        .unwrap_or_default();

    Json(CheckHostResp {
        reason: m.reason.as_str().to_string(),
        rule,
        rules,
        service_name: String::new(),
        cname: String::new(),
        ip_addrs: None,
        filter_id,
    })
}

/// A rewrite as the API reports it.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RewriteJson {
    /// The domain pattern.
    pub domain: String,
    /// The answer.
    pub answer: String,
    /// Whether the rewrite is active.
    ///
    /// Absent in requests, where a new rewrite is always enabled; always
    /// present in responses, as upstream sends it.
    #[serde(default = "default_true", skip_serializing_if = "is_never")]
    pub enabled: bool,
}

/// The default for a rewrite's `enabled` flag in a request body.
fn default_true() -> bool {
    true
}

/// Never skips a field; the flag is always serialised.
fn is_never(_: &bool) -> bool {
    false
}

/// `GET /control/rewrite/list`
pub async fn rewrite_list(State(s): State<Shared>) -> Json<Vec<RewriteJson>> {
    let cfg = s.config.read();

    Json(
        cfg.filtering
            .rewrites
            .iter()
            .filter(|r| r.enabled)
            .map(|r| RewriteJson {
                domain: r.domain.clone(),
                answer: r.answer.clone(),
                enabled: r.enabled,
            })
            .collect(),
    )
}

/// `POST /control/rewrite/add`
pub async fn rewrite_add(State(s): State<Shared>, Json(req): Json<RewriteJson>) -> ApiResult<()> {
    if req.domain.trim().is_empty() || req.answer.trim().is_empty() {
        return Err(ApiError::bad_request("both domain and answer are required"));
    }

    s.config.write().filtering.rewrites.push(Rewrite {
        domain: req.domain,
        answer: req.answer,
        enabled: req.enabled,
    });

    s.save_config().map_err(ApiError::internal)
}

/// `POST /control/rewrite/delete`
pub async fn rewrite_delete(
    State(s): State<Shared>,
    Json(req): Json<RewriteJson>,
) -> ApiResult<()> {
    s.config
        .write()
        .filtering
        .rewrites
        .retain(|r| !(r.domain == req.domain && r.answer == req.answer));

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/rewrite/update` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct RewriteUpdateReq {
    /// The rewrite to replace.
    pub target: RewriteJson,
    /// What to replace it with.
    pub update: RewriteJson,
}

/// `PUT /control/rewrite/update`
pub async fn rewrite_update(
    State(s): State<Shared>,
    Json(req): Json<RewriteUpdateReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let Some(r) = cfg
            .filtering
            .rewrites
            .iter_mut()
            .find(|r| r.domain == req.target.domain && r.answer == req.target.answer)
        else {
            return Err(ApiError::not_found("no such rewrite"));
        };

        r.domain = req.update.domain.clone();
        r.answer = req.update.answer.clone();
    }

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/rewrite/settings`
pub async fn rewrite_settings(State(s): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({ "enabled": s.config.read().filtering.rewrites_enabled }))
}

/// The `/control/rewrite/settings/update` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct EnabledReq {
    /// Whether the feature is on.
    pub enabled: bool,
}

/// `PUT /control/rewrite/settings/update`
pub async fn rewrite_settings_update(
    State(s): State<Shared>,
    Json(req): Json<EnabledReq>,
) -> ApiResult<()> {
    s.config.write().filtering.rewrites_enabled = req.enabled;

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/safebrowsing/status` and `/control/parental/status`
///
/// Always off.  This build ships neither checker -- see the safe browsing and
/// parental control section of TASK.md -- and echoing whatever the config file
/// happens to hold would tell the interface a lookup is running when none is,
/// which is the same trap `dhcp_status` avoids.
pub async fn hashprefix_status() -> Json<serde_json::Value> {
    Json(json!({ "enabled": false }))
}

/// The safe-search settings, as the API exchanges them.
///
/// Every field defaults, because Go's `encoding/json` leaves a missing bool
/// `false` rather than failing: a client that sends only the flags it wants
/// on gets 200 from upstream, and got 422 here.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SafeSearchJson {
    /// Whether safe search is enforced.
    pub enabled: bool,
    /// Enforce on Bing.
    pub bing: bool,
    /// Enforce on DuckDuckGo.
    pub duckduckgo: bool,
    /// Enforce on Ecosia.
    pub ecosia: bool,
    /// Enforce on Google.
    pub google: bool,
    /// Enforce on Pixabay.
    pub pixabay: bool,
    /// Enforce on Yandex.
    pub yandex: bool,
    /// Enforce on YouTube.
    pub youtube: bool,
}

/// `GET /control/safesearch/status` and `/settings`
pub async fn safesearch_status(State(s): State<Shared>) -> Json<SafeSearchJson> {
    let c = s.config.read().filtering.safe_search.clone();

    Json(SafeSearchJson {
        enabled: c.enabled,
        bing: c.bing,
        duckduckgo: c.duckduckgo,
        ecosia: c.ecosia,
        google: c.google,
        pixabay: c.pixabay,
        yandex: c.yandex,
        youtube: c.youtube,
    })
}

/// `PUT /control/safesearch/settings`
pub async fn safesearch_settings(
    State(s): State<Shared>,
    Json(req): Json<SafeSearchJson>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let c = &mut cfg.filtering.safe_search;
        c.enabled = req.enabled;
        c.bing = req.bing;
        c.duckduckgo = req.duckduckgo;
        c.ecosia = req.ecosia;
        c.google = req.google;
        c.pixabay = req.pixabay;
        c.yandex = req.yandex;
        c.youtube = req.youtube;
    }

    s.save_config().map_err(ApiError::internal)
}

/// `POST /control/safesearch/enable` and `/disable`
pub async fn safesearch_set(s: Shared, enabled: bool) -> ApiResult<()> {
    s.config.write().filtering.safe_search.enabled = enabled;

    s.save_config().map_err(ApiError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_lists_render_as_null() {
        assert!(or_null(Vec::<u8>::new()).is_none());
        assert_eq!(or_null(vec![1u8]), Some(vec![1u8]));
    }
}

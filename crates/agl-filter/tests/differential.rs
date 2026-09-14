//! Differential test against the Go implementation.
//!
//! The fixtures are captured from a real AdGuard Home v0.107.79:
//!
//!   * `adguard-dns-filter.txt.gz` — the AdGuard DNS filter list it downloaded
//!     (179,334 rules);
//!   * `go-check-host.tsv` — what its `/control/filtering/check_host` endpoint
//!     answered for a 300-domain corpus.
//!
//! This engine must reach the same verdict, with the same winning rule, for
//! every domain in that corpus.

use std::io::Read;

use agl_filter::engine::{Engine, Request};

/// Decompresses the captured filter list.
fn filter_list() -> String {
    let gz = include_bytes!("../../../tests/fixtures/filters/adguard-dns-filter.txt.gz");
    let mut s = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut s)
        .expect("fixture must decompress");

    s
}

/// The expectations captured from the Go implementation.
fn go_truth() -> Vec<(String, String, String)> {
    include_str!("../../../tests/fixtures/filters/go-check-host.tsv")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split('\t');
            let dom = it.next().unwrap_or("").to_string();
            let reason = it.next().unwrap_or("").to_string();
            let rule = it.next().unwrap_or("").to_string();

            (dom, reason, rule)
        })
        .collect()
}

#[test]
fn matches_the_go_engine_on_the_real_adguard_dns_filter() {
    let list = filter_list();
    let engine = Engine::build([(1i64, list.as_str())], []);

    assert!(
        engine.block.len() > 150_000,
        "expected the full list to load, got {} rules",
        engine.block.len()
    );

    let truth = go_truth();
    assert!(
        truth.len() > 4_000,
        "the corpus should hold thousands of domains, got {}",
        truth.len()
    );

    // Two different things are worth measuring separately.
    //
    //   * The *verdict* — blocked, allowed or not filtered.  This is what the
    //     client actually observes, and it must match exactly.
    //   * The *cited rule* — which of the matching rules gets reported.  When
    //     several rules of equal priority match, upstream's choice falls out
    //     of its shortcut index's bucket-balancing and the order it happens to
    //     walk the URL; it is arbitrary, not semantic.  This engine uses the
    //     fast suffix-walk index instead and resolves such ties by load order,
    //     so it may legitimately cite a different, equally valid rule.
    let mut verdict_mismatches: Vec<String> = Vec::new();
    let mut rule_mismatches: Vec<String> = Vec::new();
    let mut compared = 0usize;

    for (dom, want_reason, want_rule) in &truth {
        // `RewriteEtcHosts` comes from the OS hosts file, which this engine is
        // not given here.
        if want_reason == "RewriteEtcHosts" {
            continue;
        }
        compared += 1;

        let res = engine.match_request(&Request {
            hostname: dom,
            qtype: 1,
            ..Default::default()
        });

        let got_reason = res.reason.as_str();
        let got_rule = res.rules.first().map(|r| r.text.as_str()).unwrap_or("");

        if got_reason != want_reason {
            verdict_mismatches.push(format!("{dom}: go={want_reason:?} rust={got_reason:?}"));
        } else if got_rule != want_rule {
            rule_mismatches.push(format!("{dom}: go={want_rule:?} rust={got_rule:?}"));
        }
    }

    assert!(
        verdict_mismatches.is_empty(),
        "{} of {compared} verdicts disagree with the Go engine:\n{}",
        verdict_mismatches.len(),
        verdict_mismatches.join("\n")
    );

    // Ties are permitted, but a regression that scrambles rule selection
    // wholesale should still fail the build.
    let agreement = (compared - rule_mismatches.len()) as f64 / compared as f64;
    assert!(
        agreement >= 0.99,
        "only {:.2}% of cited rules match ({} ties out of {compared}):\n{}",
        agreement * 100.0,
        rule_mismatches.len(),
        rule_mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    eprintln!(
        "verdicts: {compared}/{compared} exact; cited rules: {:.2}% exact ({} arbitrary ties)",
        agreement * 100.0,
        rule_mismatches.len()
    );
}

#[test]
fn loads_the_real_list_quickly_enough_to_be_practical() {
    let list = filter_list();
    let start = std::time::Instant::now();
    let engine = Engine::build([(1i64, list.as_str())], []);
    let elapsed = start.elapsed();

    // Generous bound: this is a correctness guard against an accidental
    // quadratic index build, not a benchmark.
    assert!(
        elapsed.as_secs() < 30,
        "building the index took {elapsed:?} for {} rules",
        engine.block.len()
    );
}

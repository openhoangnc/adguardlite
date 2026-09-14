//! Round-trip fidelity against real query log lines.
//!
//! The fixture holds one line per distinct entry shape observed in a running
//! AdGuard Home v0.107.79 — blocked, allowlisted, cached, upstream-answered,
//! DNSSEC-authenticated, and every query type it was asked for.  Re-encoding
//! each must reproduce the original byte for byte, or an existing
//! `querylog.json` would change shape the moment this build appends to it.

use agl_querylog::entry::Entry;

/// The captured lines.
const GOLDEN: &str = include_str!("../../../tests/fixtures/querylog/go-entries.jsonl");

fn lines() -> Vec<&'static str> {
    GOLDEN
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn every_real_line_round_trips_byte_for_byte() {
    let lines = lines();
    assert!(
        lines.len() >= 40,
        "expected a broad fixture, got {}",
        lines.len()
    );

    let mut failures = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        match Entry::from_line(line) {
            Ok(e) => {
                let out = e.to_line().expect("re-encoding must succeed");
                if out.trim_end() != *line {
                    failures.push(format!(
                        "line {}:\n  in : {line}\n  out: {}",
                        i + 1,
                        out.trim_end()
                    ));
                }
            }
            Err(e) => failures.push(format!("line {}: parse failed: {e}\n  {line}", i + 1)),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} lines did not round-trip:\n{}",
        failures.len(),
        lines.len(),
        failures.join("\n")
    );
}

#[test]
fn the_fixture_covers_the_shapes_that_matter() {
    let all = GOLDEN;

    // Each of these appears in at least one captured line; losing coverage of
    // one would make the round-trip test weaker without failing it.
    for marker in [
        r#""Cached":true"#,
        r#""AD":true"#,
        r#""Upstream":"#,
        r#""IsFiltered":true"#,
        r#""Result":{}"#,
        r#""Reason":1"#,
        r#""Reason":3"#,
    ] {
        assert!(all.contains(marker), "fixture lost coverage of {marker}");
    }
}

#[test]
fn parsed_entries_expose_the_fields_the_api_needs() {
    let blocked = lines()
        .into_iter()
        .find_map(|l| {
            let e = Entry::from_line(l).ok()?;
            e.result.is_filtered.then_some(e)
        })
        .expect("the fixture should hold a blocked entry");

    assert!(!blocked.question_host.is_empty());
    assert!(!blocked.question_type.is_empty());
    assert_eq!(blocked.question_class, "IN");
    assert!(!blocked.result.rules.is_empty());
    assert!(blocked.elapsed > 0);
    assert!(Entry::decode_answer(blocked.answer.as_deref().unwrap_or("")).is_some());
}

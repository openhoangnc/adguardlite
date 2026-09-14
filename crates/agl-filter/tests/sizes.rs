//! Guards on the in-memory footprint of the rule types.
//!
//! A real blocklist holds ~180,000 network rules, so these structs are
//! multiplied by that: when `NetworkRule` carried its `Options` inline it was
//! 296 bytes, and the engine used more memory than the Go implementation it
//! replaces.  Boxing the modifiers and dropping the build-only fields brought
//! it to 56.  These assertions exist so that regresses loudly rather than
//! quietly.

use std::mem::size_of;

use agl_filter::rule::{HostRule, NetworkRule, Options, Pattern};

#[test]
fn a_network_rule_stays_small() {
    assert!(
        size_of::<NetworkRule>() <= 64,
        "NetworkRule grew to {} bytes; at list scale that is ~{} MB",
        size_of::<NetworkRule>(),
        size_of::<NetworkRule>() * 180_000 / 1_048_576
    );
}

#[test]
fn the_pattern_carries_no_payload_for_the_common_case() {
    assert!(
        size_of::<Pattern>() <= 16,
        "Pattern grew to {} bytes",
        size_of::<Pattern>()
    );
}

#[test]
fn modifiers_are_not_stored_inline() {
    // Options is large, which is exactly why it must live behind a pointer.
    assert!(
        size_of::<Options>() > size_of::<NetworkRule>(),
        "this test is only meaningful while Options is the larger type"
    );
    assert!(
        size_of::<Option<Box<Options>>>() == 8,
        "the modifiers must cost one pointer when absent"
    );
}

#[test]
fn a_rule_without_modifiers_allocates_no_options() {
    let Ok(agl_filter::rule::Rule::Network(n)) = agl_filter::rule::parse("||ads.example.com^", 1)
    else {
        panic!("expected a network rule");
    };

    assert!(
        n.rule.opts.is_none(),
        "a plain rule must carry no options block"
    );
}

#[test]
fn a_host_rule_stays_small() {
    assert!(
        size_of::<HostRule>() <= 96,
        "HostRule grew to {}",
        size_of::<HostRule>()
    );
}

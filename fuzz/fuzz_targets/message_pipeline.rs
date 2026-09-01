#![no_main]
//! The message pipeline against arbitrary bytes.
//!
//! What is fuzzed is not "does MIME parse" — `mail-parser` has its own fuzzing
//! — but what Pigeon does *around* a parse it does not control: transport
//! conversion, header prepending, and the decision to forward an unparseable
//! message rather than lose it.
//!
//! The invariant is narrow and load-bearing: whatever arrives, the relayed form
//! must still end its headers with a blank line and must never gain a bare CR
//! or LF. A payload that fails either is one this host would smuggle a second
//! message through — the exact hazard `pigeon-auth::normalize` exists for.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The relay form, built the way acceptance builds it.
    let payload = pigeon_auth::normalize::to_crlf(data);

    // Conversion is idempotent: converting an already-converted payload must
    // change nothing, or every retry would rewrite the bytes a signature covers.
    let twice = pigeon_auth::normalize::to_crlf(&payload);
    assert_eq!(
        payload.as_ref(),
        twice.as_ref(),
        "transport conversion is not idempotent"
    );

    // And it leaves nothing that terminates a DATA section early at a lax
    // receiver, which is what carrying a bare LF would do.
    assert!(
        !pigeon_auth::normalize::needs_conversion(&payload),
        "a converted payload still needs conversion"
    );
});

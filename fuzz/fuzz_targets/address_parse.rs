#![no_main]
//! Address validation, against arbitrary text.
//!
//! This function is a gate, not a formatter. The daemon's startup check calls
//! it to refuse a destination that would fail every delivery, and the session
//! calls it to keep malformed recipients out of routing — so what matters is
//! not that it returns something, but that everything it *accepts* is safe to
//! interpolate into a command and a trace header.
//!
//! Every property below corresponds to a real finding: control characters
//! (20a), `x@.` reaching the startup guard (28), and folding the local part
//! merging distinct mailboxes (12).

use libfuzzer_sys::fuzz_target;
use pigeon_types::Address;

fuzz_target!(|raw: &str| {
    let Ok(address) = Address::parse(raw) else {
        return;
    };

    let local = address.local();
    let domain = address.domain();

    // Nothing that ends a line or a syntactic element survives acceptance.
    for (field, value) in [("local", local), ("domain", domain)] {
        for c in value.chars() {
            assert!(
                !c.is_control(),
                "{field} of an accepted address holds a control character: {raw:?}"
            );
        }
        assert!(
            !value.contains('<') && !value.contains('>'),
            "{field} of an accepted address holds an angle bracket: {raw:?}"
        );
    }

    // A domain that cannot be resolved must not be accepted, because the
    // caller's next move is to treat it as deliverable.
    assert!(!domain.is_empty(), "empty domain accepted: {raw:?}");
    assert!(domain.contains('.'), "single-label domain accepted: {raw:?}");
    for label in domain.split('.') {
        assert!(!label.is_empty(), "empty domain label accepted: {raw:?}");
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "hyphen-edged domain label accepted: {raw:?}"
        );
    }
    assert!(!local.is_empty(), "empty local part accepted: {raw:?}");

    // The parse borrows rather than rewrites, so printing it must give back
    // exactly what was parsed. Anything else means a value is being silently
    // altered somewhere between acceptance and the wire.
    assert_eq!(
        address.to_string(),
        raw,
        "address did not round-trip through Display"
    );

    // Case folding is the domain's alone. RFC 5321 §2.4 reserves the local
    // part to the destination host, and folding it merges distinct mailboxes.
    let upper = raw.to_ascii_uppercase();
    if let Ok(other) = Address::parse(&upper) {
        assert_eq!(
            address.same_mailbox(&other),
            local == other.local(),
            "mailbox identity did not depend solely on the local part: {raw:?}"
        );
    }

    // Tag stripping stays inside the local part it was given.
    let base = address.local_without_tag();
    assert!(
        local.starts_with(base) && !base.is_empty(),
        "plus-tag stripping left {base:?}, which is not a prefix of {local:?}"
    );
});

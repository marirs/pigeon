#![no_main]
//! The SMTP command parser, against arbitrary bytes.
//!
//! Not just "does not panic". The parser hands borrowed slices straight into
//! the `Received:` header and into outbound `RCPT TO:` commands, so a path or
//! greeting carrying a bare CR is a header-injection primitive. That property
//! is asserted here rather than assumed, because it is the one an example-based
//! test cannot cover exhaustively.

use libfuzzer_sys::fuzz_target;
use pigeon_smtp::command::{Command, parse};

/// Nothing the parser returns as a borrowed argument may carry a byte that
/// ends a line or a syntactic element downstream.
fn assert_no_injection(field: &str, value: &str) {
    for b in value.bytes() {
        assert!(
            b != b'\r' && b != b'\n' && b != 0,
            "{field} carried {b:#04x}, which breaks framing downstream: {value:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let first = parse(data);

    // Deterministic. A parser whose answer depends on anything but its input
    // cannot be reasoned about from a transcript.
    let second = parse(data);
    assert_eq!(first, second, "parse is not deterministic for {data:?}");

    let Ok(command) = first else { return };

    match command {
        Command::Ehlo(name) | Command::Helo(name) => {
            assert_no_injection("greeting", name);
            // The session rejects an empty greeting; the parser must not
            // present one as valid in the first place.
            assert!(!name.is_empty(), "empty greeting accepted from {data:?}");
        }
        Command::Mail { path, params } | Command::Rcpt { path, params } => {
            // The null sender is an empty path and is valid; anything else
            // reaches `Address::parse` and then the wire.
            assert_no_injection("path", path);
            assert_no_injection("params", params);
        }
        Command::Auth {
            mechanism,
            initial,
        } => {
            // Both reach a reply or a credential check, so both reach somewhere
            // an injected CRLF would be two lines instead of one.
            assert_no_injection("mechanism", mechanism);
            if let Some(initial) = initial {
                assert_no_injection("initial response", initial);
            }
        }
        Command::Data
        | Command::Rset
        | Command::Noop
        | Command::Quit
        | Command::StartTls => {}
    }
});

//! Transport conversion of a received payload (`M2-DESIGN.md` §2, R-1).
//!
//! SMTP lines end with CRLF. A payload containing a bare CR or a bare LF is
//! nonconforming, and Pigeon converts it — **once**, after inbound
//! authentication and before anything is added, signed or stored. RFC 6376 §5.3
//! puts transport conversion before signing, which is where this sits.
//!
//! # Why convert rather than preserve
//!
//! Pigeon cannot be smuggled *into*: `DataReader` ends a message on `CRLF.CRLF`
//! and nothing else. What it can do is *carry* the primitive. A body containing
//! `LF . LF` relayed verbatim to a receiver whose parser is lax terminates that
//! receiver's DATA early and injects everything after it as a second message —
//! from Pigeon's IP, with Pigeon's reputation. A forwarder is the ideal
//! amplifier for that: it is precisely a machine that takes bytes from a
//! stranger and re-emits them from a trusted host.
//!
//! The header block is not exempt, and is the more interesting half. A bare CR
//! inside a header is a line break to some parsers and an ordinary octet to
//! others, which makes one set of bytes two different header sets depending on
//! who reads them.
//!
//! # What it costs
//!
//! A signature computed over the nonconforming bytes will not verify at the
//! receiver. That is recorded honestly: verification ran *before* this, against
//! what actually arrived, and the ARC set says so.

use std::borrow::Cow;

/// Convert bare CR and bare LF to CRLF.
///
/// Returns the payload unchanged, without copying, when it is already
/// conforming — which is almost always, and is worth not paying for.
pub fn to_crlf(payload: &[u8]) -> Cow<'_, [u8]> {
    if !needs_conversion(payload) {
        return Cow::Borrowed(payload);
    }

    // Capacity for the common shape of a nonconforming payload: LF-only line
    // endings, which grow by one byte per line.
    let mut out = Vec::with_capacity(payload.len() + payload.len() / 32 + 16);
    let mut i = 0;

    while i < payload.len() {
        match payload[i] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                // A CR that already has its LF consumes both; a bare one
                // consumes only itself, and the byte after it is whatever it
                // was — including another CR, which becomes its own line
                // ending on the next pass.
                i += if payload.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
            }
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    Cow::Owned(out)
}

/// Whether [`to_crlf`] would change anything.
///
/// Separate from the conversion so the caller can record that a message was
/// nonconforming without holding two buffers to compare.
pub fn needs_conversion(payload: &[u8]) -> bool {
    for (i, &b) in payload.iter().enumerate() {
        match b {
            // A bare LF: one not preceded by CR. Looking *backwards* is what
            // lets this be a plain scan — the LF of a well-formed pair is
            // recognised where it stands, so nothing has to be skipped ahead
            // of. A lone LF at index 0 has nothing before it and is bare.
            //
            // An earlier version advanced past the LF from the CR arm as well.
            // It was redundant, and no mutation of it could be made to fail a
            // test, which is what exposed it: the guard here already excludes
            // every LF that a skip would have stepped over.
            b'\n' if i == 0 || payload[i - 1] != b'\r' => return true,
            b'\r' if payload.get(i + 1) != Some(&b'\n') => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(input: &[u8]) -> Vec<u8> {
        to_crlf(input).into_owned()
    }

    #[test]
    fn a_conforming_payload_is_untouched_and_uncopied() {
        let input = b"Subject: hi\r\n\r\nbody\r\n";
        assert!(!needs_conversion(input));
        assert!(
            matches!(to_crlf(input), Cow::Borrowed(_)),
            "a conforming payload was copied"
        );
    }

    #[test]
    fn bare_lf_becomes_crlf() {
        assert_eq!(conv(b"a\nb\n"), b"a\r\nb\r\n");
    }

    #[test]
    fn bare_cr_becomes_crlf() {
        // Old-Mac line endings, and also what a truncated CRLF looks like.
        assert_eq!(conv(b"a\rb\r"), b"a\r\nb\r\n");
    }

    #[test]
    fn existing_crlf_is_not_doubled() {
        // The mistake that would corrupt every conforming message: treating the
        // CR and the LF of a pair as two separate line endings.
        assert_eq!(conv(b"a\r\nb\n"), b"a\r\nb\r\n");
    }

    #[test]
    fn headers_are_converted_too() {
        // The half that a body-only normaliser would leave, and the more
        // interesting one: a bare CR in a header is a line break to some
        // parsers and an octet to others.
        let input = b"To: a@example.com\rSubject: injected\r\n\r\nbody\r\n";
        assert_eq!(
            conv(input),
            b"To: a@example.com\r\nSubject: injected\r\n\r\nbody\r\n"
        );
    }

    #[test]
    fn the_smuggling_sequence_does_not_survive() {
        // The reason this module exists. `LF . LF` relayed verbatim ends the
        // DATA of a lax receiver early; after conversion the only line ending
        // is CRLF, and dot-stuffing on the way out then applies to it.
        let out = conv(b"body\n.\nSMTP smuggled\r\n");
        assert_eq!(out, b"body\r\n.\r\nSMTP smuggled\r\n");
        assert!(
            !out.windows(3).any(|w| w == b"\n.\n"),
            "the bare-LF dot sequence survived"
        );
    }

    #[test]
    fn a_lone_cr_before_a_cr_lf_pair_is_its_own_line_ending() {
        assert_eq!(conv(b"a\r\r\nb"), b"a\r\n\r\nb");
    }

    #[test]
    fn a_trailing_bare_lf_is_converted() {
        assert_eq!(conv(b"a\n"), b"a\r\n");
    }

    #[test]
    fn a_leading_bare_lf_is_converted() {
        // Index 0 has nothing before it, which is the case a backwards-looking
        // check gets wrong if it reads past the start.
        assert_eq!(conv(b"\na"), b"\r\na");
    }

    #[test]
    fn conversion_is_idempotent() {
        // Running it twice must not differ from running it once, or a retry
        // that re-derived the relay form would produce a different message.
        for input in [
            &b"a\nb"[..],
            b"a\rb",
            b"a\r\nb",
            b"\r\r\r",
            b"\n\n",
            b"a\r\r\nb",
            b"",
        ] {
            let once = conv(input);
            let twice = conv(&once);
            assert_eq!(once, twice, "not idempotent for {input:?}");
            assert!(!needs_conversion(&once), "still nonconforming: {once:?}");
        }
    }

    /// An independent answer to "is this conforming?".
    ///
    /// Deliberately not `needs_conversion`, and deliberately not written the
    /// same way: it splits on CRLF first and then looks for a stray CR or LF in
    /// what is left, where the real one walks the bytes. Comparing an
    /// implementation against itself is how the first version of the agreement
    /// test below passed with a broken detector — `to_crlf` short-circuits on
    /// `needs_conversion`, so a detector that under-reports also suppresses the
    /// conversion, and the two agree by construction while both are wrong.
    fn conforming_oracle(payload: &[u8]) -> bool {
        let mut rest = payload;
        while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
            let (line, after) = rest.split_at(pos);
            if line.contains(&b'\r') || line.contains(&b'\n') {
                return false;
            }
            rest = &after[2..];
        }
        !rest.contains(&b'\r') && !rest.contains(&b'\n')
    }

    #[test]
    fn the_detector_matches_an_independent_oracle() {
        for input in [
            &b""[..],
            b"\r",
            b"a\r",
            b"\n",
            b"a\n",
            b"\r\n",
            b"a\r\nb\r\n",
            b"a\rb",
            b"a\n\rb",
            b"\r\n\r\n",
            b"\r\r",
            b"\r\r\n",
            b"\n\r\n",
            b"plain text",
        ] {
            assert_eq!(
                needs_conversion(input),
                !conforming_oracle(input),
                "detector disagrees with the oracle for {input:?}"
            );
        }
    }

    #[test]
    fn a_payload_ending_in_a_bare_cr_is_converted() {
        // The case a "is the next byte an LF?" check gets wrong when there is
        // no next byte. Found by mutation: every other test passed with it
        // broken, because `to_crlf` short-circuits on the same detector.
        assert!(needs_conversion(b"a\r"));
        assert_eq!(conv(b"a\r"), b"a\r\n");
    }

    #[test]
    fn the_detector_and_the_converter_agree() {
        // If `needs_conversion` says no and `to_crlf` would have changed
        // something, the payload is signed in one form and sent in another.
        for input in [
            &b""[..],
            b"\r\n",
            b"\n",
            b"\r",
            b"a\r\nb\r\n",
            b"a\rb",
            b"a\n\rb",
            b"\r\n\r\n",
            b"\r\r",
        ] {
            let converted = to_crlf(input);
            assert_eq!(
                needs_conversion(input),
                converted.as_ref() != input,
                "disagreement for {input:?} -> {:?}",
                converted.as_ref()
            );
        }
    }

    #[test]
    fn nothing_but_line_endings_changes() {
        let input = b"Subject: =?utf-8?B?8J+Qpg==?=\nbody with . dots and \x00 nulls\n";
        let out = conv(input);
        let strip = |v: &[u8]| -> Vec<u8> {
            v.iter()
                .copied()
                .filter(|&b| b != b'\r' && b != b'\n')
                .collect()
        };
        assert_eq!(strip(&out), strip(input), "a non-line-ending byte changed");
    }
}

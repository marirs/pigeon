#![no_main]
//! Command-line framing, fed in adversarial chunk boundaries.
//!
//! Same differential property as the body reader, and the same reason: a
//! pipelining client writes a whole transaction in one packet, and a slow one
//! delivers a single CRLF across two. Both must frame identically.

use libfuzzer_sys::fuzz_target;
use pigeon_smtp::codec::LineReader;

const MAX: usize = 4096;

/// Drain every line the reader can produce from `data`, split at `splits`.
///
/// Returns the lines and whether framing reported an error, which is itself
/// part of the result: an over-long line must be reported at the same point
/// however the bytes arrived.
fn frame(data: &[u8], splits: &[usize]) -> (Vec<Vec<u8>>, bool) {
    let mut reader = LineReader::new(MAX);
    let mut lines = Vec::new();
    let mut start = 0;
    let mut boundaries: Vec<usize> = Vec::new();

    for &raw in splits {
        if start >= data.len() {
            break;
        }
        let end = start + (raw % (data.len() - start + 1));
        boundaries.push(end);
        start = end;
    }
    boundaries.push(data.len());

    let mut cursor = 0;
    for end in boundaries {
        reader.feed(&data[cursor..end]);
        cursor = end;
        loop {
            let mut line = Vec::new();
            match reader.take_line(&mut line) {
                Ok(true) => lines.push(line),
                Ok(false) => break,
                Err(_) => return (lines, true),
            }
        }
    }
    (lines, false)
}

fuzz_target!(|input: (Vec<u8>, Vec<usize>)| {
    let (data, splits) = input;
    if data.len() > MAX * 8 {
        return;
    }

    let whole = frame(&data, &[]);
    let split = frame(&data, &splits);
    assert_eq!(
        whole, split,
        "chunk boundaries changed framing for {data:?} split at {splits:?}"
    );

    // A framed line is what `parse` is handed, and the framer splits on LF and
    // keeps it — so exactly one LF, at the very end. An interior one would mean
    // two commands delivered as one, which is how a parser disagreement becomes
    // a smuggled command.
    //
    // The first version of this assertion said "no LF at all", which is what
    // the module's own docstring implied ("CRLF-delimited") and not what the
    // code does. The fuzzer found it in seconds. Worth keeping the note: the
    // assertion was wrong, the code was right, and it took a disagreement
    // between them to notice the docstring had never matched either.
    for line in &whole.0 {
        assert_eq!(
            line.iter().filter(|&&b| b == b'\n').count(),
            1,
            "a framed line did not hold exactly one LF: {line:?}"
        );
        assert!(
            line.ends_with(b"\n"),
            "a framed line did not end at its terminator: {line:?}"
        );
        assert!(
            line.len() <= MAX,
            "a framed line of {} bytes exceeded the {MAX}-byte cap",
            line.len()
        );
    }
});

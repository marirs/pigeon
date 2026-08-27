#![no_main]
//! Message-body reading, fed in adversarial chunk boundaries.
//!
//! The bug this exists for is a terminator split across two reads. A real
//! client cannot be made to produce that on demand, and every example-based
//! test picks the splits its author thought of — so the split points come from
//! the fuzzer, and the property is differential: however the bytes are
//! divided, the reader must produce the same body it produces from one feed.

use libfuzzer_sys::fuzz_target;
use pigeon_smtp::codec::{DataReader, DataStatus};

const MAX: usize = 64 * 1024;

/// Feed `data` split at `splits`, returning the reader's final view.
fn read_in_chunks(data: &[u8], splits: &[usize]) -> (Vec<u8>, bool, bool) {
    let mut reader = DataReader::new(MAX);
    let mut start = 0;

    for &raw in splits {
        if start >= data.len() {
            break;
        }
        // Map the fuzzer's number onto a real boundary at or after `start`.
        let end = start + (raw % (data.len() - start + 1));
        let (_, status) = reader.feed(&data[start..end]);
        start = end;
        if status == DataStatus::Complete {
            return (reader.body().to_vec(), true, reader.is_too_large());
        }
    }

    let (_, status) = reader.feed(&data[start..]);
    (
        reader.body().to_vec(),
        status == DataStatus::Complete,
        reader.is_too_large(),
    )
}

fuzz_target!(|input: (Vec<u8>, Vec<usize>)| {
    let (data, splits) = input;
    if data.len() > MAX {
        return;
    }

    let whole = read_in_chunks(&data, &[]);
    let split = read_in_chunks(&data, &splits);

    assert_eq!(
        whole, split,
        "chunk boundaries changed the result for {data:?} split at {splits:?}"
    );

    // The limit is a promise made to the rest of the process: a body is bounded
    // memory. `TooLarge` keeps scanning to stay in sync with the client, so the
    // buffer must still not grow past the cap.
    let (body, _complete, too_large) = whole;
    assert!(
        body.len() <= MAX,
        "body of {} bytes exceeded the {MAX}-byte cap (too_large={too_large})",
        body.len()
    );
});

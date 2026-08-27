#![no_main]
//! The delivery client, against a server that says anything at all.
//!
//! `pigeon-testkit` scripts a peer that misbehaves in ways somebody thought of.
//! This is the other half: the replies come from the fuzzer, so the client
//! meets continuation lines that never end, codes that are not numbers, replies
//! split mid-digit, and bytes that are not UTF-8 — while it is mid-transaction
//! and has already handed over a body.
//!
//! Time is paused, so the 30-minute delivery budget and every phase timeout
//! resolve instantly rather than being skipped. A client that would hang
//! forever in production returns `Timeout` here instead of stalling the fuzzer.

use libfuzzer_sys::fuzz_target;
use pigeon_smtp::{Envelope, deliver};

fuzz_target!(|replies: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("runtime");

    runtime.block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(4096);

        // Everything the fuzzer produced, then silence. The client must reach
        // a decision from a truncated conversation rather than waiting on one
        // that will never continue.
        let script = replies.to_vec();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = server_side.write_all(&script).await;
            let _ = server_side.shutdown().await;
            // Held open so the client's writes do not fail early with a broken
            // pipe, which would cut the transaction short of the reply parsing
            // this target exists to exercise.
            std::future::pending::<()>().await;
        });

        let envelope = Envelope {
            sender: "sender@example.com".into(),
            recipients: vec!["recipient@example.net".into()],
        };

        // Any outcome is acceptable; hanging or panicking is not. A permanent
        // verdict is the dangerous one — it bounces mail with no copy kept —
        // so it must only ever come from a reply the client actually read.
        if let Ok(accepted) = deliver(
            client_side,
            "fuzz.test",
            &envelope,
            &[b"Subject: t\r\n\r\nbody\r\n"],
        )
        .await
        {
            assert!(
                !accepted.message.contains('\r') && !accepted.message.contains('\n'),
                "the accepted-message text carried a line break into the log: {:?}",
                accepted.message
            );
        }
    });
});

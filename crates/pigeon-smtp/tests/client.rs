//! The delivery client against servers that misbehave.
//!
//! Pigeon's own server is well-behaved, so testing the client only against it
//! proves the happy path and nothing else. Real receiving servers reject
//! `EHLO`, answer 4xx under load, hang up mid-reply, and occasionally emit
//! nonsense. What the client does with each decides whether a message is
//! retried, bounced, or lost — and only the first of those is recoverable.

use std::time::Duration;

use pigeon_smtp::{ClientError, Envelope};
use pigeon_testkit::Peer;
use tokio::net::TcpStream;

fn envelope() -> Envelope {
    Envelope {
        sender: "sender@example.org".into(),
        recipients: vec!["someone@example.net".into()],
    }
}

async fn deliver_to(peer: Peer) -> Result<pigeon_smtp::Accepted, ClientError> {
    let (addr, _t) = peer.spawn().await;
    let stream = TcpStream::connect(addr).await.unwrap();
    pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope(),
        &[b"Subject: hi\r\n\r\nBody\r\n".as_slice()],
        None,
    )
    .await
}

#[tokio::test]
async fn accepts_a_well_behaved_server() {
    let (addr, transcript) = Peer::accepting().spawn().await;
    let stream = TcpStream::connect(addr).await.unwrap();

    let accepted = pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope(),
        &[b"hi\r\n".as_slice()],
        None,
    )
    .await
    .expect("should deliver");

    assert_eq!(accepted.code, 250);
    // The remote's text is kept because it usually carries their queue id,
    // which is the only handle you have when asking them what happened.
    assert!(
        accepted.message.contains("TESTPEER"),
        "lost remote text: {}",
        accepted.message
    );

    assert!(transcript.saw("EHLO client.test"));
    assert!(transcript.saw("MAIL FROM:<sender@example.org>"));
    assert!(transcript.saw("RCPT TO:<someone@example.net>"));
    assert!(transcript.saw("QUIT"));
}

#[tokio::test]
async fn falls_back_to_helo_when_ehlo_is_refused() {
    // Rare, but it happens, and losing ESMTP costs far less than losing mail.
    let (addr, transcript) = Peer::new()
        .send("220 old.invalid ESMTP")
        .read_line() // EHLO
        .send("500 Command not recognized")
        .read_line() // HELO
        .send("250 old.invalid")
        .read_line() // MAIL
        .send("250 Ok")
        .read_line() // RCPT
        .send("250 Ok")
        .read_line() // DATA
        .send("354 Go ahead")
        .read_body()
        .send("250 Ok")
        .read_line()
        .send("221 Bye")
        .close()
        .spawn()
        .await;

    let stream = TcpStream::connect(addr).await.unwrap();
    pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope(),
        &[b"hi\r\n".as_slice()],
        None,
    )
    .await
    .expect("should fall back to HELO");

    assert!(transcript.saw("EHLO"), "should try EHLO first");
    assert!(transcript.saw("HELO client.test"), "should retry with HELO");
}

#[tokio::test]
async fn rejected_recipient_is_permanent() {
    let err = deliver_to(
        Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line()
            .send("250 test.invalid")
            .read_line()
            .send("250 Ok")
            .read_line() // RCPT
            .send("550 No such user here")
            .close(),
    )
    .await
    .expect_err("should fail");

    // Bounce rather than retry: the mailbox will not exist tomorrow either.
    assert!(err.is_permanent(), "got {err}");
}

#[tokio::test]
async fn greylisting_is_transient() {
    // 451 from a greylister is the single most common temporary rejection.
    // Treating it as permanent would bounce ordinary mail on first contact.
    let err = deliver_to(
        Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line()
            .send("250 test.invalid")
            .read_line() // MAIL
            .send("451 Greylisted, try again in 300 seconds")
            .close(),
    )
    .await
    .expect_err("should fail");

    assert!(
        !err.is_permanent(),
        "greylisting must be retried, got {err}"
    );
}

#[tokio::test]
async fn refusal_at_connect_is_transient() {
    // 421 means "not now", not "never".
    let err = deliver_to(Peer::new().send("421 Service not available").close())
        .await
        .expect_err("should fail");
    assert!(!err.is_permanent(), "got {err}");
}

#[tokio::test]
async fn body_rejected_after_acceptance_is_still_classified() {
    // Content filters reject here, long after the recipient was accepted.
    let err = deliver_to(
        Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line()
            .send("250 test.invalid")
            .read_line()
            .send("250 Ok")
            .read_line()
            .send("250 Ok")
            .read_line()
            .send("354 Go ahead")
            .read_body()
            .send("552 Message rejected by content filter")
            .close(),
    )
    .await
    .expect_err("should fail");

    assert!(err.is_permanent(), "got {err}");
}

#[tokio::test]
async fn multiline_greeting_is_read_as_one_reply() {
    let (addr, transcript) = Peer::new()
        .send("220-test.invalid ESMTP")
        .send("220-This server has a long banner")
        .send("220 and it finally ends here")
        .read_line()
        .send("250 test.invalid")
        .read_line()
        .send("250 Ok")
        .read_line()
        .send("250 Ok")
        .read_line()
        .send("354 Go ahead")
        .read_body()
        .send("250 Ok")
        .read_line()
        .send("221 Bye")
        .close()
        .spawn()
        .await;

    let stream = TcpStream::connect(addr).await.unwrap();
    pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope(),
        &[b"hi\r\n".as_slice()],
        None,
    )
    .await
    .expect("multiline banner is normal");

    // Continuation lines must not be mistaken for the reply to EHLO.
    assert!(transcript.saw("EHLO"));
}

#[tokio::test]
async fn hanging_up_mid_reply_is_a_protocol_error() {
    let err = deliver_to(Peer::new().send_raw(b"220-test.invalid\r\n").close())
        .await
        .expect_err("should fail");

    assert!(matches!(err, ClientError::Protocol(_)), "got {err}");
    assert!(
        !err.is_permanent(),
        "an interrupted reply should be retried"
    );
}

#[tokio::test]
async fn garbage_does_not_panic_the_client() {
    // A multi-byte character where the status code belongs. Slicing the first
    // three bytes without checking would split it and take down the task.
    for junk in [
        "é50 not a status code\r\n".as_bytes(),
        b"\xff\xfe\xfd nonsense\r\n",
        b"ok\r\n",
        b"\r\n",
    ] {
        let err = deliver_to(Peer::new().send_raw(junk).close())
            .await
            .expect_err("should fail");
        assert!(
            matches!(err, ClientError::Protocol(_)),
            "got {err} for {junk:?}"
        );
    }
}

#[tokio::test]
async fn reply_code_changing_mid_reply_is_refused() {
    // Trusting either half of a contradictory reply would be a guess.
    let err = deliver_to(
        Peer::new()
            .send("220-test.invalid")
            .send("550 actually no")
            .close(),
    )
    .await
    .expect_err("should fail");

    assert!(matches!(err, ClientError::Protocol(_)), "got {err}");
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out_rather_than_hanging() {
    // Without a bound on the read this task would never finish: no error, no
    // retry, just a message that stops moving and a task that never ends.
    // The clock is paused, so this resolves instantly rather than in minutes.
    let err = deliver_to(Peer::new().stall(Duration::from_secs(3600)))
        .await
        .expect_err("should give up");

    assert!(matches!(err, ClientError::Timeout(_)), "got {err}");
    assert!(!err.is_permanent(), "a slow server should be retried");
}

#[tokio::test(start_paused = true)]
async fn silence_after_the_body_also_times_out() {
    let err = deliver_to(
        Peer::new()
            .send("220 test.invalid ESMTP")
            .read_line()
            .send("250 test.invalid")
            .read_line()
            .send("250 Ok")
            .read_line()
            .send("250 Ok")
            .read_line()
            .send("354 Go ahead")
            .read_body()
            .stall(Duration::from_secs(3600)),
    )
    .await
    .expect_err("should give up");

    assert!(matches!(err, ClientError::Timeout(_)), "got {err}");
}

#[tokio::test]
async fn body_arrives_dot_stuffed_and_terminated() {
    let (addr, transcript) = Peer::accepting().spawn().await;
    let stream = TcpStream::connect(addr).await.unwrap();

    let env = envelope();
    pigeon_smtp::deliver(
        stream,
        "client.test",
        &env,
        &[b".leading\r\nplain\r\n".as_slice()],
        None,
    )
    .await
    .unwrap();

    // Checked against the peer's own scan for the terminator, not against the
    // codec that produced it.
    let body = transcript
        .lines()
        .into_iter()
        .find(|l| l.contains("plain"))
        .expect("no body");
    assert_eq!(body, "..leading\r\nplain\r\n.\r\n");
}

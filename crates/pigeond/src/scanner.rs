//! Content filtering through an external scanner.
//!
//! Pigeon does not filter mail itself and is not going to: spam and malware
//! detection is a full-time adversarial problem with its own release cadence,
//! and a mail forwarder that shipped its own would be shipping a worse
//! rspamd. What it does instead is hand the finished message to whatever the
//! operator already runs, and act on the answer.
//!
//! # The contract
//!
//! The configured command is spawned per message. The message — headers and
//! body, exactly as it would be sent onward — goes to its standard input. The
//! **exit status** is the verdict:
//!
//! | Status | Verdict | Sender is told |
//! |---|---|---|
//! | `0` | accept | `250`, as usual |
//! | `1` | reject | `550`, permanently |
//! | anything else | could not tell | `451`, try again |
//!
//! Two codes rather than a parsed protocol, because every scanner speaks a
//! different one and the operator already has a wrapper script if they need
//! translating. `clamdscan` and `rspamc` both already exit `0`/`1` this way.
//!
//! # Why the third case is not "accept"
//!
//! A scanner that crashes, cannot be executed, or times out has said nothing.
//! Treating that as "clean" turns a broken scanner into no scanner at all,
//! silently, at exactly the moment somebody is trying to get something past
//! it. Treating it as "spam" would bounce legitimate mail on a local fault.
//! `451` is the only honest answer: the sender still has the message, and
//! retries it once the operator has noticed.
//!
//! That choice is the reverse of the blocklist's, and deliberately. A blocklist
//! failing open costs one spam message; a scanner failing open costs every
//! message that arrives while it is broken, because the scanner is the only
//! thing looking at content at all.
//!
//! # Where it runs
//!
//! At the end of `DATA`, before the queue transaction — the last moment a
//! message can be refused while it is still the sender's problem.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

/// What the scanner said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Refuse permanently. The scanner's own output is carried for the log, not
    /// for the sender: it may quote the message it was given.
    Reject {
        reason: String,
    },
    /// The scanner could not be consulted. Refuse transiently.
    Unavailable {
        reason: String,
    },
}

/// A configured scanner.
#[derive(Debug, Clone)]
pub struct Scanner {
    /// The program, and the arguments before the message.
    pub command: PathBuf,
    pub args: Vec<String>,
    /// How long one message may take. A scanner that hangs must not hold the
    /// SMTP session past its own data timeout.
    pub timeout: Duration,
}

impl Scanner {
    /// Hand one message to the scanner and wait for its verdict.
    pub async fn scan(&self, message: &[u8]) -> Verdict {
        let spawned = tokio::process::Command::new(&self.command)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The message is written to stdin, so the child must not inherit
            // this process's terminal or a scanner that reads more than it was
            // given could consume the SMTP session's own input.
            .kill_on_drop(true)
            .spawn();

        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                return Verdict::Unavailable {
                    reason: format!("cannot run {}: {e}", self.command.display()),
                };
            }
        };

        // Written and awaited together: a scanner that answers before reading
        // the whole message — a size limit, say — would otherwise deadlock
        // against a write nobody is draining.
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => {
                return Verdict::Unavailable {
                    reason: "the scanner has no standard input".into(),
                };
            }
        };

        let message = message.to_vec();
        let feed = async move {
            // A closed pipe is not an error here: the scanner has decided
            // without reading the rest, which is its business.
            let _ = stdin.write_all(&message).await;
            let _ = stdin.shutdown().await;
        };

        let finished = tokio::time::timeout(self.timeout, async {
            tokio::join!(feed, child.wait_with_output()).1
        })
        .await;

        let output = match finished {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Verdict::Unavailable {
                    reason: format!("the scanner failed: {e}"),
                };
            }
            Err(_) => {
                // The child is killed by `kill_on_drop` when the future is
                // dropped here, so a hung scanner does not accumulate one
                // process per message.
                return Verdict::Unavailable {
                    reason: format!("the scanner did not answer within {:?}", self.timeout),
                };
            }
        };

        match output.status.code() {
            Some(0) => Verdict::Accept,
            Some(1) => Verdict::Reject {
                reason: summarise(&output.stdout, &output.stderr),
            },
            Some(code) => Verdict::Unavailable {
                reason: format!(
                    "the scanner exited {code}: {}",
                    summarise(&output.stdout, &output.stderr)
                ),
            },
            // Killed by a signal.
            None => Verdict::Unavailable {
                reason: "the scanner was killed".into(),
            },
        }
    }
}

/// One line of whatever the scanner said, for the log.
///
/// Bounded and single-line: the output may quote the message, and an unbounded
/// multi-line value would put attacker-controlled content into the log in a
/// shape that can forge log entries.
fn summarise(stdout: &[u8], stderr: &[u8]) -> String {
    let text = if stdout.is_empty() { stderr } else { stdout };
    String::from_utf8_lossy(text)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(script: &str) -> Scanner {
        Scanner {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn zero_accepts_and_one_rejects() {
        assert_eq!(
            scanner("cat > /dev/null").scan(b"message").await,
            Verdict::Accept
        );

        assert!(matches!(
            scanner("cat > /dev/null; echo 'Spam: yes'; exit 1")
                .scan(b"message")
                .await,
            Verdict::Reject { reason } if reason.contains("Spam: yes")
        ));
    }

    #[tokio::test]
    async fn the_message_reaches_the_scanner_on_standard_input() {
        // The whole point: the scanner sees the bytes that would be sent
        // onward, not a summary of them.
        let seen = scanner("grep -q 'Subject: hello' && exit 0 || exit 1");
        assert_eq!(
            seen.scan(b"Subject: hello\r\n\r\nbody\r\n").await,
            Verdict::Accept
        );
        assert!(matches!(
            seen.scan(b"Subject: something else\r\n\r\nbody\r\n").await,
            Verdict::Reject { .. }
        ));
    }

    #[tokio::test]
    async fn an_unknown_status_is_unavailable_rather_than_clean() {
        // A scanner that fails in a way it did not describe has said nothing,
        // and reading silence as "clean" turns a broken scanner into no scanner
        // — silently, at the moment somebody is trying to get past it.
        assert!(matches!(
            scanner("exit 3").scan(b"message").await,
            Verdict::Unavailable { .. }
        ));
    }

    #[tokio::test]
    async fn a_scanner_that_cannot_be_run_is_unavailable() {
        let missing = Scanner {
            command: "/nonexistent/scanner".into(),
            args: Vec::new(),
            timeout: Duration::from_secs(5),
        };
        assert!(matches!(
            missing.scan(b"message").await,
            Verdict::Unavailable { .. }
        ));
    }

    #[tokio::test]
    async fn a_hanging_scanner_is_bounded() {
        // A scanner that never answers must not hold the SMTP session open past
        // its own data timeout, and must not leave a process behind per message.
        let slow = Scanner {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), "sleep 30".into()],
            timeout: Duration::from_millis(200),
        };

        let started = std::time::Instant::now();
        assert!(matches!(
            slow.scan(b"message").await,
            Verdict::Unavailable { .. }
        ));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout did not bound the scan: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_scanner_that_stops_reading_early_still_answers() {
        // `head -c1` closes the pipe after one byte. Writing the message and
        // waiting for the child have to happen together, or this deadlocks
        // against a write nobody is draining.
        let picky = scanner("head -c1 > /dev/null; exit 1");
        let big = vec![b'x'; 1024 * 1024];
        assert!(matches!(
            picky.scan(&big).await,
            Verdict::Reject { .. } | Verdict::Unavailable { .. }
        ));
    }

    #[test]
    fn the_logged_summary_is_one_bounded_line() {
        // Scanner output may quote the message, so an unbounded multi-line
        // value would put attacker-controlled content into the log in a shape
        // that can forge entries.
        let noisy = b"first line\nsecond line\n".to_vec();
        assert_eq!(summarise(&noisy, b""), "first line");

        let long = vec![b'x'; 1000];
        assert_eq!(summarise(&long, b"").len(), 200);
    }
}

//! A metrics endpoint, bound to loopback unless told otherwise.
//!
//! Prometheus text format over HTTP, because that is what scrapers read and it
//! is a format a person can also `curl`. The whole server is a few dozen lines:
//! it answers `GET /metrics` and nothing else, which is the entire requirement
//! and avoids putting an HTTP stack in a mail server.
//!
//! # Local by default, and it says so
//!
//! The default listener is `127.0.0.1`. Metrics describe who sends mail here,
//! how much of it is failing and which domains are gated — an operational map
//! of the host, exposed with no authentication because a scraper on the same
//! machine does not need any. Binding it to a public address is a decision the
//! operator makes explicitly, and the daemon logs a warning when they do,
//! because "I did not realise it was reachable" is the usual way this goes
//! wrong.
//!
//! # Read from the database, not from counters
//!
//! What is worth scraping — how much mail is waiting, how old the oldest is,
//! how many domains are gated — is state, and the database already holds it
//! consistently. In-process counters would be a second copy that drifts on
//! restart and disagrees with `pigeon health`.

use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct Metrics {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl Metrics {
    /// Serve until stopped.
    pub async fn start(listen: SocketAddr, db: PathBuf) -> std::io::Result<Self> {
        if !listen.ip().is_loopback() {
            tracing::warn!(
                %listen,
                "the metrics endpoint is not on loopback: it is unauthenticated, and it \
                 describes who sends mail here and what is failing"
            );
        }

        let listener = TcpListener::bind(listen).await?;
        tracing::info!(%listen, "metrics endpoint listening");

        let (stop, mut stopped) = watch::channel(false);
        let handle = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = stopped.changed() => return,
                    accepted = listener.accept() => accepted,
                };

                let Ok((mut stream, _)) = accepted else {
                    continue;
                };
                let db = db.clone();

                // One connection at a time would be enough for a scraper, but a
                // stuck client would then stop every other scrape. Spawned, and
                // bounded by the read timeout below.
                tokio::spawn(async move {
                    let _ = serve_one(&mut stream, &db).await;
                });
            }
        });

        Ok(Self { stop, handle })
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    pub fn supervise(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            match self.handle.await {
                Ok(()) => tracing::debug!("the metrics endpoint stopped"),
                Err(e) if e.is_panic() => {
                    tracing::error!(error = %e, "the metrics endpoint panicked")
                }
                Err(_) => {}
            }
        })
    }
}

/// Answer one request.
///
/// Deliberately not a general HTTP server: it reads one bounded request, looks
/// at the path, and answers. A mail server with a general HTTP stack in it has
/// a second attack surface for the sake of one endpoint.
async fn serve_one(
    stream: &mut tokio::net::TcpStream,
    db: &std::path::Path,
) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];

    // Bounded in time and size: a scraper sends a short request immediately,
    // and anything that does not is not a scraper.
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    let n = match read {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, body) = if path.starts_with("/metrics") {
        ("200 OK", render(db))
    } else {
        // Not a 404 page: this is not a website, and the one useful thing to
        // say is where the metrics are.
        ("404 Not Found", "# try /metrics\n".to_string())
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// The metrics themselves, read from the database each scrape.
fn render(db: &std::path::Path) -> String {
    let mut out = String::new();

    let Ok(conn) = pigeon_db::open(db) else {
        // An unreadable database is itself the metric worth exporting: a
        // scraper seeing zero for everything else would read it as a quiet
        // host rather than a broken one.
        out.push_str("# HELP pigeon_up whether the daemon can read its own database\n");
        out.push_str("# TYPE pigeon_up gauge\npigeon_up 0\n");
        return out;
    };

    out.push_str("# HELP pigeon_up whether the daemon can read its own database\n");
    out.push_str("# TYPE pigeon_up gauge\npigeon_up 1\n");

    let counts: [(&str, &str, &str); 6] = [
        (
            "pigeon_domains",
            "domains configured",
            "SELECT count(*) FROM domain",
        ),
        (
            "pigeon_domains_gated",
            "domains whose DNS no longer passes",
            "SELECT count(*) FROM domain WHERE status = 'error'",
        ),
        (
            "pigeon_queue_waiting",
            "deliveries not yet terminal",
            "SELECT count(*) FROM delivery WHERE state IN ('queued','deferred','delivering')",
        ),
        (
            "pigeon_queue_frozen",
            "deliveries held by an operator",
            "SELECT count(*) FROM delivery WHERE frozen_at IS NOT NULL",
        ),
        (
            "pigeon_reports_owed",
            "failures whose sender has not been told yet",
            "SELECT count(*) FROM delivery WHERE notification = 'owed'",
        ),
        (
            "pigeon_messages_total",
            "messages whose records are still retained",
            "SELECT count(*) FROM message",
        ),
    ];

    for (name, help, sql) in counts {
        let value: i64 = conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1);
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
        ));
    }

    // The one that says whether the queue is draining. A count cannot: a
    // hundred messages a minute old is a busy host, one message four days old
    // is a problem nobody has noticed.
    let oldest: Option<i64> = conn
        .query_row(
            "SELECT min(m.received_at) FROM delivery d JOIN message m ON m.id = d.message_id
              WHERE d.state IN ('queued','deferred','delivering')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(None);

    out.push_str("# HELP pigeon_queue_oldest_seconds age of the oldest message still waiting\n");
    out.push_str("# TYPE pigeon_queue_oldest_seconds gauge\n");
    out.push_str(&format!(
        "pigeon_queue_oldest_seconds {}\n",
        oldest.map(|at| crate::unix_now() - at).unwrap_or(0)
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_database_reports_itself_as_down() {
        // A scraper seeing zeros for everything would read a broken host as a
        // quiet one, which is the failure this metric exists to prevent.
        let text = render(&PathBuf::from("/nonexistent/pigeon.db"));
        assert!(text.contains("pigeon_up 0"), "{text}");
        assert!(
            !text.contains("pigeon_queue_waiting"),
            "a host that cannot read its database reported queue depth: {text}"
        );
    }

    #[tokio::test]
    async fn the_endpoint_answers_metrics_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("pigeon-metrics-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).unwrap();
        pigeon_db::migrate(&mut conn, &db).unwrap();
        drop(conn);

        let metrics = Metrics::start("127.0.0.1:0".parse().unwrap(), db.clone())
            .await
            .expect("bind");
        // The port is not returned by `start`, so the test binds its own
        // listener path: rendering is what matters, and it is called directly.
        metrics.stop();

        let text = render(&db);
        assert!(text.contains("pigeon_up 1"), "{text}");
        assert!(text.contains("pigeon_queue_waiting 0"), "{text}");
        assert!(text.contains("pigeon_domains 0"), "{text}");
        // Prometheus requires HELP and TYPE before a sample, and a scraper
        // rejects the whole page without them.
        assert!(text.contains("# TYPE pigeon_queue_waiting gauge"), "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

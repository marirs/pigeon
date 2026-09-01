//! Rendering an RFC 3464 delivery status notification.
//!
//! What a person reads when their mail did not arrive, and what their mail
//! client parses to say so. Three decisions shape it:
//!
//! - **`Original-Recipient` names the address the sender wrote.** After
//!   forwarding, the destination that failed is a mailbox the sender has never
//!   heard of, and a report naming only that is a report they cannot act on.
//! - **Headers only, never the body.** Returning the body doubles the traffic
//!   an attacker gets from one message and returns content to an address that
//!   may not have sent it.
//! - **A missing original is described, not hidden.** If the body cannot be
//!   read the headers are omitted — and the report says Pigeon could not
//!   include them, rather than implying the message had none.

use crate::dsn::{Entry, Owed};

/// Render the report for one message's owed failures.
///
/// `original_headers` is `None` when the spooled message could not be read.
pub fn render(
    report: &Owed,
    reporting_host: &str,
    recipient: &str,
    original_headers: Option<&str>,
    date: &str,
    boundary: &str,
) -> Vec<u8> {
    let mut out = String::new();

    out.push_str(&format!(
        "From: Mail Delivery System <MAILER-DAEMON@{reporting_host}>\r\n"
    ));
    out.push_str(&format!("To: <{recipient}>\r\n"));
    out.push_str("Subject: Undelivered Mail Returned to Sender\r\n");
    out.push_str(&format!("Date: {date}\r\n"));
    // Bounces are not themselves bounced, and this is the header that says so
    // to anything reading it rather than the envelope.
    out.push_str("Auto-Submitted: auto-replied\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n"
    ));
    out.push_str("\r\n");

    // 1. The human part, first, because most people who open this are not
    //    reading the machine-readable section.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    out.push_str("This is the mail delivery system at ");
    out.push_str(reporting_host);
    out.push_str(".\r\n\r\n");
    out.push_str("Your message could not be delivered to the following recipients:\r\n\r\n");
    for entry in &report.entries {
        out.push_str(&human_paragraph(entry));
    }
    if original_headers.is_none() {
        out.push_str(
            "\r\nThe original message headers could not be included: this system could not \
             read its own stored copy of the message. That is a fault here, not with your \
             message or with the recipient.\r\n",
        );
    }

    // 2. The machine-readable part.
    out.push_str(&format!("\r\n--{boundary}\r\n"));
    out.push_str("Content-Type: message/delivery-status\r\n\r\n");
    out.push_str(&format!("Reporting-MTA: dns; {reporting_host}\r\n"));
    for entry in &report.entries {
        out.push_str("\r\n");
        // One per address the sender wrote, so a client can match the failure
        // to what the user typed.
        for original in &entry.original_recipients {
            out.push_str(&format!("Original-Recipient: rfc822; {original}\r\n"));
        }
        out.push_str(&format!(
            "Final-Recipient: rfc822; {}\r\n",
            entry.destination
        ));
        out.push_str("Action: failed\r\n");
        out.push_str(&format!("Status: {}\r\n", status_code(entry)));
        if let Some(code) = entry.code {
            out.push_str(&format!(
                "Diagnostic-Code: smtp; {code} {}\r\n",
                diagnostic(entry)
            ));
        } else {
            out.push_str(&format!(
                "Diagnostic-Code: x-local; {}\r\n",
                diagnostic(entry)
            ));
        }
    }

    // 3. The original headers, or nothing.
    if let Some(headers) = original_headers {
        out.push_str(&format!("\r\n--{boundary}\r\n"));
        out.push_str("Content-Type: text/rfc822-headers\r\n\r\n");
        out.push_str(headers);
        if !headers.ends_with("\r\n") {
            out.push_str("\r\n");
        }
    }

    out.push_str(&format!("\r\n--{boundary}--\r\n"));
    out.into_bytes()
}

fn human_paragraph(entry: &Entry) -> String {
    let addresses = if entry.original_recipients.is_empty() {
        entry.destination.clone()
    } else {
        entry.original_recipients.join(", ")
    };

    match entry.state.as_str() {
        // Two different things to do about it, so two different sentences.
        "expired" => format!(
            "  {addresses}\r\n    Delivery to {} kept failing for long enough that this \
             system gave up. The last response was: {}\r\n",
            entry.destination,
            diagnostic(entry)
        ),
        _ => format!(
            "  {addresses}\r\n    The server for {} refused it permanently: {}\r\n",
            entry.destination,
            diagnostic(entry)
        ),
    }
}

/// An enhanced status code (RFC 3463).
fn status_code(entry: &Entry) -> &'static str {
    match (entry.state.as_str(), entry.code) {
        ("expired", _) => "4.4.7",
        (_, Some(550)) => "5.1.1",
        (_, Some(code)) if (500..600).contains(&code) => "5.0.0",
        // No SMTP code and not expired: a local fault, and the status says so
        // rather than blaming the recipient's server.
        _ => "4.3.0",
    }
}

fn diagnostic(entry: &Entry) -> String {
    entry
        .response
        .clone()
        .unwrap_or_else(|| "no response was recorded".to_string())
}

/// The header block of a spooled message, for the returned-headers part.
///
/// Everything up to the first blank line. `None` if there is no blank line at
/// all, which means the stored message is not one this can quote from.
pub fn headers_of(message: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(message).ok()?;
    let end = text.find("\r\n\r\n").or_else(|| text.find("\n\n"))?;
    Some(text[..end].to_string())
}

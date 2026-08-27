//! Choosing where to deliver.
//!
//! Ordering candidate hosts is separate from asking DNS for them, because the
//! ordering rules carry all the subtlety and none of the I/O. Preference
//! ordering, spreading load across equal-preference hosts, and recognising a
//! domain that refuses mail outright are all decided here, against records the
//! caller supplies.

use std::fmt;

/// One MX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    /// Exchange hostname as DNS returned it, trailing dot and all.
    pub exchange: String,
}

impl MxRecord {
    pub fn new(preference: u16, exchange: impl Into<String>) -> Self {
        Self { preference, exchange: exchange.into() }
    }

    /// Whether this is the RFC 7505 null MX.
    ///
    /// `MX 0 .` is a domain stating that it accepts no mail at all. It is a
    /// deliberate declaration, not a misconfiguration, so mail for it fails
    /// permanently rather than being retried for days.
    fn is_null(&self) -> bool {
        self.preference == 0 && matches!(self.exchange.trim(), "." | "")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MxError {
    /// The domain publishes a null MX and accepts no mail. Permanent.
    NullMx,
    /// No usable exchange. The caller should fall back to an address lookup,
    /// since a domain with an A record and no MX still receives mail.
    NoUsableHost,
}

impl fmt::Display for MxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullMx => f.write_str("domain publishes a null MX and accepts no mail"),
            Self::NoUsableHost => f.write_str("no usable MX host"),
        }
    }
}

impl std::error::Error for MxError {}

/// Order candidate hosts, best first.
///
/// `rotation` spreads load across hosts of equal preference. Passing a counter
/// that advances per delivery gives round-robin; passing a constant gives a
/// stable order. Always trying the first host in DNS order would send an
/// entire queue at one member of a balanced pool.
pub fn order_hosts(records: &[MxRecord], rotation: u64) -> Result<Vec<String>, MxError> {
    // A null MX is only meaningful as the entire answer. Alongside real
    // exchanges it is a misconfiguration, and refusing the mail over it would
    // be a worse error than ignoring it.
    if records.len() == 1 && records[0].is_null() {
        return Err(MxError::NullMx);
    }

    let mut usable: Vec<(u16, String)> = records
        .iter()
        .filter(|r| !r.is_null())
        .filter_map(|r| normalise(&r.exchange).map(|h| (r.preference, h)))
        .collect();

    if usable.is_empty() {
        return Err(MxError::NoUsableHost);
    }

    // Lowest preference first. `sort_by_key` is a stable sort, which matters:
    // DNS order has to survive within a preference group for the rotation
    // below to be the only thing reordering equals.
    usable.sort_by_key(|(preference, _)| *preference);

    let mut out: Vec<String> = Vec::with_capacity(usable.len());
    let mut i = 0;
    while i < usable.len() {
        let pref = usable[i].0;
        let end = usable[i..].partition_point(|(p, _)| *p == pref) + i;
        let group = &usable[i..end];

        // Rotate the group so successive deliveries start at different hosts.
        let offset = (rotation % group.len() as u64) as usize;
        for k in 0..group.len() {
            let host = &group[(offset + k) % group.len()].1;
            if !out.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                out.push(host.clone());
            }
        }
        i = end;
    }

    if out.is_empty() { Err(MxError::NoUsableHost) } else { Ok(out) }
}

/// Trim a DNS name into something connectable, or reject it.
fn normalise(exchange: &str) -> Option<String> {
    let host = exchange.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return None;
    }
    // A hostname with a space or an embedded null is not one; refuse rather
    // than pass it to a connect call.
    if host.chars().any(|c| c.is_whitespace() || c == '\0') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(records: &[MxRecord]) -> Vec<String> {
        order_hosts(records, 0).unwrap()
    }

    #[test]
    fn orders_by_preference() {
        let r = [
            MxRecord::new(30, "third.example.com."),
            MxRecord::new(10, "first.example.com."),
            MxRecord::new(20, "second.example.com."),
        ];
        assert_eq!(hosts(&r), ["first.example.com", "second.example.com", "third.example.com"]);
    }

    #[test]
    fn strips_trailing_dot_and_lowercases() {
        let r = [MxRecord::new(10, "MX1.Example.COM.")];
        assert_eq!(hosts(&r), ["mx1.example.com"]);
    }

    #[test]
    fn rotation_spreads_equal_preference_hosts() {
        let r = [
            MxRecord::new(10, "a.example.com."),
            MxRecord::new(10, "b.example.com."),
            MxRecord::new(10, "c.example.com."),
        ];
        // Every host leads for some rotation, so a queue does not land
        // entirely on one member of a balanced pool.
        let firsts: Vec<String> =
            (0..3).map(|n| order_hosts(&r, n).unwrap()[0].clone()).collect();
        assert_eq!(firsts, ["a.example.com", "b.example.com", "c.example.com"]);

        // Rotation reorders, never drops.
        for n in 0..6 {
            let mut got = order_hosts(&r, n).unwrap();
            got.sort();
            assert_eq!(got, ["a.example.com", "b.example.com", "c.example.com"]);
        }
    }

    #[test]
    fn rotation_does_not_cross_preference_groups() {
        let r = [
            MxRecord::new(10, "primary.example.com."),
            MxRecord::new(20, "backup-a.example.com."),
            MxRecord::new(20, "backup-b.example.com."),
        ];
        // The primary leads regardless of rotation: preference is a priority,
        // not a suggestion.
        for n in 0..4 {
            assert_eq!(order_hosts(&r, n).unwrap()[0], "primary.example.com");
        }
    }

    #[test]
    fn null_mx_is_a_permanent_refusal() {
        // RFC 7505: the domain is stating it accepts no mail. Retrying for
        // five days would be wrong.
        assert_eq!(order_hosts(&[MxRecord::new(0, ".")], 0), Err(MxError::NullMx));
    }

    #[test]
    fn null_mx_alongside_real_hosts_is_ignored_not_obeyed() {
        // Contradictory records are a misconfiguration. Delivering is the
        // better failure than refusing mail the domain probably wants.
        let r = [MxRecord::new(0, "."), MxRecord::new(10, "mx.example.com.")];
        assert_eq!(hosts(&r), ["mx.example.com"]);
    }

    #[test]
    fn rejects_unusable_exchanges() {
        assert_eq!(order_hosts(&[MxRecord::new(10, "")], 0), Err(MxError::NoUsableHost));
        assert_eq!(order_hosts(&[MxRecord::new(10, "localhost")], 0), Err(MxError::NoUsableHost));
        assert_eq!(
            order_hosts(&[MxRecord::new(10, "bad host.example.com")], 0),
            Err(MxError::NoUsableHost)
        );
        assert_eq!(order_hosts(&[], 0), Err(MxError::NoUsableHost));
    }

    #[test]
    fn keeps_good_records_when_some_are_unusable() {
        let r = [MxRecord::new(10, "  "), MxRecord::new(20, "mx.example.com.")];
        assert_eq!(hosts(&r), ["mx.example.com"]);
    }

    #[test]
    fn deduplicates_case_insensitively() {
        let r = [
            MxRecord::new(10, "mx.example.com."),
            MxRecord::new(10, "MX.EXAMPLE.COM."),
            MxRecord::new(20, "mx.example.com."),
        ];
        assert_eq!(hosts(&r), ["mx.example.com"]);
    }
}

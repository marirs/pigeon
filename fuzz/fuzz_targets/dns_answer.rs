#![no_main]
//! MX answers, as they arrive from a resolver that may be hostile.
//!
//! A blocklist operator, a compromised recursor, or a domain owner can put
//! whatever they like in these records. What must hold is that ordering them
//! never panics and never produces a host Pigeon would connect to blindly: an
//! exchange with an empty name, a name that is only dots, or a preference that
//! overflows is refused rather than dialled.

use libfuzzer_sys::fuzz_target;
use pigeon_dns::{MxRecord, order_hosts};

fuzz_target!(|data: &[u8]| {
    // Two bytes of preference and a name, repeated: enough shape for the
    // fuzzer to explore ordering, ties and malformed names.
    let mut records = Vec::new();
    let mut rest = data;
    while rest.len() >= 3 {
        let preference = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(rest[2]).min(rest.len() - 3);
        let name = String::from_utf8_lossy(&rest[3..3 + len]).into_owned();
        records.push(MxRecord::new(preference, name));
        rest = &rest[3 + len..];
    }

    if let Ok(hosts) = order_hosts(&records, u64::from(data.len() as u32)) {
        for host in hosts {
            // Every host that survives ordering has to be something worth
            // connecting to. A blank or dot-only name would be handed to
            // `connect`, and resolving it is somebody else's guess.
            assert!(!host.is_empty(), "an empty exchange survived ordering");
            assert!(
                host.chars().any(|c| c != '.'),
                "a dot-only exchange survived ordering: {host:?}"
            );
        }
    }
});

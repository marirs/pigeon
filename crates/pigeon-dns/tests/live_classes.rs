//! Confirms the NXDOMAIN / NODATA / transient split still holds under the
//! feature set mail-auth's `ring` forces onto hickory (`M2-DESIGN.md` §8.3).
use pigeon_dns::{LookupError, MxLookup, SystemResolver};

#[tokio::test]
#[ignore = "needs DNS"]
async fn nxdomain_nodata_and_transient_stay_distinct() {
    let r = SystemResolver::from_system().expect("no system resolver");

    // A name that does not exist: permanent, and the message must never be
    // retried against it.
    let nx = r
        .lookup_mx("this-domain-really-should-not-exist-pigeon.invalid")
        .await;
    assert!(
        matches!(nx, Err(LookupError::NoSuchDomain(_))),
        "NXDOMAIN was not classified as a missing domain: {nx:?}"
    );

    // A name that exists and publishes no MX. This is the case finding 13 got
    // wrong by matching on error text: both arrive as NoRecordsFound and both
    // stringify identically, so only the response code separates them — and
    // treating this as NXDOMAIN refused mail to every domain with an A record
    // and no MX, permanently.
    let nodata = r.lookup_mx("a.root-servers.net").await;
    assert!(
        matches!(nodata, Err(LookupError::NoRecords(_))),
        "NODATA was not classified as a domain without MX: {nodata:?}"
    );

    // And a name that does resolve, so the test cannot pass by failing at
    // everything.
    let ok = r.lookup_mx("gmail.com").await;
    assert!(ok.is_ok(), "gmail.com did not resolve: {ok:?}");
}

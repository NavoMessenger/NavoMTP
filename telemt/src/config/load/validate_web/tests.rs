use super::*;

#[test]
fn web_host_normalization_matches_client_vectors() {
    assert_eq!(
        normalize_web_host(" Proxy.Example.COM ", "host").unwrap(),
        "proxy.example.com"
    );
    assert_eq!(
        normalize_web_host("bücher.example", "host").unwrap(),
        "xn--bcher-kva.example"
    );
    for invalid in [
        "localhost",
        "127.0.0.1",
        "127.1",
        "0x7f.1",
        "0177.0.0.1",
        "1.2.3",
        "site.example:443",
        "site..example",
        "site.example.",
    ] {
        assert!(normalize_web_host(invalid, "host").is_err(), "{invalid}");
    }
}

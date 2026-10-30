use super::*;
use ipnetwork::IpNetwork;
use proptest::prelude::*;

use crate::config::{WebCarrier, WebClientIpSource};
use crate::web::http::capability::{bridge_candidate, scan_capabilities};

#[test]
fn canonical_bridge_query_rejects_aliases() {
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    assert!(bridge_candidate(Some(&format!("bridge={token}"))).is_canonical());
    assert!(!bridge_candidate(Some(&format!("x=1&bridge={token}"))).is_canonical());
    assert!(!bridge_candidate(Some(&format!("bridge={token}="))).is_canonical());
}

#[test]
fn capability_scan_checks_every_entry_independent_of_match_position() {
    let capabilities = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    for (expected_index, candidate) in capabilities.iter().enumerate() {
        let scan = scan_capabilities(&capabilities, candidate);
        assert!(bool::from(scan.matched));
        assert_eq!(scan.matched_index as usize, expected_index);
        assert_eq!(scan.comparisons, capabilities.len());
    }

    let miss = scan_capabilities(&capabilities, &[99u8; 32]);
    assert!(!bool::from(miss.matched));
    assert_eq!(miss.comparisons, capabilities.len());

    let empty = scan_capabilities(&[], &[99u8; 32]);
    assert!(!bool::from(empty.matched));
    assert_eq!(empty.comparisons, 0);
}

#[test]
fn capability_profile_table_drift_fails_closed() {
    let capability = [5u8; 32];
    let mut config = crate::web::http::tests::runtime_config(capability, WebCarrier::Https);
    let runtime = Arc::get_mut(config.web.runtime.as_mut().unwrap()).unwrap();
    let vhost = Arc::get_mut(runtime.vhosts.get_mut("proxy.example.com").unwrap()).unwrap();

    assert!(match_profile(vhost, &capability).is_some());
    vhost.capabilities[0] = [6u8; 32];
    assert!(match_profile(vhost, &[6u8; 32]).is_none());
    vhost.capabilities = Vec::new().into_boxed_slice();
    assert!(match_profile(vhost, &capability).is_none());
}

proptest! {
    #[test]
    fn every_capability_has_one_canonical_bridge_query(capability in any::<[u8; 32]>()) {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
        let candidate = bridge_candidate(Some(&format!("bridge={token}")));
        prop_assert!(candidate.is_canonical());
        prop_assert_eq!(candidate.scan_bytes(), &capability);
    }
}

#[test]
fn host_is_canonical_and_forwarded_identity_is_single_parseable_ip() {
    let request = Request::builder()
        .header(header::HOST, "proxy.example.com:443")
        .header("x-forwarded-for", "192.0.2.10")
        .body(())
        .unwrap();
    assert_eq!(canonical_request_host(&request), Some("proxy.example.com"));
    let trusted: [IpNetwork; 1] = ["127.0.0.1/32".parse().unwrap()];
    assert_eq!(
        client_ip(
            &request,
            "127.0.0.1:40000".parse().unwrap(),
            WebClientIpSource::XForwardedFor,
            &trusted,
        ),
        Some("192.0.2.10".parse().unwrap())
    );

    let expanded_ipv6 = Request::builder()
        .header("x-forwarded-for", "2001:0db8:0:0:0:0:0:10")
        .body(())
        .unwrap();
    assert_eq!(
        client_ip(
            &expanded_ipv6,
            "127.0.0.1:40000".parse().unwrap(),
            WebClientIpSource::XForwardedFor,
            &trusted,
        ),
        Some("2001:db8::10".parse().unwrap())
    );

    let without_forwarded_address = Request::builder().body(()).unwrap();
    assert_eq!(
        client_ip(
            &without_forwarded_address,
            "127.0.0.1:40000".parse().unwrap(),
            WebClientIpSource::XForwardedFor,
            &trusted,
        ),
        Some("127.0.0.1".parse().unwrap())
    );

    let empty_forwarded_address = Request::builder()
        .header("x-forwarded-for", "")
        .body(())
        .unwrap();
    assert_eq!(
        client_ip(
            &empty_forwarded_address,
            "127.0.0.1:40000".parse().unwrap(),
            WebClientIpSource::XForwardedFor,
            &trusted,
        ),
        Some("127.0.0.1".parse().unwrap())
    );

    let uppercase = Request::builder()
        .header(header::HOST, "Proxy.Example.com")
        .body(())
        .unwrap();
    assert!(canonical_request_host(&uppercase).is_none());
    let appended = Request::builder()
        .header("x-forwarded-for", "192.0.2.10, 198.51.100.4")
        .body(())
        .unwrap();
    assert!(
        client_ip(
            &appended,
            "127.0.0.1:40000".parse().unwrap(),
            WebClientIpSource::XForwardedFor,
            &trusted,
        )
        .is_none()
    );
}

#[test]
fn bearer_and_sequence_headers_reject_noncanonical_aliases() {
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
    let request = Request::builder()
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-up-seq", "17")
        .body(())
        .unwrap();
    assert_eq!(
        bearer_token_hash(&request),
        Some(Sha256::digest([1u8; 32]).into())
    );
    assert_eq!(canonical_u64_header(&request, "x-up-seq"), Some(17));

    let leading_zero = Request::builder()
        .header("x-up-seq", "017")
        .body(())
        .unwrap();
    assert!(canonical_u64_header(&leading_zero, "x-up-seq").is_none());
}

#[test]
fn cookie_header_accepts_only_absent_or_one_empty_value() {
    let absent = Request::new(());
    assert!(compatible_cookie_header(&absent));

    let empty = Request::builder()
        .header(header::COOKIE, "")
        .body(())
        .unwrap();
    assert!(compatible_cookie_header(&empty));

    let nonempty = Request::builder()
        .header(header::COOKIE, "state=unexpected")
        .body(())
        .unwrap();
    assert!(!compatible_cookie_header(&nonempty));

    let whitespace = Request::builder()
        .header(header::COOKIE, " ")
        .body(())
        .unwrap();
    assert!(!compatible_cookie_header(&whitespace));

    let mut duplicate_empty = Request::new(());
    duplicate_empty
        .headers_mut()
        .append(header::COOKIE, "".parse().unwrap());
    duplicate_empty
        .headers_mut()
        .append(header::COOKIE, "".parse().unwrap());
    assert!(!compatible_cookie_header(&duplicate_empty));

    let mut duplicate_mixed = Request::new(());
    duplicate_mixed
        .headers_mut()
        .append(header::COOKIE, "".parse().unwrap());
    duplicate_mixed
        .headers_mut()
        .append(header::COOKIE, "state=unexpected".parse().unwrap());
    assert!(!compatible_cookie_header(&duplicate_mixed));
}

#[test]
fn carrier_metadata_is_canonical_and_legacy_safe() {
    let automatic = Request::builder()
        .header(
            "x-carrier-capabilities",
            "https,https-lanes,websocket,websocket-lanes",
        )
        .header("x-carrier-attempt", "2")
        .header("x-carrier-failure", "timeout")
        .header(header::USER_AGENT, "Example  Browser")
        .body(())
        .unwrap();
    let parsed = carrier_request(&automatic, "proxy.example.com").unwrap();
    assert!(parsed.is_automatic());
    assert_eq!(parsed.attempt(), Some(2));
    assert_eq!(parsed.failure(), Some(CarrierFailure::Timeout));

    let missing_failure = Request::builder()
        .header(
            "x-carrier-capabilities",
            "https,https-lanes,websocket,websocket-lanes",
        )
        .header("x-carrier-attempt", "2")
        .body(())
        .unwrap();
    assert!(carrier_request(&missing_failure, "proxy.example.com").is_none());

    let legacy = Request::builder()
        .header(header::USER_AGENT, "Native")
        .body(())
        .unwrap();
    assert!(
        !carrier_request(&legacy, "proxy.example.com")
            .unwrap()
            .is_automatic()
    );

    let reordered = Request::builder()
        .header("x-carrier-capabilities", "websocket,https")
        .header("x-carrier-attempt", "1")
        .body(())
        .unwrap();
    assert!(carrier_request(&reordered, "proxy.example.com").is_none());
}

#[test]
fn native_ios_user_agent_enforces_the_https_capability_ceiling() {
    let metadata_free = Request::builder()
        .header(
            header::USER_AGENT,
            "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
        )
        .body(())
        .unwrap();
    let parsed = carrier_request(&metadata_free, "proxy.example.com").unwrap();
    assert_eq!(parsed.class(), CarrierClientClass::Ios);
    assert!(!parsed.is_automatic());
    assert!(!parsed.uses_capabilities());

    let automatic = Request::builder()
        .header("x-carrier-capabilities", "https,https-lanes")
        .header("x-carrier-attempt", "1")
        .header(
            header::USER_AGENT,
            "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
        )
        .body(())
        .unwrap();
    let parsed = carrier_request(&automatic, "proxy.example.com").unwrap();
    assert_eq!(parsed.class(), CarrierClientClass::Ios);
    assert!(parsed.is_automatic());
    assert!(parsed.supports(WebCarrier::Https));
    assert!(!parsed.supports(WebCarrier::HttpsLanes));
    assert!(!parsed.supports(WebCarrier::Websocket));
    assert!(!parsed.supports(WebCarrier::WebsocketLanes));

    let incompatible = Request::builder()
        .header("x-carrier-capabilities", "websocket")
        .header("x-carrier-attempt", "1")
        .header(
            header::USER_AGENT,
            "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
        )
        .body(())
        .unwrap();
    assert!(carrier_request(&incompatible, "proxy.example.com").is_none());

    let stripped = Request::builder()
        .header("x-carrier-attempt", "1")
        .header(header::ORIGIN, "https://proxy.example.com")
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-dest", "empty")
        .header(
            header::USER_AGENT,
            "Telemt/1 CFNetwork/1498.700.2 Darwin/23.6.0",
        )
        .body(())
        .unwrap();
    assert!(carrier_request(&stripped, "proxy.example.com").is_none());
}

#[test]
fn mapped_private_addresses_are_not_learning_evidence() {
    for address in ["::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
        let effective_ip = address.parse().unwrap();
        let request = Request::builder()
            .header("x-forwarded-for", address)
            .body(())
            .unwrap();
        assert!(!carrier_ip_learning_eligible(&request, effective_ip));
    }
    let effective_ip = "::ffff:8.8.8.8".parse().unwrap();
    let request = Request::builder()
        .header("x-forwarded-for", "::ffff:8.8.8.8")
        .body(())
        .unwrap();
    assert!(carrier_ip_learning_eligible(&request, effective_ip));
}

#[test]
fn strict_browser_metadata_recovers_a_stripped_capability_marker() {
    let request = Request::builder()
        .header("x-carrier-attempt", "1")
        .header(header::ORIGIN, "https://proxy.example.com")
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-dest", "empty")
        .body(())
        .unwrap();
    let parsed = carrier_request(&request, "proxy.example.com").unwrap();
    assert_eq!(parsed.class(), CarrierClientClass::BrowserHint);
}

#[test]
fn user_agent_learning_key_is_case_and_whitespace_normalized() {
    let first = Request::builder()
        .header(header::USER_AGENT, "  Example\t Browser  ")
        .body(())
        .unwrap();
    let second = Request::builder()
        .header(header::USER_AGENT, "example browser")
        .body(())
        .unwrap();
    assert_eq!(
        normalized_user_agent_hash(&first),
        normalized_user_agent_hash(&second)
    );
}

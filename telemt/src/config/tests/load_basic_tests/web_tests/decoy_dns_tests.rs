use super::*;

#[test]
fn decoy_dns_resolution_defaults_to_never() {
    let decoy: WebDecoyConfig = serde_json::from_value(serde_json::json!({
        "mode": "http_upstream",
        "upstream": "http://127.0.0.1:18081"
    }))
    .unwrap();
    let serialized = serde_json::to_value(decoy).unwrap();
    assert_eq!(serialized["resolve"], "never");
}

#[test]
fn decoy_dns_timeout_defaults_to_five_seconds() {
    let serialized = serde_json::to_value(WebTimeoutsConfig::default()).unwrap();
    assert_eq!(serialized["decoy_resolve_secs"], 5);
}

#[test]
fn decoy_dns_resolution_is_opt_in_and_mode_specific() {
    let hostname = WEB_CONFIG.replace("127.0.0.1:18081", "example.com:18081");
    assert!(load_config_error_from_temp_toml(&hostname).contains("IP literal"));
    let never = hostname.replace(
        "mode = \"http_upstream\"",
        "mode = \"http_upstream\"\nresolve = \"never\"",
    );
    assert!(load_config_error_from_temp_toml(&never).contains("IP literal"));
    let unknown = WEB_CONFIG.replace(
        "mode = \"http_upstream\"",
        "mode = \"http_upstream\"\nresolve = \"always\"",
    );
    assert!(load_config_error_from_temp_toml(&unknown).contains("unknown variant"));
    let wrong_mode = WEB_CONFIG.replace(
        "mode = \"http_upstream\"",
        "mode = \"static_directory\"\nresolve = \"startup\"\ndirectory = \"/tmp\"",
    );
    assert!(
        load_config_error_from_temp_toml(&wrong_mode).contains("only valid for mode=http_upstream")
    );
}

#[test]
fn decoy_dns_timeout_bounds_are_independent_from_request_deadlines() {
    for seconds in [0, 3601] {
        let text = format!("{WEB_CONFIG}\n[web.timeouts]\ndecoy_resolve_secs = {seconds}\n");
        assert!(load_config_error_from_temp_toml(&text).contains("decoy_resolve_secs"));
    }
    let text = format!("{WEB_CONFIG}\n[web.timeouts]\ndecoy_resolve_secs = 3600\n");
    assert_eq!(
        load_config_from_temp_toml(&text)
            .web
            .timeouts
            .decoy_resolve_secs,
        3600
    );
}

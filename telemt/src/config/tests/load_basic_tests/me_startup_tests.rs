use super::*;

#[test]
fn stun_nat_probe_concurrency_zero_is_rejected() {
    let toml = r#"
        [general]
        stun_nat_probe_concurrency = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_stun_nat_probe_concurrency_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.stun_nat_probe_concurrency must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_reinit_every_default_is_set() {
    let toml = r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_reinit_every_default_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(
        cfg.general.me_reinit_every_secs,
        default_me_reinit_every_secs()
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_reinit_every_zero_is_rejected() {
    let toml = r#"
        [general]
        me_reinit_every_secs = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_reinit_every_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_reinit_every_secs must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_single_endpoint_outage_backoff_range_is_validated() {
    let toml = r#"
        [general]
        me_single_endpoint_outage_backoff_min_ms = 4000
        me_single_endpoint_outage_backoff_max_ms = 3000

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_single_endpoint_outage_backoff_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains(
        "general.me_single_endpoint_outage_backoff_min_ms must be <= general.me_single_endpoint_outage_backoff_max_ms"
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_single_endpoint_shadow_writers_too_large_is_rejected() {
    let toml = r#"
        [general]
        me_single_endpoint_shadow_writers = 33

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_single_endpoint_shadow_writers_limit_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_single_endpoint_shadow_writers must be within [0, 32]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_adaptive_floor_min_writers_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_adaptive_floor_min_writers_single_endpoint = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_adaptive_floor_min_writers_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(
        err.contains(
            "general.me_adaptive_floor_min_writers_single_endpoint must be within [1, 32]"
        )
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_floor_mode_adaptive_is_parsed() {
    let toml = r#"
        [general]
        me_floor_mode = "adaptive"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_floor_mode_adaptive_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.me_floor_mode, MeFloorMode::Adaptive);
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_adaptive_floor_max_active_writers_per_core_zero_is_rejected() {
    let toml = r#"
        [general]
        me_adaptive_floor_max_active_writers_per_core = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_adaptive_floor_max_active_per_core_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_adaptive_floor_max_active_writers_per_core must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_adaptive_floor_max_warm_writers_global_zero_is_rejected() {
    let toml = r#"
        [general]
        me_adaptive_floor_max_warm_writers_global = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_adaptive_floor_max_warm_global_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_adaptive_floor_max_warm_writers_global must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn upstream_connect_retry_attempts_zero_is_rejected() {
    let toml = r#"
        [general]
        upstream_connect_retry_attempts = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_upstream_connect_retry_attempts_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.upstream_connect_retry_attempts must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn upstream_unhealthy_fail_threshold_zero_is_rejected() {
    let toml = r#"
        [general]
        upstream_unhealthy_fail_threshold = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_upstream_unhealthy_fail_threshold_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.upstream_unhealthy_fail_threshold must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn tg_connect_zero_is_rejected() {
    let toml = r#"
        [general]
        tg_connect = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_tg_connect_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.tg_connect must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn rpc_proxy_req_every_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        rpc_proxy_req_every = 9

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_rpc_proxy_req_every_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.rpc_proxy_req_every must be 0 or within [10, 300]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn rpc_proxy_req_every_zero_and_valid_range_are_accepted() {
    let toml_zero = r#"
        [general]
        rpc_proxy_req_every = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path_zero = dir.join("telemt_rpc_proxy_req_every_zero_ok_test.toml");
    std::fs::write(&path_zero, toml_zero).unwrap();
    let cfg_zero = ProxyConfig::load(&path_zero).unwrap();
    assert_eq!(cfg_zero.general.rpc_proxy_req_every, 0);
    let _ = std::fs::remove_file(path_zero);

    let toml_valid = r#"
        [general]
        rpc_proxy_req_every = 40

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let path_valid = dir.join("telemt_rpc_proxy_req_every_valid_ok_test.toml");
    std::fs::write(&path_valid, toml_valid).unwrap();
    let cfg_valid = ProxyConfig::load(&path_valid).unwrap();
    assert_eq!(cfg_valid.general.rpc_proxy_req_every, 40);
    let _ = std::fs::remove_file(path_valid);
}

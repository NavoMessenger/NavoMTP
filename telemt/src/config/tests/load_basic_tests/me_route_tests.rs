use super::*;

#[test]
fn me_route_backpressure_base_timeout_ms_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_route_backpressure_base_timeout_ms = 5001

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_route_backpressure_base_timeout_ms_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_route_backpressure_base_timeout_ms must be within [1, 5000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_route_backpressure_high_timeout_ms_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_route_backpressure_base_timeout_ms = 100
        me_route_backpressure_high_timeout_ms = 5001

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_route_backpressure_high_timeout_ms_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_route_backpressure_high_timeout_ms must be within [1, 5000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_route_no_writer_wait_ms_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_route_no_writer_wait_ms = 5

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_route_no_writer_wait_ms_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_route_no_writer_wait_ms must be within [10, 5000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_route_blocking_send_timeout_ms_zero_is_rejected() {
    let toml = r#"
        [general]
        me_route_blocking_send_timeout_ms = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_route_blocking_send_timeout_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_route_blocking_send_timeout_ms must be within [1, 5000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_route_no_writer_mode_is_parsed() {
    let toml = r#"
        [general]
        me_route_no_writer_mode = "inline_recovery_legacy"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_route_no_writer_mode_parse_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(
        cfg.general.me_route_no_writer_mode,
        crate::config::MeRouteNoWriterMode::InlineRecoveryLegacy
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn proxy_config_cache_paths_empty_are_rejected() {
    let toml = r#"
        [general]
        proxy_config_v4_cache_path = "   "

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_proxy_config_v4_cache_path_empty_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.proxy_config_v4_cache_path cannot be empty"));
    let _ = std::fs::remove_file(path);

    let toml_v6 = r#"
        [general]
        proxy_config_v6_cache_path = ""

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let path_v6 = dir.join("telemt_proxy_config_v6_cache_path_empty_test.toml");
    std::fs::write(&path_v6, toml_v6).unwrap();
    let err_v6 = ProxyConfig::load(&path_v6).unwrap_err().to_string();
    assert!(err_v6.contains("general.proxy_config_v6_cache_path cannot be empty"));
    let _ = std::fs::remove_file(path_v6);
}

#[test]
fn me_hardswap_warmup_defaults_are_set() {
    let toml = r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_hardswap_warmup_defaults_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(
        cfg.general.me_hardswap_warmup_delay_min_ms,
        default_me_hardswap_warmup_delay_min_ms()
    );
    assert_eq!(
        cfg.general.me_hardswap_warmup_delay_max_ms,
        default_me_hardswap_warmup_delay_max_ms()
    );
    assert_eq!(
        cfg.general.me_hardswap_warmup_extra_passes,
        default_me_hardswap_warmup_extra_passes()
    );
    assert_eq!(
        cfg.general.me_hardswap_warmup_pass_backoff_base_ms,
        default_me_hardswap_warmup_pass_backoff_base_ms()
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_hardswap_warmup_delay_range_is_validated() {
    let toml = r#"
        [general]
        me_hardswap_warmup_delay_min_ms = 2001
        me_hardswap_warmup_delay_max_ms = 2000

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_hardswap_warmup_delay_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains(
        "general.me_hardswap_warmup_delay_min_ms must be <= general.me_hardswap_warmup_delay_max_ms"
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_hardswap_warmup_delay_max_zero_is_rejected() {
    let toml = r#"
        [general]
        me_hardswap_warmup_delay_max_ms = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_hardswap_warmup_delay_max_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_hardswap_warmup_delay_max_ms must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_hardswap_warmup_extra_passes_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_hardswap_warmup_extra_passes = 11

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_hardswap_warmup_extra_passes_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_hardswap_warmup_extra_passes must be within [0, 10]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_hardswap_warmup_pass_backoff_zero_is_rejected() {
    let toml = r#"
        [general]
        me_hardswap_warmup_pass_backoff_base_ms = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_hardswap_warmup_backoff_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_hardswap_warmup_pass_backoff_base_ms must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_config_stable_snapshots_zero_is_rejected() {
    let toml = r#"
        [general]
        me_config_stable_snapshots = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_config_stable_snapshots_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_config_stable_snapshots must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn proxy_secret_stable_snapshots_zero_is_rejected() {
    let toml = r#"
        [general]
        proxy_secret_stable_snapshots = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_proxy_secret_stable_snapshots_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.proxy_secret_stable_snapshots must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn proxy_secret_len_max_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        proxy_secret_len_max = 16

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_proxy_secret_len_max_out_of_range_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.proxy_secret_len_max must be within [32, 4096]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn me_pool_min_fresh_ratio_out_of_range_is_rejected() {
    let toml = r#"
        [general]
        me_pool_min_fresh_ratio = 1.5

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_me_pool_min_ratio_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.me_pool_min_fresh_ratio must be within [0.0, 1.0]"));
    let _ = std::fs::remove_file(path);
}

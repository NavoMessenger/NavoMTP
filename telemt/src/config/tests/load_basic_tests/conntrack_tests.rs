use super::*;

#[test]
fn conntrack_control_is_opt_in_by_default() {
    assert!(!default_conntrack_control_enabled());
    assert!(
        !ProxyConfig::default()
            .server
            .conntrack_control
            .inline_conntrack_control
    );
    let cfg = load_config_from_temp_toml(
        r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
        "#,
    );
    assert!(!cfg.server.conntrack_control.inline_conntrack_control);
    assert!(
        !cfg.server
            .conntrack_control
            .inline_conntrack_control_explicit
    );
    assert_eq!(
        serde_json::to_value(&cfg.server.conntrack_control).unwrap()["inline_conntrack_control"],
        false,
    );
}

#[test]
fn conntrack_control_preserves_explicit_enablement() {
    for enabled in [false, true] {
        let cfg = load_config_from_temp_toml(&format!(
            r#"
            [server.conntrack_control]
            inline_conntrack_control = {enabled}
            backend = "nftables"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
            "#,
        ));
        assert_eq!(
            cfg.server.conntrack_control.inline_conntrack_control,
            enabled
        );
        assert!(
            cfg.server
                .conntrack_control
                .inline_conntrack_control_explicit
        );
        assert_eq!(
            cfg.server.conntrack_control.backend,
            ConntrackBackend::Nftables
        );
        assert_eq!(
            serde_json::to_value(&cfg.server.conntrack_control).unwrap()["inline_conntrack_control"],
            enabled,
        );
    }
}

#[test]
fn conntrack_pressure_high_watermark_out_of_range_is_rejected() {
    let toml = r#"
        [server.conntrack_control]
        pressure_high_watermark_pct = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_conntrack_high_watermark_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(
        err.contains(
            "server.conntrack_control.pressure_high_watermark_pct must be within [1, 100]"
        )
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn conntrack_pressure_low_watermark_must_be_below_high() {
    let toml = r#"
        [server.conntrack_control]
        pressure_high_watermark_pct = 50
        pressure_low_watermark_pct = 50

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_conntrack_low_watermark_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains(
        "server.conntrack_control.pressure_low_watermark_pct must be < pressure_high_watermark_pct"
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn conntrack_delete_budget_zero_is_rejected() {
    let toml = r#"
        [server.conntrack_control]
        delete_budget_per_sec = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_conntrack_delete_budget_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("server.conntrack_control.delete_budget_per_sec must be > 0"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn conntrack_hybrid_mode_requires_listener_allow_list() {
    let toml = r#"
        [server.conntrack_control]
        mode = "hybrid"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_conntrack_hybrid_requires_ips_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(
        err.contains(
            "server.conntrack_control.hybrid_listener_ips must be non-empty in mode=hybrid"
        )
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn conntrack_profile_is_loaded_from_config() {
    let toml = r#"
        [server.conntrack_control]
        profile = "aggressive"

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_conntrack_profile_parse_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(
        cfg.server.conntrack_control.profile,
        ConntrackPressureProfile::Aggressive
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn force_close_default_matches_drain_ttl() {
    let toml = r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_force_close_default_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 90);
    assert_eq!(cfg.general.effective_me_pool_force_close_secs(), 90);
    let _ = std::fs::remove_file(path);
}

#[test]
fn force_close_zero_uses_runtime_safety_fallback() {
    let toml = r#"
        [general]
        me_reinit_drain_timeout_secs = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_force_close_zero_fallback_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 0);
    assert_eq!(cfg.general.effective_me_pool_force_close_secs(), 300);
    let _ = std::fs::remove_file(path);
}

#[test]
fn force_close_bumped_when_below_drain_ttl() {
    let toml = r#"
        [general]
        me_pool_drain_ttl_secs = 90
        me_reinit_drain_timeout_secs = 30

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_force_close_bump_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.me_reinit_drain_timeout_secs, 90);
    let _ = std::fs::remove_file(path);
}

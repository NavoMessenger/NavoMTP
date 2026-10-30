use super::*;

#[test]
fn proxy_protocol_trusted_cidrs_missing_uses_trust_all_but_explicit_empty_stays_empty() {
    let cfg_missing: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg_missing.server.proxy_protocol_trusted_cidrs,
        default_proxy_protocol_trusted_cidrs()
    );

    let cfg_explicit_empty: ProxyConfig = toml::from_str(
        r#"
        [server]
        proxy_protocol_trusted_cidrs = []

        [general]
        [network]
        [access]
        "#,
    )
    .unwrap();
    assert!(
        cfg_explicit_empty
            .server
            .proxy_protocol_trusted_cidrs
            .is_empty()
    );
}

#[test]
fn conntrack_inline_explicit_flag_is_false_when_omitted() {
    let cfg = load_config_from_temp_toml(
        r#"
        [general]
        [network]
        [server]
        [server.conntrack_control]
        [access]
        "#,
    );
    assert!(
        !cfg.server
            .conntrack_control
            .inline_conntrack_control_explicit
    );
}

#[test]
fn conntrack_inline_explicit_flag_is_true_when_present() {
    let cfg = load_config_from_temp_toml(
        r#"
        [general]
        [network]
        [server]
        [server.conntrack_control]
        inline_conntrack_control = true
        [access]
        "#,
    );
    assert!(
        cfg.server
            .conntrack_control
            .inline_conntrack_control_explicit
    );
}

#[test]
fn unknown_sni_action_parses_and_defaults_to_drop() {
    let cfg_default: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [censorship]
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg_default.censorship.unknown_sni_action,
        UnknownSniAction::Drop
    );

    let cfg_mask: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [censorship]
        unknown_sni_action = "mask"
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg_mask.censorship.unknown_sni_action,
        UnknownSniAction::Mask
    );

    let cfg_accept: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [censorship]
        unknown_sni_action = "accept"
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg_accept.censorship.unknown_sni_action,
        UnknownSniAction::Accept
    );

    let cfg_reject: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [censorship]
        unknown_sni_action = "reject_handshake"
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg_reject.censorship.unknown_sni_action,
        UnknownSniAction::RejectHandshake
    );
}

#[test]
fn exclusive_mask_parses_domain_target_map() {
    let cfg = load_config_from_temp_toml(
        r#"
        [general]
        [network]
        [server]
        [access]
        [censorship]
        tls_domain = "weißbiergärten.de"
        tls_domains = ["bürgeramt.de"]
        [censorship.exclusive_mask]
        "bürgeramt.de" = "rindfleischetikettierungsüberwachungsaufgabenübertragungsgesetz.de:443"
        "ipv6.example" = "[::1]:443"
        "#,
    );

    assert!(cfg.censorship.tls_domain.is_ascii());
    assert!(cfg.censorship.tls_domain.contains("xn--"));
    assert_eq!(cfg.censorship.tls_domains.len(), 1);
    let normalized_extra = &cfg.censorship.tls_domains[0];
    assert!(normalized_extra.is_ascii());
    assert!(normalized_extra.contains("xn--"));

    let normalized_target = cfg
        .censorship
        .exclusive_mask
        .get(normalized_extra)
        .expect("exclusive_mask key must match normalized tls_domains entry");
    assert!(normalized_target.is_ascii());
    assert!(normalized_target.contains("xn--"));
    assert!(normalized_target.ends_with(":443"));
    assert_eq!(
        cfg.censorship.exclusive_mask.get("ipv6.example"),
        Some(&"[::1]:443".to_string())
    );
}

#[test]
fn api_gray_action_parses_and_defaults_to_drop() {
    let cfg_default: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        "#,
    )
    .unwrap();
    assert_eq!(cfg_default.server.api.gray_action, ApiGrayAction::Drop);

    let cfg_api: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [server.api]
        gray_action = "api"
        "#,
    )
    .unwrap();
    assert_eq!(cfg_api.server.api.gray_action, ApiGrayAction::Api);

    let cfg_200: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [server.api]
        gray_action = "200"
        "#,
    )
    .unwrap();
    assert_eq!(cfg_200.server.api.gray_action, ApiGrayAction::Ok200);

    let cfg_drop: ProxyConfig = toml::from_str(
        r#"
        [server]
        [general]
        [network]
        [access]
        [server.api]
        gray_action = "drop"
        "#,
    )
    .unwrap();
    assert_eq!(cfg_drop.server.api.gray_action, ApiGrayAction::Drop);
}

#[test]
fn top_level_beobachten_keys_migrate_to_general_when_general_not_explicit() {
    let cfg = load_config_from_temp_toml(
        r#"
        beobachten = false
        beobachten_minutes = 7
        beobachten_flush_secs = 3
        beobachten_file = "tmp/legacy-beob.txt"

        [server]
        [general]
        [network]
        [access]
        "#,
    );

    assert!(!cfg.general.beobachten);
    assert_eq!(cfg.general.beobachten_minutes, 7);
    assert_eq!(cfg.general.beobachten_flush_secs, 3);
    assert_eq!(cfg.general.beobachten_file, "tmp/legacy-beob.txt");
}

#[test]
fn general_beobachten_keys_have_priority_over_legacy_top_level() {
    let cfg = load_config_from_temp_toml(
        r#"
        beobachten = true
        beobachten_minutes = 30
        beobachten_flush_secs = 30
        beobachten_file = "tmp/legacy-beob.txt"

        [server]
        [general]
        beobachten = false
        beobachten_minutes = 5
        beobachten_flush_secs = 2
        beobachten_file = "tmp/general-beob.txt"
        [network]
        [access]
        "#,
    );

    assert!(!cfg.general.beobachten);
    assert_eq!(cfg.general.beobachten_minutes, 5);
    assert_eq!(cfg.general.beobachten_flush_secs, 2);
    assert_eq!(cfg.general.beobachten_file, "tmp/general-beob.txt");
}

#[test]
fn dc_overrides_allow_string_and_array() {
    let toml = r#"
        [dc_overrides]
        "201" = "149.154.175.50:443"
        "202" = ["149.154.167.51:443", "149.154.175.100:443"]
    "#;
    let cfg: ProxyConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.dc_overrides["201"], vec!["149.154.175.50:443"]);
    assert_eq!(
        cfg.dc_overrides["202"],
        vec!["149.154.167.51:443", "149.154.175.100:443"]
    );
}

#[test]
fn load_with_metadata_collects_include_files() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("telemt_load_metadata_{nonce}"));
    std::fs::create_dir_all(&dir).unwrap();
    let main_path = dir.join("config.toml");
    let include_path = dir.join("included.toml");

    std::fs::write(
        &include_path,
        r#"
            [access.users]
            user = "00000000000000000000000000000000"
        "#,
    )
    .unwrap();
    std::fs::write(
        &main_path,
        r#"
            include = "included.toml"

            [censorship]
            tls_domain = "example.com"
        "#,
    )
    .unwrap();

    let loaded = ProxyConfig::load_with_metadata(&main_path).unwrap();
    let main_normalized = normalize_config_path(&main_path);
    let include_normalized = normalize_config_path(&include_path);

    assert!(loaded.source_files.contains(&main_normalized));
    assert!(loaded.source_files.contains(&include_normalized));

    let _ = std::fs::remove_file(main_path);
    let _ = std::fs::remove_file(include_path);
    let _ = std::fs::remove_dir(dir);
}

#[test]
fn dc_overrides_inject_dc203_default() {
    let toml = r#"
        [general]
        use_middle_proxy = false

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_dc_override_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert!(
        cfg.dc_overrides
            .get("203")
            .map(|v| v.contains(&"91.105.192.100:443".to_string()))
            .unwrap_or(false)
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn update_every_overrides_legacy_fields() {
    let toml = r#"
        [general]
        update_every = 123
        proxy_secret_auto_reload_secs = 700
        proxy_config_auto_reload_secs = 800

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_update_every_override_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.effective_update_every_secs(), 123);
    let _ = std::fs::remove_file(path);
}

#[test]
fn update_every_fallback_to_legacy_min() {
    let toml = r#"
        [general]
        proxy_secret_auto_reload_secs = 600
        proxy_config_auto_reload_secs = 120

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_update_every_legacy_min_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.general.update_every, None);
    assert_eq!(cfg.general.effective_update_every_secs(), 120);
    let _ = std::fs::remove_file(path);
}

#[test]
fn update_every_zero_is_rejected() {
    let toml = r#"
        [general]
        update_every = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_update_every_zero_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("general.update_every must be > 0"));
    let _ = std::fs::remove_file(path);
}

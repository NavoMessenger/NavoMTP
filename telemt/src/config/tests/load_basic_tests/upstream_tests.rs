use super::*;

#[test]
fn shadowsocks_upstream_url_loads_successfully() {
    let toml = format!(
        r#"
        [general]
        use_middle_proxy = false

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"

        [[upstreams]]
        type = "shadowsocks"
        url = "{url}"
        interface = "127.0.0.2"
        "#,
        url = TEST_SHADOWSOCKS_URL,
    );
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_shadowsocks_valid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();

    assert!(matches!(
        &cfg.upstreams[0].upstream_type,
        UpstreamType::Shadowsocks { url, interface }
            if url == TEST_SHADOWSOCKS_URL && interface.as_deref() == Some("127.0.0.2")
    ));

    let _ = std::fs::remove_file(path);
}

#[test]
fn shadowsocks_requires_direct_mode() {
    let toml = format!(
        r#"
        [general]
        use_middle_proxy = true

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"

        [[upstreams]]
        type = "shadowsocks"
        url = "{url}"
        "#,
        url = TEST_SHADOWSOCKS_URL,
    );
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_shadowsocks_me_reject_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("shadowsocks upstreams require general.use_middle_proxy = false"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn invalid_shadowsocks_url_is_rejected() {
    let toml = r#"
        [general]
        use_middle_proxy = false

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"

        [[upstreams]]
        type = "shadowsocks"
        url = "not-a-valid-ss-url"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_shadowsocks_invalid_url_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("invalid shadowsocks url"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn shadowsocks_plugins_are_rejected() {
    let toml = format!(
        r#"
        [general]
        use_middle_proxy = false

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"

        [[upstreams]]
        type = "shadowsocks"
        url = "{url}?plugin=obfs-local%3Bobfs%3Dhttp"
        "#,
        url = TEST_SHADOWSOCKS_URL,
    );
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_shadowsocks_plugin_reject_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(err.contains("shadowsocks plugins are not supported"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn invalid_user_ad_tag_reports_access_user_ad_tags_key() {
    let toml = r#"
        [censorship]
        tls_domain = "example.com"

        [access.users]
        alice = "00000000000000000000000000000000"

        [access.user_ad_tags]
        alice = "not_hex"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_invalid_user_ad_tag_message_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("access.user_ad_tags['alice'] must be exactly 32 hex characters"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn invalid_dns_override_is_rejected() {
    let toml = r#"
        [network]
        dns_overrides = ["example.com:443:2001:db8::10"]

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_invalid_dns_override_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("must be bracketed"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn valid_dns_override_is_accepted() {
    let toml = r#"
        [network]
        dns_overrides = ["example.com:443:127.0.0.1", "example.net:443:[2001:db8::10]"]

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_valid_dns_override_test.toml");
    std::fs::write(&path, toml).unwrap();
    let cfg = ProxyConfig::load(&path).unwrap();
    assert_eq!(cfg.network.dns_overrides.len(), 2);
    let _ = std::fs::remove_file(path);
}

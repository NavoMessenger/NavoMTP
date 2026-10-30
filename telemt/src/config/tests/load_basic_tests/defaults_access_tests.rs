use super::*;

#[test]
fn serde_defaults_remain_unchanged_for_present_sections() {
    let toml = r#"
        [network]
        [general]
        [server]
        [access]
    "#;
    let cfg: ProxyConfig = toml::from_str(toml).unwrap();

    assert_eq!(cfg.logging, LoggingConfig::default());
    assert_eq!(cfg.network.ipv6, default_network_ipv6());
    assert_eq!(cfg.network.stun_use, default_true());
    assert_eq!(cfg.network.stun_tcp_fallback, default_stun_tcp_fallback());
    assert_eq!(
        cfg.general.middle_proxy_warm_standby,
        default_middle_proxy_warm_standby()
    );
    assert_eq!(
        cfg.general.me_reconnect_max_concurrent_per_dc,
        default_me_reconnect_max_concurrent_per_dc()
    );
    assert_eq!(
        cfg.general.me_reconnect_fast_retry_count,
        default_me_reconnect_fast_retry_count()
    );
    assert_eq!(
        cfg.general.me_init_retry_attempts,
        default_me_init_retry_attempts()
    );
    assert_eq!(cfg.general.me2dc_fallback, default_me2dc_fallback());
    assert_eq!(cfg.general.me2dc_fast, default_me2dc_fast());
    assert_eq!(
        cfg.general.proxy_config_v4_cache_path,
        default_proxy_config_v4_cache_path()
    );
    assert_eq!(
        cfg.general.proxy_config_v6_cache_path,
        default_proxy_config_v6_cache_path()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_shadow_writers,
        default_me_single_endpoint_shadow_writers()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_outage_mode_enabled,
        default_me_single_endpoint_outage_mode_enabled()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_outage_disable_quarantine,
        default_me_single_endpoint_outage_disable_quarantine()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_outage_backoff_min_ms,
        default_me_single_endpoint_outage_backoff_min_ms()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_outage_backoff_max_ms,
        default_me_single_endpoint_outage_backoff_max_ms()
    );
    assert_eq!(
        cfg.general.me_single_endpoint_shadow_rotate_every_secs,
        default_me_single_endpoint_shadow_rotate_every_secs()
    );
    assert_eq!(cfg.general.me_floor_mode, MeFloorMode::default());
    assert_eq!(
        cfg.general.me_adaptive_floor_idle_secs,
        default_me_adaptive_floor_idle_secs()
    );
    assert_eq!(
        cfg.general.me_adaptive_floor_min_writers_single_endpoint,
        default_me_adaptive_floor_min_writers_single_endpoint()
    );
    assert_eq!(
        cfg.general.me_adaptive_floor_recover_grace_secs,
        default_me_adaptive_floor_recover_grace_secs()
    );
    assert_eq!(
        cfg.general.upstream_connect_retry_attempts,
        default_upstream_connect_retry_attempts()
    );
    assert_eq!(
        cfg.general.upstream_connect_retry_backoff_ms,
        default_upstream_connect_retry_backoff_ms()
    );
    assert_eq!(
        cfg.general.upstream_unhealthy_fail_threshold,
        default_upstream_unhealthy_fail_threshold()
    );
    assert_eq!(
        cfg.general.upstream_connect_failfast_hard_errors,
        default_upstream_connect_failfast_hard_errors()
    );
    assert_eq!(
        cfg.general.rpc_proxy_req_every,
        default_rpc_proxy_req_every()
    );
    assert_eq!(cfg.general.beobachten_file, default_beobachten_file());
    assert_eq!(cfg.general.update_every, default_update_every());
    assert_eq!(cfg.server.listen_addr_ipv4, default_listen_addr_ipv4());
    assert_eq!(cfg.server.listen_addr_ipv6, default_listen_addr_ipv6_opt());
    assert_eq!(cfg.server.client_mss_value(), Ok(None));
    assert_eq!(
        cfg.server.proxy_protocol_trusted_cidrs,
        default_proxy_protocol_trusted_cidrs()
    );
    assert_eq!(cfg.censorship.unknown_sni_action, UnknownSniAction::Drop);
    assert_eq!(cfg.server.api.listen, default_api_listen());
    assert_eq!(cfg.server.api.whitelist, default_api_whitelist());
    assert_eq!(cfg.server.api.gray_action, ApiGrayAction::Drop);
    assert_eq!(
        cfg.server.api.request_body_limit_bytes,
        default_api_request_body_limit_bytes()
    );
    assert_eq!(
        cfg.server.api.minimal_runtime_enabled,
        default_api_minimal_runtime_enabled()
    );
    assert_eq!(
        cfg.server.api.minimal_runtime_cache_ttl_ms,
        default_api_minimal_runtime_cache_ttl_ms()
    );
    assert_eq!(
        cfg.server.api.runtime_edge_enabled,
        default_api_runtime_edge_enabled()
    );
    assert_eq!(
        cfg.server.api.runtime_edge_cache_ttl_ms,
        default_api_runtime_edge_cache_ttl_ms()
    );
    assert_eq!(
        cfg.server.api.runtime_edge_top_n,
        default_api_runtime_edge_top_n()
    );
    assert_eq!(
        cfg.server.api.runtime_edge_events_capacity,
        default_api_runtime_edge_events_capacity()
    );
    assert_eq!(
        cfg.server.conntrack_control.inline_conntrack_control,
        default_conntrack_control_enabled()
    );
    assert_eq!(cfg.server.conntrack_control.mode, ConntrackMode::default());
    assert_eq!(
        cfg.server.conntrack_control.backend,
        ConntrackBackend::default()
    );
    assert_eq!(
        cfg.server.conntrack_control.profile,
        ConntrackPressureProfile::default()
    );
    assert_eq!(
        cfg.server.conntrack_control.pressure_high_watermark_pct,
        default_conntrack_pressure_high_watermark_pct()
    );
    assert_eq!(
        cfg.server.conntrack_control.pressure_low_watermark_pct,
        default_conntrack_pressure_low_watermark_pct()
    );
    assert_eq!(
        cfg.server.conntrack_control.delete_budget_per_sec,
        default_conntrack_delete_budget_per_sec()
    );
    assert_eq!(cfg.access.users, default_access_users());
    assert_eq!(
        cfg.access.user_max_tcp_conns_global_each,
        default_user_max_tcp_conns_global_each()
    );
    assert_eq!(
        cfg.access.user_max_unique_ips_mode,
        UserMaxUniqueIpsMode::default()
    );
    assert_eq!(
        cfg.access.user_max_unique_ips_window_secs,
        default_user_max_unique_ips_window_secs()
    );
}

#[test]
fn logging_config_is_loaded_from_strict_config() {
    let cfg = load_config_from_temp_toml(
        r#"
            [general]
            config_strict = true

            [general.modes]
            classic = false
            secure = false
            tls = true

            [logging]
            destination = "file"
            path = "/tmp/telemt.log"
            rotation = "daily"
            max_size_bytes = 1024
            max_files = 3
            max_age_secs = 60

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#,
    );

    assert_eq!(cfg.logging.destination, LoggingDestination::File);
    assert_eq!(cfg.logging.path.as_deref(), Some("/tmp/telemt.log"));
    assert_eq!(cfg.logging.rotation, LogRotation::Daily);
    assert_eq!(cfg.logging.max_size_bytes, 1024);
    assert_eq!(cfg.logging.max_files, 3);
    assert_eq!(cfg.logging.max_age_secs, 60);
}

#[test]
fn cidr_rate_limits_accept_auto_templates_in_strict_config() {
    let cfg = load_config_from_temp_toml(
        r#"
            [general]
            config_strict = true

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*/24" = { up_bps = 1024, down_bps = 0 }
            "*4/30" = { up_bps = 0, down_bps = 2048 }
            "*6/64" = { up_bps = 4096, down_bps = 0 }
        "#,
    );

    assert!(
        cfg.access
            .cidr_rate_limits
            .contains_key(&CidrRateLimitKey::AutoDual(24))
    );
    assert!(
        cfg.access
            .cidr_rate_limits
            .contains_key(&CidrRateLimitKey::AutoV4(30))
    );
    assert!(
        cfg.access
            .cidr_rate_limits
            .contains_key(&CidrRateLimitKey::AutoV6(64))
    );
}

#[test]
fn cidr_rate_limits_reject_invalid_auto_template_prefix() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*4/33" = { up_bps = 1024, down_bps = 0 }
        "#,
    );

    assert!(error.contains("prefix must be within 0..=32"));
}

#[test]
fn cidr_rate_limits_reject_duplicate_normalized_auto_templates() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "*/32" = { up_bps = 1024, down_bps = 0 }
            "*6/128" = { up_bps = 2048, down_bps = 0 }
        "#,
    );

    assert!(error.contains("duplicates normalized auto-template *6/128"));
}

#[test]
fn rate_limits_accept_the_packed_counter_maximum() {
    let cfg = load_config_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.user_rate_limits]
            user = { up_bps = 100000000000, down_bps = 0 }

            [access.cidr_rate_limits]
            "203.0.113.0/24" = { up_bps = 0, down_bps = 100000000000 }
        "#,
    );

    assert_eq!(cfg.access.user_rate_limits["user"].up_bps, 100_000_000_000);
    assert_eq!(
        cfg.access.cidr_rate_limits[&CidrRateLimitKey::Network("203.0.113.0/24".parse().unwrap())]
            .down_bps,
        100_000_000_000
    );
}

#[test]
fn user_rate_limits_reject_values_above_the_packed_counter_maximum() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.user_rate_limits]
            user = { up_bps = 100000000001, down_bps = 0 }
        "#,
    );

    assert!(error.contains("access.user_rate_limits.user.up_bps must be within"));
}

#[test]
fn cidr_rate_limits_reject_values_above_the_packed_counter_maximum() {
    let error = load_config_error_from_temp_toml(
        r#"
            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"

            [access.cidr_rate_limits]
            "203.0.113.0/24" = { up_bps = 0, down_bps = 100000000001 }
        "#,
    );

    assert!(error.contains("access.cidr_rate_limits.203.0.113.0/24.down_bps must be within"));
}

#[test]
fn file_logging_requires_path() {
    let error = load_config_error_from_temp_toml(
        r#"
            [general.modes]
            classic = false
            secure = false
            tls = true

            [logging]
            destination = "file"

            [censorship]
            tls_domain = "example.com"

            [access.users]
            user = "00000000000000000000000000000000"
        "#,
    );

    assert!(error.contains("logging.path must be set"));
}

#[test]
fn impl_defaults_are_sourced_from_default_helpers() {
    let network = NetworkConfig::default();
    assert_eq!(network.ipv6, default_network_ipv6());
    assert_eq!(network.stun_use, default_true());
    assert_eq!(network.stun_tcp_fallback, default_stun_tcp_fallback());

    let general = GeneralConfig::default();
    assert_eq!(
        general.middle_proxy_warm_standby,
        default_middle_proxy_warm_standby()
    );
    assert_eq!(
        general.me_reconnect_max_concurrent_per_dc,
        default_me_reconnect_max_concurrent_per_dc()
    );
    assert_eq!(
        general.me_reconnect_fast_retry_count,
        default_me_reconnect_fast_retry_count()
    );
    assert_eq!(
        general.me_init_retry_attempts,
        default_me_init_retry_attempts()
    );
    assert_eq!(general.me2dc_fallback, default_me2dc_fallback());
    assert_eq!(general.me2dc_fast, default_me2dc_fast());
    assert_eq!(
        general.proxy_config_v4_cache_path,
        default_proxy_config_v4_cache_path()
    );
    assert_eq!(
        general.proxy_config_v6_cache_path,
        default_proxy_config_v6_cache_path()
    );
    assert_eq!(
        general.me_single_endpoint_shadow_writers,
        default_me_single_endpoint_shadow_writers()
    );
    assert_eq!(
        general.me_single_endpoint_outage_mode_enabled,
        default_me_single_endpoint_outage_mode_enabled()
    );
    assert_eq!(
        general.me_single_endpoint_outage_disable_quarantine,
        default_me_single_endpoint_outage_disable_quarantine()
    );
    assert_eq!(
        general.me_single_endpoint_outage_backoff_min_ms,
        default_me_single_endpoint_outage_backoff_min_ms()
    );
    assert_eq!(
        general.me_single_endpoint_outage_backoff_max_ms,
        default_me_single_endpoint_outage_backoff_max_ms()
    );
    assert_eq!(
        general.me_single_endpoint_shadow_rotate_every_secs,
        default_me_single_endpoint_shadow_rotate_every_secs()
    );
    assert_eq!(general.me_floor_mode, MeFloorMode::default());
    assert_eq!(
        general.me_adaptive_floor_idle_secs,
        default_me_adaptive_floor_idle_secs()
    );
    assert_eq!(
        general.me_adaptive_floor_min_writers_single_endpoint,
        default_me_adaptive_floor_min_writers_single_endpoint()
    );
    assert_eq!(
        general.me_adaptive_floor_recover_grace_secs,
        default_me_adaptive_floor_recover_grace_secs()
    );
    assert_eq!(
        general.upstream_connect_retry_attempts,
        default_upstream_connect_retry_attempts()
    );
    assert_eq!(
        general.upstream_connect_retry_backoff_ms,
        default_upstream_connect_retry_backoff_ms()
    );
    assert_eq!(
        general.upstream_unhealthy_fail_threshold,
        default_upstream_unhealthy_fail_threshold()
    );
    assert_eq!(
        general.upstream_connect_failfast_hard_errors,
        default_upstream_connect_failfast_hard_errors()
    );
    assert_eq!(general.rpc_proxy_req_every, default_rpc_proxy_req_every());
    assert_eq!(general.beobachten_file, default_beobachten_file());
    assert_eq!(general.update_every, default_update_every());

    let server = ServerConfig::default();
    assert_eq!(server.listen_addr_ipv6, Some(default_listen_addr_ipv6()));
    assert_eq!(
        server.proxy_protocol_trusted_cidrs,
        default_proxy_protocol_trusted_cidrs()
    );
    assert_eq!(
        AntiCensorshipConfig::default().unknown_sni_action,
        UnknownSniAction::Drop
    );
    assert_eq!(server.api.listen, default_api_listen());
    assert_eq!(server.api.whitelist, default_api_whitelist());
    assert_eq!(server.api.gray_action, ApiGrayAction::Drop);
    assert_eq!(
        server.api.request_body_limit_bytes,
        default_api_request_body_limit_bytes()
    );
    assert_eq!(
        server.api.minimal_runtime_enabled,
        default_api_minimal_runtime_enabled()
    );
    assert_eq!(
        server.api.minimal_runtime_cache_ttl_ms,
        default_api_minimal_runtime_cache_ttl_ms()
    );
    assert_eq!(
        server.api.runtime_edge_enabled,
        default_api_runtime_edge_enabled()
    );
    assert_eq!(
        server.api.runtime_edge_cache_ttl_ms,
        default_api_runtime_edge_cache_ttl_ms()
    );
    assert_eq!(
        server.api.runtime_edge_top_n,
        default_api_runtime_edge_top_n()
    );
    assert_eq!(
        server.api.runtime_edge_events_capacity,
        default_api_runtime_edge_events_capacity()
    );
    assert_eq!(
        server.conntrack_control.inline_conntrack_control,
        default_conntrack_control_enabled()
    );
    assert_eq!(server.conntrack_control.mode, ConntrackMode::default());
    assert_eq!(
        server.conntrack_control.backend,
        ConntrackBackend::default()
    );
    assert_eq!(
        server.conntrack_control.profile,
        ConntrackPressureProfile::default()
    );
    assert_eq!(
        server.conntrack_control.pressure_high_watermark_pct,
        default_conntrack_pressure_high_watermark_pct()
    );
    assert_eq!(
        server.conntrack_control.pressure_low_watermark_pct,
        default_conntrack_pressure_low_watermark_pct()
    );
    assert_eq!(
        server.conntrack_control.delete_budget_per_sec,
        default_conntrack_delete_budget_per_sec()
    );

    let access = AccessConfig::default();
    assert_eq!(access.users, default_access_users());
    assert_eq!(
        access.user_max_tcp_conns_global_each,
        default_user_max_tcp_conns_global_each()
    );
}

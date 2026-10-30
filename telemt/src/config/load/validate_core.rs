use super::*;

pub(super) fn validate(config: &mut ProxyConfig) -> Result<()> {
    if let Some(path) = &config.general.proxy_config_v4_cache_path
        && path.trim().is_empty()
    {
        return Err(ProxyError::Config(
            "general.proxy_config_v4_cache_path cannot be empty when provided".to_string(),
        ));
    }

    if let Some(path) = &config.general.proxy_config_v6_cache_path
        && path.trim().is_empty()
    {
        return Err(ProxyError::Config(
            "general.proxy_config_v6_cache_path cannot be empty when provided".to_string(),
        ));
    }

    if let Some(update_every) = config.general.update_every {
        if update_every == 0 {
            return Err(ProxyError::Config(
                "general.update_every must be > 0".to_string(),
            ));
        }
    } else {
        let legacy_secret = config.general.proxy_secret_auto_reload_secs;
        let legacy_config = config.general.proxy_config_auto_reload_secs;
        let effective = legacy_secret.min(legacy_config);
        if effective == 0 {
            return Err(ProxyError::Config(
                "legacy proxy_*_auto_reload_secs values must be > 0 when general.update_every is not set".to_string(),
            ));
        }

        if legacy_secret != default_proxy_secret_reload_secs()
            || legacy_config != default_proxy_config_reload_secs()
        {
            warn!(
                proxy_secret_auto_reload_secs = legacy_secret,
                proxy_config_auto_reload_secs = legacy_config,
                effective_update_every_secs = effective,
                "proxy_*_auto_reload_secs are deprecated; set general.update_every"
            );
        }
    }

    if config.general.stun_nat_probe_concurrency == 0 {
        return Err(ProxyError::Config(
            "general.stun_nat_probe_concurrency must be > 0".to_string(),
        ));
    }

    if config.general.me_init_retry_attempts > 1_000_000 {
        return Err(ProxyError::Config(
            "general.me_init_retry_attempts must be within [0, 1000000]".to_string(),
        ));
    }

    if config.general.upstream_connect_retry_attempts == 0 {
        return Err(ProxyError::Config(
            "general.upstream_connect_retry_attempts must be > 0".to_string(),
        ));
    }

    if config.general.upstream_connect_budget_ms == 0 {
        return Err(ProxyError::Config(
            "general.upstream_connect_budget_ms must be > 0".to_string(),
        ));
    }

    if config.general.tg_connect == 0 {
        return Err(ProxyError::Config(
            "general.tg_connect must be > 0".to_string(),
        ));
    }

    if config.general.upstream_unhealthy_fail_threshold == 0 {
        return Err(ProxyError::Config(
            "general.upstream_unhealthy_fail_threshold must be > 0".to_string(),
        ));
    }

    if config.general.rpc_proxy_req_every != 0
        && !(10..=300).contains(&config.general.rpc_proxy_req_every)
    {
        return Err(ProxyError::Config(
            "general.rpc_proxy_req_every must be 0 or within [10, 300]".to_string(),
        ));
    }

    if config.timeouts.client_handshake == 0 {
        return Err(ProxyError::Config(
            "timeouts.client_handshake must be > 0".to_string(),
        ));
    }

    let handshake_timeout_ms = config
        .timeouts
        .client_handshake
        .checked_mul(1000)
        .ok_or_else(|| {
            ProxyError::Config(
                "timeouts.client_handshake is too large to validate milliseconds budget"
                    .to_string(),
            )
        })?;

    if config.censorship.server_hello_delay_max_ms >= handshake_timeout_ms {
        return Err(ProxyError::Config(
            "censorship.server_hello_delay_max_ms must be < timeouts.client_handshake * 1000"
                .to_string(),
        ));
    }

    if config.censorship.mask_shape_bucket_floor_bytes == 0 {
        return Err(ProxyError::Config(
            "censorship.mask_shape_bucket_floor_bytes must be > 0".to_string(),
        ));
    }

    if config.censorship.mask_shape_bucket_cap_bytes
        < config.censorship.mask_shape_bucket_floor_bytes
    {
        return Err(ProxyError::Config(
            "censorship.mask_shape_bucket_cap_bytes must be >= censorship.mask_shape_bucket_floor_bytes"
                .to_string(),
        ));
    }

    if config.censorship.mask_shape_above_cap_blur && !config.censorship.mask_shape_hardening {
        return Err(ProxyError::Config(
            "censorship.mask_shape_above_cap_blur requires censorship.mask_shape_hardening = true"
                .to_string(),
        ));
    }

    if config.censorship.mask_shape_hardening_aggressive_mode
        && !config.censorship.mask_shape_hardening
    {
        return Err(ProxyError::Config(
            "censorship.mask_shape_hardening_aggressive_mode requires censorship.mask_shape_hardening = true"
                .to_string(),
        ));
    }

    if config.censorship.mask_shape_above_cap_blur
        && config.censorship.mask_shape_above_cap_blur_max_bytes == 0
    {
        return Err(ProxyError::Config(
            "censorship.mask_shape_above_cap_blur_max_bytes must be > 0 when censorship.mask_shape_above_cap_blur is enabled"
                .to_string(),
        ));
    }

    if config.censorship.mask_shape_above_cap_blur_max_bytes > 1_048_576 {
        return Err(ProxyError::Config(
            "censorship.mask_shape_above_cap_blur_max_bytes must be <= 1048576".to_string(),
        ));
    }

    if config.censorship.mask_relay_max_bytes > 67_108_864 {
        return Err(ProxyError::Config(
            "censorship.mask_relay_max_bytes must be <= 67108864".to_string(),
        ));
    }

    if !(5..=50).contains(&config.censorship.mask_classifier_prefetch_timeout_ms) {
        return Err(ProxyError::Config(
            "censorship.mask_classifier_prefetch_timeout_ms must be within [5, 50]".to_string(),
        ));
    }

    if config.censorship.mask_timing_normalization_ceiling_ms
        < config.censorship.mask_timing_normalization_floor_ms
    {
        return Err(ProxyError::Config(
            "censorship.mask_timing_normalization_ceiling_ms must be >= censorship.mask_timing_normalization_floor_ms"
                .to_string(),
        ));
    }

    if config.censorship.mask_timing_normalization_enabled
        && config.censorship.mask_timing_normalization_floor_ms == 0
    {
        return Err(ProxyError::Config(
            "censorship.mask_timing_normalization_floor_ms must be > 0 when censorship.mask_timing_normalization_enabled is true"
                .to_string(),
        ));
    }

    if config.censorship.mask_timing_normalization_ceiling_ms > 60_000 {
        return Err(ProxyError::Config(
            "censorship.mask_timing_normalization_ceiling_ms must be <= 60000".to_string(),
        ));
    }

    if config.timeouts.relay_client_idle_soft_secs == 0 {
        return Err(ProxyError::Config(
            "timeouts.relay_client_idle_soft_secs must be > 0".to_string(),
        ));
    }

    if config.timeouts.relay_client_idle_hard_secs == 0 {
        return Err(ProxyError::Config(
            "timeouts.relay_client_idle_hard_secs must be > 0".to_string(),
        ));
    }

    if config.timeouts.relay_client_idle_hard_secs < config.timeouts.relay_client_idle_soft_secs {
        return Err(ProxyError::Config(
            "timeouts.relay_client_idle_hard_secs must be >= timeouts.relay_client_idle_soft_secs"
                .to_string(),
        ));
    }

    if config
        .timeouts
        .relay_idle_grace_after_downstream_activity_secs
        > config.timeouts.relay_client_idle_hard_secs
    {
        return Err(ProxyError::Config(
            "timeouts.relay_idle_grace_after_downstream_activity_secs must be <= timeouts.relay_client_idle_hard_secs"
                .to_string(),
        ));
    }
    Ok(())
}

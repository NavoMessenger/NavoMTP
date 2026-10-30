use super::*;

/// Restart-only differences must not enqueue another DNS preparation after activation.
pub(super) fn source_matches_active(
    active: &ProxyConfig,
    source: &crate::config::ParsedConfigSource,
) -> bool {
    config_equal(active, &overlay_hot_fields(active, &source.config))
}

/// Reads only source state; watcher initialization and unchanged events never need DNS.
pub(super) async fn read_source(path: &PathBuf) -> Option<crate::config::ParsedConfigSource> {
    let path = path.clone();
    match tokio::task::spawn_blocking(move || ProxyConfig::parse_source(path)).await {
        Ok(Ok(source)) => Some(source),
        Ok(Err(error)) => {
            error!("config reload: failed to parse: {}", error);
            None
        }
        Err(error) => {
            error!("config reload: source reader failed: {}", error);
            None
        }
    }
}

/// Prepares fresh evidence only for changed sources or an explicit reload request.
pub(super) async fn reload(
    path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
    dns_resolver: Option<Arc<crate::network::dns_overrides::GenerationDnsResolver>>,
    force: bool,
) -> Option<WatchManifest> {
    let source = read_source(path).await?;
    let manifest = WatchManifest::from_source_files(&source.source_files);
    if !force && reload_state.is_applied(source.rendered_hash) {
        return Some(manifest);
    }
    let loaded = match source.prepare().await {
        Ok(loaded) => loaded,
        Err(error) => {
            error!(
                "config reload: preparation failed: {}; keeping old config",
                error
            );
            return Some(manifest);
        }
    };
    let old = config_tx.borrow().clone();
    // Static-site reconstruction after the listener overlay must not block Tokio workers.
    // The worker only builds data: cancellation cannot leave a detached publisher behind.
    let result = tokio::task::spawn_blocking(move || {
        prepare_effective_config(&old, &loaded.config).map(|applied| (loaded, applied))
    })
    .await;
    match result {
        Ok(Ok(prepared)) => reload_config_with_resolver(
            prepared,
            config_tx,
            log_tx,
            detected_ip_v4,
            detected_ip_v6,
            reload_state,
            dns_resolver.as_deref(),
        ),
        Ok(Err(error)) => {
            error!(
                "config reload: effective WEB validation failed: {}; keeping old config",
                error
            );
            Some(manifest)
        }
        Err(error) => {
            error!(
                "config reload: runtime builder failed: {}; keeping old config",
                error
            );
            Some(manifest)
        }
    }
}

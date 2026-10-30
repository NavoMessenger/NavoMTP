use super::*;

use crate::config::WebCarrierMethod;

#[test]
fn carrier_method_reload_is_hot_and_preserves_process_limits() {
    let mut active = ProxyConfig::default();
    for method in [WebCarrierMethod::Put, WebCarrierMethod::Post] {
        let mut desired = active.clone();
        desired.web.carrier_method = method;
        assert_eq!(classify_config_changes(&active, &desired).changed, ["web"]);
        assert!(!classify_config_changes(&active, &desired).restart_required);
        desired.web.limits.max_http_connections += 1;
        let applied = overlay_hot_fields(&active, &desired);
        assert_eq!(applied.web.carrier_method, method);
        assert_eq!(
            applied.web.limits.max_http_connections,
            active.web.limits.max_http_connections
        );
        active = applied;
    }
}

#[test]
fn carrier_method_reload_publishes_both_directions_and_keeps_last_good_value() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let source = |method| format!("[web]\ncarrier_method = \"{method}\"\n");
    std::fs::write(&path, source("post")).unwrap();
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let (config_tx, _config_rx) = watch::channel(Arc::clone(&initial));
    let (log_tx, _log_rx) = watch::channel(initial.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));
    for (token, method) in [
        ("put", WebCarrierMethod::Put),
        ("post", WebCarrierMethod::Post),
    ] {
        std::fs::write(&path, source(token)).unwrap();
        reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();
        let applied = config_tx.borrow().clone();
        assert_eq!(applied.web.carrier_method, method);
        std::fs::write(&path, source("PATCH")).unwrap();
        reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state);
        let unchanged = config_tx.borrow().clone();
        assert!(Arc::ptr_eq(&unchanged, &applied));
    }
}

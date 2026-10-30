use super::*;

#[tokio::test]
async fn conveyor_api_is_boolean_hot_and_rejects_invalid_patch_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[web]\nconveyor = true\n").unwrap();
    for enabled in [false, true] {
        let active = ProxyConfig::load(&path).unwrap();
        let patch = serde_json::json!({"web": {"conveyor": enabled}});
        let mut response = apply_patch_to_path(&path, &patch, None).await.unwrap();
        let desired = ProxyConfig::load(&path).unwrap();
        let resolved = reconcile_runtime_effect(&mut response, &active, &desired).unwrap();
        assert_eq!(resolved.effective.web.conveyor, enabled);
        assert!(response.runtime_reload_required);
        assert!(!response.process_restart_required);
        let (managed, _) = read_managed_config(&path).await.unwrap();
        assert_eq!(managed["web"]["conveyor"].as_bool(), Some(enabled));
        let previous = std::fs::read(&path).unwrap();
        let invalid = serde_json::json!({"web": {"conveyor": "false"}});
        let error = apply_patch_to_path(&path, &invalid, None)
            .await
            .unwrap_err();
        assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path).unwrap(), previous);
    }
}

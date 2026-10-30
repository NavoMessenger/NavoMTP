use super::*;

const SOURCE: &str = r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[web]
enabled = true
[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://localhost:18081"
resolve = "startup"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#;

#[tokio::test]
async fn decoy_dns_api_get_and_mutation_base_need_no_prepared_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        SOURCE.replace("localhost", "unresolvable.example.invalid"),
    )
    .unwrap();
    let (managed, revision) = read_managed_config(&path).await.unwrap();
    assert_eq!(
        managed["web"]["vhosts"][0]["decoy"]["resolve"].as_str(),
        Some("startup")
    );
    assert!(managed["web"].get("decoy_dns").is_none());
    let (base, base_revision) = crate::api::config_store::load_config_for_mutation(&path, None)
        .await
        .unwrap();
    assert_eq!(revision, base_revision);
    assert!(base.web.runtime.is_none());
    assert!(base.web.decoy_dns.origins.is_empty());
}

#[tokio::test]
async fn decoy_dns_api_patch_without_reload_prepares_before_disk_write() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, SOURCE).unwrap();
    // This current-thread runtime exercises the real Tokio resolver without nested block_on.
    let active = ProxyConfig::load_prepared(path.clone())
        .await
        .unwrap()
        .config;
    let before = std::fs::read(&path).unwrap();
    let mut vhosts = serde_json::to_value(&active.web.vhosts).unwrap();
    vhosts[0]["decoy"]["upstream"] = Json::String("http://localhost:18080".to_string());
    let error = apply_patch_to_path(&path, &serde_json::json!({"web": {"vhosts": vhosts}}), None)
        .await
        .unwrap_err();
    assert!(error.message.contains("overlaps WEB listener"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(active.web.runtime.is_some());

    let prepared = prepare_patch_to_path(
        &path,
        &serde_json::json!({"web": {"conveyor": false}}),
        None,
    )
    .await
    .unwrap();
    assert_eq!(prepared.desired_config.web.decoy_dns.origins.len(), 1);
    assert!(prepared.desired_config.web.runtime.is_some());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    apply_patch_to_path(
        &path,
        &serde_json::json!({"web": {"conveyor": false}}),
        None,
    )
    .await
    .unwrap();
    let reloaded = ProxyConfig::load_prepared(path).await.unwrap();
    assert!(!reloaded.config.web.conveyor);
}

#[tokio::test]
async fn decoy_dns_api_rejects_resolve_on_static_mode_before_serde_drops_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, SOURCE).unwrap();
    let base = ProxyConfig::parse_source(&path).unwrap();
    let mut vhosts = serde_json::to_value(&base.config.web.vhosts).unwrap();
    vhosts[0]["decoy"] = serde_json::json!({
        "mode": "static_directory", "directory": directory.path(), "resolve": "startup"
    });
    let before = std::fs::read(&path).unwrap();
    let error = apply_patch_to_path(&path, &serde_json::json!({"web": {"vhosts": vhosts}}), None)
        .await
        .unwrap_err();
    assert!(error.message.contains("only valid for mode=http_upstream"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

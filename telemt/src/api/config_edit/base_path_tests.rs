use super::*;

fn web_config() -> &'static str {
    r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true

[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
"#
}

fn vhosts_patch(base_path: &str) -> Json {
    serde_json::json!({
        "web": {
            "vhosts": [{
                "host": "proxy.example.com",
                "base_path": base_path,
                "public_addr": "203.0.113.10:443",
                "decoy": {
                    "mode": "http_upstream",
                    "upstream": "http://127.0.0.1:18081"
                },
                "profiles": [{
                    "user": "alice",
                    "secret_mode": "plain"
                }]
            }]
        }
    })
}

#[tokio::test]
async fn config_api_applies_valid_base_path_and_preserves_source_on_invalid_patch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, web_config()).unwrap();
    let active = ProxyConfig::load(&path).unwrap();

    let mut response = apply_patch_to_path(&path, &vhosts_patch("MixedCase/path"), None)
        .await
        .unwrap();
    let desired = ProxyConfig::load(&path).unwrap();
    let resolved = reconcile_runtime_effect(&mut response, &active, &desired).unwrap();
    assert!(!response.restart_required);
    assert!(response.runtime_reload_required);
    assert!(!response.process_restart_required);
    assert!(response.deferred_process_fields.is_empty());
    assert!(resolved.runtime_changed);
    assert_eq!(desired.web.vhosts[0].base_path, "MixedCase/path");
    assert_eq!(
        resolved.effective.web.runtime.as_ref().unwrap().vhosts["proxy.example.com"].base,
        "/MixedCase/path/"
    );

    let (managed, _revision) = read_managed_config(&path).await.unwrap();
    let vhosts = managed["web"]["vhosts"].as_array().unwrap();
    assert_eq!(vhosts[0]["base_path"].as_str(), Some("MixedCase/path"));
    assert!(managed["web"].get("runtime").is_none());
    assert!(!managed.as_table().unwrap().contains_key("access"));

    let before_invalid = std::fs::read(&path).unwrap();
    let error = apply_patch_to_path(&path, &vhosts_patch("/invalid"), None)
        .await
        .unwrap_err();
    assert_eq!(error.status, hyper::StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read(&path).unwrap(), before_invalid);
}

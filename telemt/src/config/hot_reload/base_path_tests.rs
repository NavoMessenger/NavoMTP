use base64::Engine as _;

use super::*;

fn write_base_path_config(path: &Path, base_path: &str) {
    let base_path = if base_path.is_empty() {
        String::new()
    } else {
        format!("base_path = \"{base_path}\"\n")
    };
    let config = format!(
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
{base_path}public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
"#,
    );
    std::fs::write(path, config).unwrap();
}

#[test]
fn reload_rejects_invalid_base_then_publishes_route_identity_together() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    write_base_path_config(&path, "");
    let initial = Arc::new(ProxyConfig::load(&path).unwrap());
    let initial_hash = ProxyConfig::load_with_metadata(&path)
        .unwrap()
        .rendered_hash;
    let initial_capability = initial.web.runtime.as_ref().unwrap().capabilities[0];
    let (config_tx, _config_rx) = watch::channel(Arc::clone(&initial));
    let (log_tx, _log_rx) = watch::channel(initial.general.log_level.clone());
    let mut reload_state = ReloadState::new(Some(initial_hash));

    write_base_path_config(&path, "/invalid");
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state);
    let unchanged = config_tx.borrow().clone();
    assert!(Arc::ptr_eq(&unchanged, &initial));
    assert_eq!(unchanged.web.vhosts[0].base_path, "");
    assert_eq!(
        unchanged.web.runtime.as_ref().unwrap().capabilities[0],
        initial_capability
    );

    write_base_path_config(&path, "dobry-cola-super-app");
    reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state);
    let applied = config_tx.borrow().clone();
    let runtime = applied.web.runtime.as_ref().unwrap();
    let vhost = &runtime.vhosts["proxy.example.com"];
    assert_eq!(applied.web.vhosts[0].base_path, "dobry-cola-super-app");
    assert_eq!(vhost.base, "/dobry-cola-super-app/");
    assert_eq!(vhost.capabilities[0], vhost.profiles[0].capability);
    assert_eq!(runtime.capabilities.as_ref(), vhost.capabilities.as_ref());
    assert!(!runtime.capabilities.contains(&initial_capability));
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vhost.capabilities[0]),
        "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ"
    );
}

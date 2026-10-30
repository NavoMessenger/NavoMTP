use super::*;

#[test]
fn web_runtime_collects_every_vhost_capability() {
    let configured = format!(
        "{WEB_CONFIG}\n{}",
        r#"
[[web.vhosts]]
host = "Other.Example.COM"
base_path = "other/path"
public_addr = "203.0.113.11:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18082"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "dd"
"#
    );
    let config = load_config_from_temp_toml(&configured);
    let runtime = config.web.runtime.as_ref().unwrap();
    let first = &runtime.vhosts["proxy.example.com"];
    let second = &runtime.vhosts["other.example.com"];

    assert_eq!(runtime.capabilities.len(), 2);
    assert_eq!(first.capabilities[0], first.profiles[0].capability);
    assert_eq!(second.capabilities[0], second.profiles[0].capability);
    assert_ne!(first.capabilities[0], second.capabilities[0]);
    assert!(runtime.capabilities.contains(&first.capabilities[0]));
    assert!(runtime.capabilities.contains(&second.capabilities[0]));
}

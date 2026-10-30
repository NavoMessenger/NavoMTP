use super::*;

#[test]
fn api_minimal_runtime_cache_ttl_out_of_range_is_rejected() {
    let toml = r#"
        [server.api]
        enabled = true
        listen = "127.0.0.1:9091"
        minimal_runtime_cache_ttl_ms = 70000

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_api_minimal_runtime_cache_ttl_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("server.api.minimal_runtime_cache_ttl_ms must be within [0, 60000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn api_runtime_edge_cache_ttl_out_of_range_is_rejected() {
    let toml = r#"
        [server.api]
        enabled = true
        listen = "127.0.0.1:9091"
        runtime_edge_cache_ttl_ms = 70000

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_api_runtime_edge_cache_ttl_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("server.api.runtime_edge_cache_ttl_ms must be within [0, 60000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn api_runtime_edge_top_n_out_of_range_is_rejected() {
    let toml = r#"
        [server.api]
        enabled = true
        listen = "127.0.0.1:9091"
        runtime_edge_top_n = 0

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_api_runtime_edge_top_n_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("server.api.runtime_edge_top_n must be within [1, 1000]"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn api_runtime_edge_events_capacity_out_of_range_is_rejected() {
    let toml = r#"
        [server.api]
        enabled = true
        listen = "127.0.0.1:9091"
        runtime_edge_events_capacity = 8

        [censorship]
        tls_domain = "example.com"

        [access.users]
        user = "00000000000000000000000000000000"
    "#;
    let dir = std::env::temp_dir();
    let path = dir.join("telemt_api_runtime_edge_events_capacity_invalid_test.toml");
    std::fs::write(&path, toml).unwrap();
    let err = ProxyConfig::load(&path).unwrap_err().to_string();
    assert!(err.contains("server.api.runtime_edge_events_capacity must be within [16, 4096]"));
    let _ = std::fs::remove_file(path);
}

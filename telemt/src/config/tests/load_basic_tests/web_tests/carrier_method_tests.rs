use super::*;

#[test]
fn carrier_method_defaults_and_roundtrips_without_changing_capabilities() {
    let default = load_config_from_temp_toml(WEB_CONFIG);
    assert_eq!(default.web.carrier_method, WebCarrierMethod::Post);
    let capabilities = default.web.runtime.as_ref().unwrap().capabilities.clone();
    for (token, method) in [
        ("post", WebCarrierMethod::Post),
        ("put", WebCarrierMethod::Put),
    ] {
        let configured = WEB_CONFIG.replace(
            "carrier = \"https-lanes\"",
            &format!("carrier = \"https-lanes\"\ncarrier_method = \"{token}\""),
        );
        let source = format!("[general]\nconfig_strict = true\n{configured}");
        let config = load_config_from_temp_toml(&source);
        assert_eq!(config.web.carrier_method, method);
        assert_eq!(
            config.web.runtime.as_ref().unwrap().capabilities,
            capabilities
        );
        let json = serde_json::to_value(&config.web).unwrap();
        assert_eq!(json["carrier_method"], token);
        let decoded: WebConfig = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.carrier_method, method);
        let serialized = toml::to_string(&config.web).unwrap();
        let decoded: WebConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(decoded.carrier_method, method);
    }
}

#[test]
fn carrier_method_rejects_unknown_tokens_types_and_aliases() {
    for value in ["\"POST\"", "\"PUT\"", "\"patch\"", "true", "42", "[]"] {
        let source = WEB_CONFIG.replace(
            "carrier = \"https-lanes\"",
            &format!("carrier = \"https-lanes\"\ncarrier_method = {value}"),
        );
        assert!(load_config_error_from_temp_toml(&source).contains("carrier_method"));
    }
    let configured = WEB_CONFIG.replace(
        "carrier = \"https-lanes\"",
        "carrier = \"https-lanes\"\nhttp_method = \"put\"",
    );
    let source = format!("[general]\nconfig_strict = true\n{configured}");
    assert!(load_config_error_from_temp_toml(&source).contains("http_method"));
}

use super::*;

#[test]
fn conveyor_defaults_on_and_roundtrips_without_changing_capabilities() {
    let default = load_config_from_temp_toml(WEB_CONFIG);
    assert!(default.web.conveyor);
    assert!(ProxyConfig::default().web.conveyor);
    let capabilities = default.web.runtime.as_ref().unwrap().capabilities.clone();
    for enabled in [false, true] {
        let configured = WEB_CONFIG.replace(
            "carrier = \"https-lanes\"",
            &format!("carrier = \"https-lanes\"\nconveyor = {enabled}"),
        );
        let config =
            load_config_from_temp_toml(&format!("[general]\nconfig_strict = true\n{configured}",));
        assert_eq!(config.web.conveyor, enabled);
        assert_eq!(
            config.web.runtime.as_ref().unwrap().capabilities,
            capabilities
        );
        let json = serde_json::to_value(&config.web).unwrap();
        assert_eq!(json["conveyor"], enabled);
        assert_eq!(
            serde_json::from_value::<WebConfig>(json).unwrap().conveyor,
            enabled
        );
        let toml = toml::to_string(&config.web).unwrap();
        assert_eq!(
            toml::from_str::<WebConfig>(&toml).unwrap().conveyor,
            enabled
        );
    }
}

#[test]
fn conveyor_rejects_non_boolean_values() {
    for value in ["\"true\"", "1", "0", "[]", "{}"] {
        let configured = WEB_CONFIG.replace(
            "carrier = \"https-lanes\"",
            &format!("carrier = \"https-lanes\"\nconveyor = {value}"),
        );
        assert!(load_config_error_from_temp_toml(&configured).contains("conveyor"));
    }
}

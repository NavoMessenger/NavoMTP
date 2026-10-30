use super::*;

/// Builds a static-decoy runtime with one explicit WEB endpoint base.
pub(in crate::web::http) fn runtime_config_with_base(
    capability: [u8; 32],
    carrier: WebCarrier,
    base: &str,
) -> ProxyConfig {
    runtime_config_with_carriers_and_deadlines(
        capability,
        carrier,
        false,
        true,
        Arc::from([carrier]),
        TEST_CARRIER_DEADLINES_SECS,
        base,
    )
}

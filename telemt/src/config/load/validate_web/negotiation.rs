use std::collections::HashSet;

use super::*;

/// Validates bounded carrier selection and learning policy.
pub(super) fn validate(config: &WebConfig) -> Result<Vec<WebCarrier>> {
    if let Some(carriers) = config.carriers.enabled() {
        if carriers.is_empty() {
            return config_error("web.carriers must contain at least one carrier");
        }
        let mut unique = HashSet::with_capacity(carriers.len());
        if carriers.iter().any(|carrier| !unique.insert(*carrier)) {
            return config_error("web.carriers must not contain duplicate carriers");
        }
    }
    let candidates = config.carrier_candidates();
    if config.carrier_negotiation_enabled()
        && config.carrier_learning
        && config.limits.max_carrier_learning_entries < WEB_CARRIER_LEARNING_MIN_ENTRIES
    {
        return config_error(
            "web.limits.max_carrier_learning_entries must be >= 3 when carrier learning is enabled",
        );
    }
    if candidates.len() > WebCarrier::ALL.len() {
        return config_error(
            "web.carriers and the web.carrier fallback must contain at most four carriers",
        );
    }
    let deadlines = config.timeouts.carrier_negotiation_deadlines_secs;
    if deadlines[0] == 0 || deadlines.windows(2).any(|pair| pair[0] >= pair[1]) {
        return config_error(
            "web.timeouts.carrier_negotiation_deadlines_secs must be non-zero and strictly increasing",
        );
    }
    let retained_chain_secs = deadlines[3]
        .checked_add(config.timeouts.carrier_health_secs)
        .and_then(|value| value.checked_add(1));
    if retained_chain_secs.is_none_or(|value| value >= config.timeouts.bootstrap_lifetime_secs) {
        return config_error(
            "web.timeouts final carrier deadline plus health and cleanup must be lower than bootstrap_lifetime_secs",
        );
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_is_appended_once() {
        let config = WebConfig {
            carrier: WebCarrier::Https,
            carriers: WebCarriers::Enabled(vec![WebCarrier::Websocket, WebCarrier::Https]),
            ..Default::default()
        };
        assert_eq!(
            validate(&config).unwrap(),
            vec![WebCarrier::Websocket, WebCarrier::Https]
        );
    }

    #[test]
    fn duplicate_carriers_are_rejected() {
        let config = WebConfig {
            carriers: WebCarriers::Enabled(vec![WebCarrier::Websocket, WebCarrier::Websocket]),
            ..Default::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn missing_or_false_carriers_disable_negotiation() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            value: WebCarriers,
        }

        let config = WebConfig::default();
        assert!(!config.carrier_negotiation_enabled());
        assert_eq!(validate(&config).unwrap(), [WebCarrier::Https]);

        let disabled: Wrapper = toml::from_str("value = false").unwrap();
        assert_eq!(disabled.value, WebCarriers::Disabled);
        assert!(toml::from_str::<Wrapper>("value = true").is_err());
    }

    #[test]
    fn fallback_cannot_expand_the_candidate_set_beyond_four() {
        let mut config = WebConfig {
            carrier: WebCarrier::Https,
            carriers: WebCarriers::Enabled(vec![
                WebCarrier::HttpsLanes,
                WebCarrier::Websocket,
                WebCarrier::WebsocketLanes,
                WebCarrier::Https,
            ]),
            ..Default::default()
        };
        assert_eq!(validate(&config).unwrap().len(), 4);

        config.carriers = WebCarriers::Enabled(vec![
            WebCarrier::HttpsLanes,
            WebCarrier::Websocket,
            WebCarrier::WebsocketLanes,
        ]);
        assert_eq!(validate(&config).unwrap().len(), 4);
    }

    #[test]
    fn deadlines_are_cumulative_and_bounded_by_bootstrap_lifetime() {
        let mut config = WebConfig::default();
        config.timeouts.carrier_negotiation_deadlines_secs = [3, 3, 8, 12];
        assert!(validate(&config).is_err());
        config.timeouts.carrier_negotiation_deadlines_secs = [3, 5, 8, 121];
        assert!(validate(&config).is_err());
        config.timeouts.carrier_negotiation_deadlines_secs = [3, 5, 8, 89];
        assert!(validate(&config).is_err());
        config.timeouts.carrier_negotiation_deadlines_secs = [3, 5, 8, 88];
        assert!(validate(&config).is_ok());
    }
}

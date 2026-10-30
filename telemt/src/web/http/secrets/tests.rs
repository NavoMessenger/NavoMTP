use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine as _;

use super::*;
use crate::config::WebCarrier;
use crate::maestro::generation::test_runtime_generation;
use crate::web::http::tests::runtime_config_with_base;

fn percent_encode_byte(value: u8, lowercase: bool) -> String {
    if lowercase {
        format!("%{value:02x}")
    } else {
        format!("%{value:02X}")
    }
}

#[tokio::test]
async fn scanner_recognizes_exact_credentials_across_encoding_boundaries() {
    let capability = [71u8; 32];
    let generation = test_runtime_generation(
        1,
        runtime_config_with_base(capability, WebCarrier::Https, "/relay/"),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let generation_config = generation.config();
    let config = generation_config.web.runtime.as_ref().unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);

    assert!(contains_secret(encoded.as_bytes(), config, &runtime));
    assert!(contains_secret(
        format!("prefix{encoded}suffix").as_bytes(),
        config,
        &runtime,
    ));
    for index in 0..encoded.len() {
        let mut escaped = String::with_capacity(encoded.len() + 2);
        escaped.push_str(&encoded[..index]);
        escaped.push_str(&percent_encode_byte(
            encoded.as_bytes()[index],
            index % 2 == 0,
        ));
        escaped.push_str(&encoded[index + 1..]);
        assert!(
            contains_secret(escaped.as_bytes(), config, &runtime),
            "percent-encoded byte {index} was not recognized"
        );
    }

    let profile = config.profiles[0].clone();
    let bootstrap = runtime
        .issue_bootstrap(profile, "192.0.2.10".parse().unwrap())
        .unwrap()
        .token;
    let escaped_bootstrap = bootstrap
        .bytes()
        .enumerate()
        .map(|(index, byte)| percent_encode_byte(byte, index % 2 == 0))
        .collect::<String>();
    assert!(contains_secret(bootstrap.as_bytes(), config, &runtime));
    assert!(contains_secret(
        escaped_bootstrap.as_bytes(),
        config,
        &runtime,
    ));

    let split = format!("{}%zz{}", &encoded[..20], &encoded[20..]);
    assert!(!contains_secret(split.as_bytes(), config, &runtime));
    let inactive = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([72u8; 32]);
    assert!(!contains_secret(inactive.as_bytes(), config, &runtime));

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

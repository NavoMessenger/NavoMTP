use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use super::*;
use crate::synlimit_control::model::{
    SynLimitNamespace, SynLimitRule, SynLimitTargets, synlimit_namespace,
};

fn rule(ip: IpAddr, hitcount: u32) -> SynLimitRule {
    SynLimitRule {
        ip: Some(ip),
        port: 24443,
        generic_seconds: 60,
        generic_hitcount: hitcount,
        generic_burst: 24,
        ios_seconds: 1,
        ios_hitcount: 12,
        ios_burst: 24,
        hashlimit_expire_ms: 60_000,
        hashlimit_size: 32_768,
    }
}

fn targets(low_family: &str) -> SynLimitTargets {
    let (v4_rate, v6_rate) = match low_family {
        "v4" => (2, 100),
        "v6" => (100, 2),
        _ => panic!("TELEMT_PF_LOW_FAMILY must be v4 or v6"),
    };
    SynLimitTargets {
        pf_v4: vec![rule(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 1)), v4_rate)],
        pf_v6: vec![rule(
            IpAddr::V6("fd00:18:1::1".parse::<Ipv6Addr>().unwrap()),
            v6_rate,
        )],
        ..Default::default()
    }
}

fn write_metadata(path: &str, namespace: &SynLimitNamespace) {
    std::fs::write(path, format!("anchor={}\n", namespace.pf_anchor)).unwrap();
}

async fn wait_for_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("PF runtime-test release barrier timed out");
}

#[tokio::test]
#[ignore = "requires native FreeBSD PF and VNET test harness"]
async fn production_pf_runtime_role() {
    let role = std::env::var("TELEMT_PF_ROLE").expect("TELEMT_PF_ROLE is required");
    let low_family = std::env::var("TELEMT_PF_LOW_FAMILY").unwrap_or_else(|_| "v4".to_string());
    let targets = targets(&low_family);
    let namespace = synlimit_namespace(&targets).expect("PF namespace missing");
    let metadata = std::env::var("TELEMT_PF_META").expect("TELEMT_PF_META is required");
    match role.as_str() {
        "render" => {
            let script_path = std::env::var("TELEMT_PF_SCRIPT").unwrap();
            std::fs::write(script_path, pf_synlimit_script(&targets)).unwrap();
            write_metadata(&metadata, &namespace);
        }
        "apply-wait" => {
            apply_synlimit_rules(&targets, &namespace).await.unwrap();
            write_metadata(&metadata, &namespace);
            let barrier = std::env::var("TELEMT_PF_BARRIER").unwrap();
            let release = std::env::var("TELEMT_PF_RELEASE").unwrap();
            std::fs::write(&barrier, b"ready").unwrap();
            wait_for_file(Path::new(&release)).await;
            assert!(clear_rules(&namespace).await.unwrap());
        }
        _ => panic!("TELEMT_PF_ROLE must be render or apply-wait"),
    }
}

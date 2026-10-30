use super::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::policy::{VictimClass, admission_key, pressure_key, victim_class};
use crate::config::ProxyConfig;
use crate::maestro::generation::test_runtime_generation;
use crate::web::manager::budget::WebSocketFairnessSnapshot;
use arc_swap::ArcSwap;

#[allow(clippy::too_many_arguments)]
fn entry(
    id: u64,
    owner: ProfileKey,
    session_id: u64,
    client_ip: &str,
    kind: WebSocketKind,
    phase: WebSocketPhase,
    peer_tick: u64,
    progress_tick: u64,
) -> WebSocketEntry {
    WebSocketEntry {
        id,
        owner,
        session_id,
        claim: WebSocketClaimKey {
            session_hash: [0; 32],
            kind,
        },
        client_ip: client_ip.parse().unwrap(),
        kind,
        liveness_interval_ms: 10,
        created_tick: 1,
        last_peer_tick: AtomicU64::new(peer_tick),
        last_progress_tick: AtomicU64::new(progress_tick),
        phase: AtomicU8::new(phase as u8),
        closing: AtomicBool::new(false),
        health_claimed: AtomicBool::new(false),
        cancel: CancellationToken::new(),
        released: CancellationToken::new(),
    }
}

fn fairness(fair_share: usize, usages: &[(ProfileKey, usize)]) -> WebSocketFairnessSnapshot {
    WebSocketFairnessSnapshot {
        fair_share,
        owner_bytes: usages.iter().copied().collect::<HashMap<_, _>>(),
    }
}

#[test]
fn preactive_and_dead_are_distinct_lifecycle_classes() {
    let preactive = entry(
        1,
        [1; 32],
        1,
        "192.0.2.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Claimed,
        1,
        1,
    );
    let dead = entry(
        2,
        [1; 32],
        1,
        "192.0.2.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Active,
        1,
        1,
    );

    assert_eq!(victim_class(&preactive, 100), VictimClass::PreActive);
    assert_eq!(victim_class(&dead, 100), VictimClass::Dead);
}

#[test]
fn dead_other_session_precedes_healthy_same_session() {
    let requester_owner = [1; 32];
    let usage = fairness(100, &[(requester_owner, 100), ([2; 32], 100)]);
    let dead = entry(
        2,
        [2; 32],
        2,
        "198.51.100.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Active,
        1,
        1,
    );
    let healthy = entry(
        1,
        requester_owner,
        1,
        "192.0.2.10",
        WebSocketKind::Lane(7),
        WebSocketPhase::Active,
        99,
        99,
    );

    let dead_key = admission_key(
        &dead,
        100,
        requester_owner,
        1,
        "192.0.2.10".parse().unwrap(),
        &usage,
    )
    .unwrap();
    let healthy_key = admission_key(
        &healthy,
        100,
        requester_owner,
        1,
        "192.0.2.10".parse().unwrap(),
        &usage,
    )
    .unwrap();

    assert!(dead_key < healthy_key);
}

#[test]
fn unrelated_live_victim_requires_opposite_fair_share_positions() {
    let requester_owner = [1; 32];
    let victim_owner = [2; 32];
    let candidate = entry(
        1,
        victim_owner,
        2,
        "198.51.100.10",
        WebSocketKind::Lane(7),
        WebSocketPhase::Active,
        99,
        99,
    );
    let requester_ip = "192.0.2.10".parse().unwrap();

    assert!(
        admission_key(
            &candidate,
            100,
            requester_owner,
            1,
            requester_ip,
            &fairness(100, &[(requester_owner, 99), (victim_owner, 101)]),
        )
        .is_some()
    );
    assert!(
        admission_key(
            &candidate,
            100,
            requester_owner,
            1,
            requester_ip,
            &fairness(100, &[(requester_owner, 100), (victim_owner, 101)]),
        )
        .is_none()
    );
}

#[test]
fn pressure_prefers_over_share_owner_then_lifecycle_and_id() {
    let over_owner = [1; 32];
    let under_owner = [2; 32];
    let usage = fairness(100, &[(over_owner, 101), (under_owner, 99)]);
    let over = entry(
        9,
        over_owner,
        1,
        "192.0.2.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Active,
        99,
        99,
    );
    let under = entry(
        1,
        under_owner,
        2,
        "198.51.100.10",
        WebSocketKind::Lane(7),
        WebSocketPhase::Active,
        90,
        90,
    );

    assert!(pressure_key(&over, 100, &usage) < pressure_key(&under, 100, &usage));

    let equal_usage = fairness(100, &[(over_owner, 100), (under_owner, 100)]);
    let preactive = entry(
        2,
        under_owner,
        2,
        "198.51.100.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Upgraded,
        99,
        99,
    );
    assert!(pressure_key(&preactive, 100, &equal_usage) < pressure_key(&under, 100, &equal_usage));

    let lower_id = entry(
        1,
        under_owner,
        2,
        "198.51.100.10",
        WebSocketKind::Lane(7),
        WebSocketPhase::Active,
        90,
        90,
    );
    let higher_id = entry(
        2,
        under_owner,
        2,
        "198.51.100.10",
        WebSocketKind::Lane(8),
        WebSocketPhase::Active,
        90,
        90,
    );

    assert!(
        pressure_key(&lower_id, 100, &equal_usage) < pressure_key(&higher_id, 100, &equal_usage)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_victim_claims_stay_bounded_and_return_to_zero() {
    let config = ProxyConfig::default();
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let limit = runtime.limits.max_websocket_evictions_in_flight;
    let entries = (0..limit.saturating_mul(2))
        .map(|index| {
            Arc::new(entry(
                index as u64 + 1,
                [index as u8; 32],
                index as u64 + 1,
                "192.0.2.10",
                WebSocketKind::Lane(index as u32 + 1),
                WebSocketPhase::Active,
                1,
                1,
            ))
        })
        .collect::<Vec<_>>();
    let connections = entries
        .iter()
        .map(|entry| WebSocketConnection {
            runtime: Arc::downgrade(&runtime),
            entry: Arc::clone(entry),
            slot: None,
            base_budget: None,
        })
        .collect::<Vec<_>>();
    {
        let mut registry = runtime.websockets.lock();
        for entry in &entries {
            registry.claims.insert(entry.claim, entry.id);
            registry.entries.insert(entry.id, Arc::clone(entry));
        }
    }
    let successes = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for task_id in 0..100usize {
        let runtime = Arc::clone(&runtime);
        let entries = entries.clone();
        let successes = Arc::clone(&successes);
        tasks.push(tokio::spawn(async move {
            for attempt in 0..100usize {
                let entry = &entries[(task_id * 100 + attempt) % entries.len()];
                {
                    let mut registry = runtime.websockets.lock();
                    if claim_entry(&mut registry, entry, &runtime) {
                        successes.fetch_add(1, Ordering::AcqRel);
                    }
                }
                tokio::task::yield_now().await;
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(successes.load(Ordering::Acquire), limit);
    assert_eq!(runtime.websockets.lock().evictions_in_flight, limit);

    drop(connections);
    assert_eq!(runtime.websockets.lock().evictions_in_flight, 0);
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_health_claims_publish_one_exact_live_owner() {
    let generation = test_runtime_generation(1, ProxyConfig::default());
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let owner = Arc::new(entry(
        1,
        [1; 32],
        1,
        "192.0.2.10",
        WebSocketKind::Multiplex,
        WebSocketPhase::Active,
        1,
        1,
    ));
    let connection = WebSocketConnection {
        runtime: Arc::downgrade(&runtime),
        entry: Arc::clone(&owner),
        slot: None,
        base_budget: None,
    };
    {
        let mut registry = runtime.websockets.lock();
        registry.claims.insert(owner.claim, owner.id);
        registry.entries.insert(owner.id, Arc::clone(&owner));
    }
    let successes = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let runtime = Arc::clone(&runtime);
        let successes = Arc::clone(&successes);
        tasks.push(tokio::spawn(async move {
            if runtime.claim_websocket_health(1, [0; 32]) {
                successes.fetch_add(1, Ordering::AcqRel);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(successes.load(Ordering::Acquire), 1);
    assert!(!runtime.claim_websocket_health(1, [0; 32]));
    assert!(!runtime.claim_websocket_health(2, [0; 32]));
    assert!(!runtime.claim_websocket_health(1, [1; 32]));

    drop(connection);
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

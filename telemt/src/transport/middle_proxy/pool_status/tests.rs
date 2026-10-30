use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::codec::WriterCommand;
use crate::transport::middle_proxy::pool::{MePool, MeWriter, WriterContour};
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

fn writer(pool: &Arc<MePool>, id: u64, dc: i32, addr: SocketAddr) -> MeWriter {
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    MeWriter {
        id,
        addr,
        source_ip: addr.ip(),
        writer_dc: dc,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx,
        byte_budget: pool.new_writer_byte_budget(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    }
}

#[tokio::test]
async fn dual_family_status_reports_each_family_floor() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        effective_prefer: 4,
        effective_multipath: false,
        ..NetworkDecision::default()
    })
    .await;
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
        Some(HashMap::from([(2, vec![(v6.ip(), v6.port())])])),
    )
    .await;
    let required_per_family = pool.required_writers_for_dc(1);
    let mut writers = pool.writers.write().await;
    for (group, dc) in [2, -2].into_iter().enumerate() {
        for offset in 0..required_per_family {
            writers.push(writer(&pool, (group as u64 * 100) + offset as u64, dc, v4));
        }
    }
    drop(writers);

    let snapshot = pool.api_status_snapshot().await;

    assert_eq!(snapshot.required_writers, required_per_family * 4);
    assert_eq!(snapshot.alive_writers, required_per_family * 2);
    assert_eq!(snapshot.coverage_pct, 50.0);
    for dc in snapshot.dcs {
        assert_eq!(dc.required_writers, required_per_family * 2);
        assert_eq!(dc.alive_writers, required_per_family);
        assert_eq!(dc.coverage_pct, 50.0);
    }
    assert!(!pool.admission_ready_full_floor().await);
}

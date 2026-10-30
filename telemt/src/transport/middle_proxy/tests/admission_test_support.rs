use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::pool::{MePool, MeWriter, WriterContour};
use super::pool_writer_security_tests::make_pool;

/// Owns idle writer visibility without spawning ME transports or client sessions.
pub(crate) struct IdlePoolFixture {
    pool: Arc<MePool>,
    draining: Vec<Arc<AtomicBool>>,
    _receivers: Vec<mpsc::Receiver<WriterCommand>>,
}

impl IdlePoolFixture {
    /// Builds both signed DC groups with a controllable readiness quorum.
    pub(crate) async fn new(ready: bool) -> Self {
        let pool = make_pool().await;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
            .await;
        let mut draining = Vec::new();
        let mut receivers = Vec::new();
        {
            let mut writers = pool.writers.write().await;
            for (id, dc) in [(1, 2), (2, -2)] {
                let (writer, receiver) = unregistered_writer(
                    &pool,
                    id,
                    dc,
                    addr,
                    pool.current_generation(),
                    WriterContour::Active,
                );
                writer.draining.store(!ready, Ordering::Release);
                draining.push(writer.draining.clone());
                receivers.push(receiver);
                writers.push(writer);
            }
        }
        Self {
            pool,
            draining,
            _receivers: receivers,
        }
    }

    /// Returns the pool sampled by the production admission gate.
    pub(crate) fn pool(&self) -> Arc<MePool> {
        self.pool.clone()
    }

    /// Changes the fixture quorum without notifying the admission gate.
    pub(crate) fn set_ready(&self, ready: bool) {
        for draining in &self.draining {
            draining.store(!ready, Ordering::Release);
        }
    }
}

/// Builds a writer whose command receiver remains owned by the test.
pub(super) fn unregistered_writer(
    pool: &Arc<MePool>,
    id: u64,
    dc: i32,
    addr: SocketAddr,
    generation: u64,
    contour: WriterContour,
) -> (MeWriter, mpsc::Receiver<WriterCommand>) {
    let (tx, rx) = mpsc::channel(8);
    (
        MeWriter {
            id,
            addr,
            source_ip: addr.ip(),
            writer_dc: dc,
            generation,
            contour: Arc::new(AtomicU8::new(contour.as_u8())),
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
        },
        rx,
    )
}

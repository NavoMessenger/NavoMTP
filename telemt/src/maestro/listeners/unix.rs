use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::maestro::generation::RuntimeGeneration;

pub(super) struct UnixAcceptHandle {
    _listener: Arc<UnixListener>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

async fn run_unix_accept_loop(
    listener: Arc<UnixListener>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    cancellation: CancellationToken,
) {
    let connection_counter = AtomicU64::new(1);
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _)) => {
                let runtime = active_runtime.load_full();
                if !*runtime.admission_rx.borrow() {
                    drop(stream);
                    continue;
                }
                let config = runtime.config();
                let timeout_ms = config.server.accept_permit_timeout_ms;
                let acquire = runtime.max_connections.clone().acquire_owned();
                let permit = if timeout_ms == 0 {
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return,
                        permit = acquire => match permit {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("Connection limiter is closed");
                                return;
                            }
                        }
                    }
                } else {
                    match tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return,
                        result = tokio::time::timeout(Duration::from_millis(timeout_ms), acquire) => result,
                    } {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) => {
                            error!("Connection limiter is closed");
                            return;
                        }
                        Err(_) => {
                            runtime.stats.increment_accept_permit_timeout_total();
                            debug!(
                                timeout_ms,
                                "Dropping accepted Unix connection: permit wait timeout"
                            );
                            continue;
                        }
                    }
                };

                let connection_id = connection_counter.fetch_add(1, Ordering::Relaxed);
                let fake_peer = SocketAddr::from(([127, 0, 0, 1], (connection_id % 65535) as u16));
                let stats = runtime.stats.clone();
                let upstream_manager = runtime.upstream_manager.clone();
                let replay_checker = runtime.replay_checker.clone();
                let buffer_pool = runtime.buffer_pool.clone();
                let rng = runtime.rng.clone();
                let me_pool = runtime.me_pool.clone();
                let me_pool_runtime = runtime.me_pool_runtime.clone();
                let route_runtime = runtime.route_runtime.clone();
                let tls_cache = runtime.tls_cache.clone();
                let ip_tracker = runtime.ip_tracker.clone();
                let beobachten = runtime.beobachten.clone();
                let shared = runtime.proxy_shared.clone();
                let proxy_protocol_enabled = config.server.proxy_protocol;

                let _ = runtime.spawn_session(async move {
                    let _permit = permit;
                    if let Err(error_value) =
                        crate::proxy::client::handle_client_stream_with_shared_and_pool_runtime(
                            stream,
                            fake_peer,
                            config,
                            stats,
                            upstream_manager,
                            replay_checker,
                            buffer_pool,
                            rng,
                            me_pool,
                            Some(me_pool_runtime),
                            route_runtime,
                            tls_cache,
                            ip_tracker,
                            beobachten,
                            shared,
                            proxy_protocol_enabled,
                        )
                        .await
                    {
                        debug!(error = %error_value, "Unix socket connection error");
                    }
                });
            }
            Err(error_value) => {
                error!(error = %error_value, "Unix socket accept error");
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
}

impl UnixAcceptHandle {
    pub(super) fn start(
        listener: UnixListener,
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    ) -> Self {
        let listener = Arc::new(listener);
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_unix_accept_loop(
            listener.clone(),
            active_runtime,
            cancellation.clone(),
        ));
        Self {
            _listener: listener,
            cancellation,
            task: Some(task),
        }
    }

    pub(super) async fn stop(&mut self) -> Result<(), String> {
        self.request_stop();
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error_value| format!("Unix listener task failed: {error_value}"))?;
        }
        Ok(())
    }

    /// Cancels Unix admission before process-owned listener waits begin.
    pub(super) fn request_stop(&self) {
        self.cancellation.cancel();
    }

    /// Joins the Unix acceptor by the process listener deadline.
    pub(super) async fn stop_until(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        self.request_stop();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        if task.is_finished() {
            return task
                .await
                .map_err(|error_value| format!("Unix listener task failed: {error_value}"));
        }
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(result) => {
                result.map_err(|error_value| format!("Unix listener task failed: {error_value}"))
            }
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("Unix listener shutdown timed out".to_string())
            }
        }
    }
}

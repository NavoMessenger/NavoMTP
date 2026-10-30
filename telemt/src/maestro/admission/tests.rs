use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

use super::*;
use crate::transport::middle_proxy::admission_test_support::IdlePoolFixture;

const POLL_MS: u64 = 20;

struct ClosureWarnings(Arc<AtomicUsize>);

impl<S: Subscriber> Layer<S> for ClosureWarnings {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        struct ChannelField(bool);
        impl tracing::field::Visit for ChannelField {
            fn record_debug(
                &mut self,
                field: &tracing::field::Field,
                _value: &dyn std::fmt::Debug,
            ) {
                self.0 |= field.name() == "watch_channel";
            }
        }
        if event.metadata().level() == &tracing::Level::WARN {
            let mut visitor = ChannelField(false);
            event.record(&mut visitor);
            if visitor.0 {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct GateFixture {
    pool: IdlePoolFixture,
    route: Arc<RouteRuntimeController>,
    admission: watch::Receiver<bool>,
    config_tx: Option<watch::Sender<Arc<ProxyConfig>>>,
    ready_tx: Option<watch::Sender<u64>>,
    config: Arc<ProxyConfig>,
    scope: RuntimeTaskScope,
}

impl GateFixture {
    async fn new() -> Self {
        let pool = IdlePoolFixture::new(false).await;
        let mut cfg = ProxyConfig::default();
        cfg.general.use_middle_proxy = true;
        cfg.general.me2dc_fallback = true;
        cfg.general.me2dc_fast = true;
        cfg.general.me_admission_poll_ms = POLL_MS;
        let config = Arc::new(cfg);
        let (config_tx, config_rx) = watch::channel(config.clone());
        let (ready_tx, ready_rx) = watch::channel(0);
        let (admission_tx, mut admission) = watch::channel(false);
        let route = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
        let scope = RuntimeTaskScope::new();
        configure_admission_gate(
            &config,
            Some(pool.pool()),
            Arc::new(RwLock::new(Some(pool.pool()))),
            route.clone(),
            &admission_tx,
            config_rx,
            ready_rx,
            scope.clone(),
        )
        .await;
        drop(admission_tx);
        admission.borrow_and_update();
        tokio::task::yield_now().await;
        Self {
            pool,
            route,
            admission,
            config_tx: Some(config_tx),
            ready_tx: Some(ready_tx),
            config,
            scope,
        }
    }

    async fn poll(&self) {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(POLL_MS)).await;
        tokio::task::yield_now().await;
    }

    async fn expect_route(&self, mode: RelayRouteMode) {
        let mut rx = self.route.subscribe();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if rx.borrow_and_update().mode == mode {
                    return;
                }
                rx.changed().await.unwrap();
            }
        })
        .await
        .expect("the generation must keep sampling readiness without client traffic");
    }
}

async fn recovery_after_watch_closure(close_config: bool, close_ready: bool) {
    let warnings = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(ClosureWarnings(warnings.clone()));
    let _default = tracing::subscriber::set_default(subscriber);
    let mut fixture = GateFixture::new().await;
    assert!(*fixture.admission.borrow());
    if close_config {
        fixture.config_tx.take();
    }
    if close_ready {
        fixture.ready_tx.take();
    }
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    let expected_warnings = usize::from(close_config) + usize::from(close_ready);
    fixture.pool.set_ready(true);
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(fixture.route.snapshot().mode, RelayRouteMode::Direct);
    fixture.poll().await;
    fixture.expect_route(RelayRouteMode::Middle).await;
    fixture.pool.set_ready(false);
    fixture.poll().await;
    fixture.expect_route(RelayRouteMode::Direct).await;
    fixture.pool.set_ready(true);
    fixture.poll().await;
    fixture.expect_route(RelayRouteMode::Middle).await;
    for _ in 0..5 {
        fixture.poll().await;
    }
    assert_eq!(warnings.load(Ordering::Relaxed), expected_warnings);
    fixture.scope.stop().await;
    assert!(fixture.admission.has_changed().is_err());
}

#[tokio::test(start_paused = true)]
async fn idle_gate_recovers_after_readiness_watch_closes() {
    recovery_after_watch_closure(false, true).await;
}

#[tokio::test(start_paused = true)]
async fn idle_gate_recovers_after_config_watch_closes() {
    recovery_after_watch_closure(true, false).await;
}

#[tokio::test(start_paused = true)]
async fn idle_gate_recovers_after_both_watches_close_without_spinning() {
    recovery_after_watch_closure(true, true).await;
}

#[tokio::test(start_paused = true)]
async fn closed_config_watch_preserves_last_effective_fallback_policy() {
    let mut fixture = GateFixture::new().await;
    let mut cfg = fixture.config.as_ref().clone();
    cfg.general.me2dc_fallback = false;
    fixture
        .config_tx
        .as_ref()
        .unwrap()
        .send_replace(Arc::new(cfg));
    fixture.poll().await;
    fixture.expect_route(RelayRouteMode::Middle).await;
    assert!(!*fixture.admission.borrow_and_update());
    fixture.config_tx.take();
    fixture.ready_tx.take();
    fixture.poll().await;
    fixture.pool.set_ready(true);
    fixture.poll().await;
    tokio::time::timeout(Duration::from_secs(1), fixture.admission.changed())
        .await
        .expect("restored readiness must open admission after notification loss")
        .unwrap();
    assert!(*fixture.admission.borrow_and_update());
    fixture.pool.set_ready(false);
    fixture.poll().await;
    tokio::time::timeout(Duration::from_secs(1), fixture.admission.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!*fixture.admission.borrow_and_update());
    assert_eq!(fixture.route.snapshot().mode, RelayRouteMode::Middle);
    fixture.scope.stop().await;
}

#[tokio::test(start_paused = true)]
async fn generation_cancellation_stops_gate_after_notification_loss() {
    let mut fixture = GateFixture::new().await;
    fixture.config_tx.take();
    fixture.ready_tx.take();
    fixture.poll().await;
    fixture.pool.set_ready(true);
    fixture.poll().await;
    fixture.expect_route(RelayRouteMode::Middle).await;
    fixture.scope.stop().await;
    assert!(fixture.admission.has_changed().is_err());
    let state = fixture.route.snapshot();
    fixture.pool.set_ready(false);
    for _ in 0..3 {
        fixture.poll().await;
    }
    assert_eq!(fixture.route.snapshot(), state);
    assert!(*fixture.admission.borrow());
}

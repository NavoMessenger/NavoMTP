use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::*;
use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

/// Public IPv4 used as source material by local discovery and encrypted ME fixtures.
pub(super) const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(91, 108, 56, 1);
/// Bounds asynchronous fixture assertions without relying on external services.
pub(super) const TEST_DEADLINE: Duration = Duration::from_secs(2);

// Concurrency and end-to-end regressions share gated local discovery servers.
mod freshness;
pub(super) mod lifecycle;
mod recovery;

/// Gated local discovery service with observable request counts.
pub(super) struct DiscoveryServer {
    /// Listening address selected by the kernel.
    pub(super) addr: SocketAddr,
    /// Number of requests actually received from clients.
    pub(super) requests: Arc<AtomicUsize>,
    arrived: Arc<Semaphore>,
    /// One permit releases one discovery response.
    pub(super) release: Arc<Semaphore>,
    task: JoinHandle<()>,
}

impl Drop for DiscoveryServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DiscoveryServer {
    /// Waits until a real discovery request reaches the server.
    pub(super) async fn received(&self) {
        tokio::time::timeout(TEST_DEADLINE, self.arrived.acquire())
            .await
            .expect("discovery request must reach the local server")
            .unwrap()
            .forget();
    }
}

/// Serves valid STUN responses with a deliberately different reflected port.
pub(super) async fn stun_server(bind: SocketAddr, reflected: IpAddr) -> DiscoveryServer {
    stun_server_response(bind, Some(reflected), Duration::ZERO).await
}

async fn stun_server_response(
    bind: SocketAddr,
    reflected: Option<IpAddr>,
    delay: Duration,
) -> DiscoveryServer {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let arrived = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let count = requests.clone();
    let signal = arrived.clone();
    let gate = release.clone();
    let task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut request).await.unwrap();
            assert!(len >= 20);
            count.fetch_add(1, Ordering::Relaxed);
            signal.add_permits(1);
            gate.acquire().await.unwrap().forget();
            tokio::time::sleep(delay).await;
            let Some(reflected) = reflected else {
                socket.send_to(&[0u8], peer).await.unwrap();
                continue;
            };
            let (family, ip) = match reflected {
                IpAddr::V4(ip) => (1u8, ip.octets().to_vec()),
                IpAddr::V6(ip) => (2u8, ip.octets().to_vec()),
            };
            let attribute_len = 4 + ip.len();
            let mut response = vec![0u8; 24 + attribute_len];
            response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
            response[2..4].copy_from_slice(&((4 + attribute_len) as u16).to_be_bytes());
            response[4..20].copy_from_slice(&request[4..20]);
            response[20..22].copy_from_slice(&1u16.to_be_bytes());
            response[22..24].copy_from_slice(&(attribute_len as u16).to_be_bytes());
            response[25] = family;
            response[26..28].copy_from_slice(&45678u16.to_be_bytes());
            response[28..].copy_from_slice(&ip);
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    DiscoveryServer {
        addr,
        requests,
        arrived,
        release,
        task,
    }
}

async fn http_server(body: &'static str) -> DiscoveryServer {
    http_server_with_delay(body, Duration::ZERO).await
}

async fn http_server_with_delay(body: &'static str, delay: Duration) -> DiscoveryServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let arrived = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let count = requests.clone();
    let signal = arrived.clone();
    let gate = release.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            signal.add_permits(1);
            gate.acquire().await.unwrap().forget();
            tokio::time::sleep(delay).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    DiscoveryServer {
        addr,
        requests,
        arrived,
        release,
        task,
    }
}

/// Builds an isolated dual-stack pool using only caller-supplied discovery services.
pub(super) async fn nat_pool(servers: Vec<String>, urls: Vec<String>) -> Arc<MePool> {
    let mut pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let pool_mut = Arc::get_mut(&mut pool).unwrap();
    let nat = Arc::get_mut(&mut pool_mut.nat_runtime).unwrap();
    nat.nat_probe = true;
    nat.nat_stun_servers = servers;
    nat.http_ip_detect_urls = urls;
    nat.nat_probe_concurrency = 2;
    pool
}

async fn wait_for_reflection(pool: &MePool, family: IpFamily) -> SocketAddr {
    tokio::time::timeout(TEST_DEADLINE, async {
        loop {
            let cached = {
                let cache = pool.nat_runtime.nat_reflection_cache.lock().await;
                match family {
                    IpFamily::V4 => cache.v4,
                    IpFamily::V6 => cache.v6,
                }
            };
            if let Some((created, addr)) = cached
                && created.elapsed() < Duration::from_secs(600)
            {
                return addr;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pool-owned STUN refresh must publish after its caller is cancelled")
}

#[tokio::test]
async fn expired_stun_refresh_survives_reconnect_timeout() {
    let fast = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let slow = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    fast.release.add_permits(16);
    let pool = nat_pool(vec![fast.addr.to_string(), slow.addr.to_string()], vec![]).await;
    pool.nat_runtime.nat_reflection_cache.lock().await.v4 = Some((
        Instant::now() - Duration::from_secs(601),
        SocketAddr::new(PUBLIC_IP.into(), 1),
    ));
    let caller_pool = pool.clone();
    let caller = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            caller_pool.maybe_reflect_public_addr(IpFamily::V4, None),
        )
        .await
    });
    fast.received().await;
    slow.received().await;
    assert!(caller.await.unwrap().is_err());
    slow.release.add_permits(16);
    assert_eq!(
        wait_for_reflection(&pool, IpFamily::V4).await.ip(),
        PUBLIC_IP
    );
    assert_eq!(fast.requests.load(Ordering::Relaxed), 1);
    assert_eq!(slow.requests.load(Ordering::Relaxed), 1);
    assert_eq!(
        pool.nat_runtime.nat_probe_attempts.load(Ordering::Relaxed),
        0
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn http_discovery_survives_reconnect_timeout() {
    let http = http_server("91.108.56.1").await;
    let pool = nat_pool(vec![], vec![format!("http://{}/", http.addr)]).await;
    let caller_pool = pool.clone();
    let caller = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            caller_pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()),
        )
        .await
    });
    http.received().await;
    assert!(caller.await.unwrap().is_err());
    http.release.add_permits(16);
    tokio::time::timeout(TEST_DEADLINE, async {
        while pool.nat_runtime.nat_ip_detected.read().await.is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pool-owned HTTP discovery must publish after caller cancellation");
    assert_eq!(
        pool.nat_runtime
            .nat_ip_detected
            .read()
            .await
            .map(|observation| observation.ip),
        Some(PUBLIC_IP.into())
    );
    assert_eq!(http.requests.load(Ordering::Relaxed), 1);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn failed_http_discovery_is_reused_during_negative_cache_window() {
    let http = http_server("not an IP address").await;
    http.release.add_permits(16);
    let pool = nat_pool(vec![], vec![format!("http://{}/", http.addr)]).await;
    for _ in 0..2 {
        assert!(
            pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into())
                .await
                .is_none()
        );
    }
    assert_eq!(
        http.requests.load(Ordering::Relaxed),
        1,
        "a failed HTTP lookup must not restart ahead of every STUN/handshake attempt"
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn successful_stun_publication_waits_for_cache_reader() {
    let server = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let pool = nat_pool(vec![server.addr.to_string()], vec![]).await;
    let caller_pool = pool.clone();
    let caller = tokio::spawn(async move {
        caller_pool
            .maybe_reflect_public_addr(IpFamily::V4, None)
            .await
    });
    server.received().await;
    let cache_reader = pool.nat_runtime.nat_reflection_cache.lock().await;
    server.release.add_permits(16);
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(cache_reader);
    assert_eq!(caller.await.unwrap().unwrap().ip(), PUBLIC_IP);
    assert_eq!(
        wait_for_reflection(&pool, IpFamily::V4).await.ip(),
        PUBLIC_IP
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

#[allow(dead_code)]
#[path = "../src/web/http/capability.rs"]
mod capability;

fn capability_at(index: usize) -> [u8; 32] {
    let mut capability = [0xa5u8; 32];
    capability[..8].copy_from_slice(&(index as u64).to_le_bytes());
    capability
}

fn consume_scan(scan: capability::CapabilityScan) {
    black_box(scan.matched.unwrap_u8());
    black_box(scan.matched_index);
}

fn bench_decoy_fasttrack(c: &mut Criterion) {
    for profile_count in [1usize, 32, 256, 1024] {
        let capabilities = (0..profile_count).map(capability_at).collect::<Vec<_>>();
        let miss = [0x5au8; 32];
        let first = capabilities[0];
        let middle = capabilities[profile_count / 2];
        let last = capabilities[profile_count - 1];
        let telemetry = AtomicU64::new(0);
        let mut group = c.benchmark_group(format!("web_decoy_fasttrack/{profile_count}"));

        group.bench_function(BenchmarkId::new("ordinary_enforce", profile_count), |b| {
            b.iter(|| {
                let candidate = capability::bridge_candidate(black_box(None));
                telemetry.fetch_add(1, Ordering::Relaxed);
                black_box(candidate.is_canonical());
            });
        });
        group.bench_function(BenchmarkId::new("ordinary_shadow", profile_count), |b| {
            b.iter(|| {
                let candidate = capability::bridge_candidate(black_box(None));
                telemetry.fetch_add(1, Ordering::Relaxed);
                consume_scan(capability::scan_capabilities(
                    black_box(&capabilities),
                    candidate.scan_bytes(),
                ));
            });
        });
        for (name, candidate) in [
            ("canonical_miss", miss),
            ("canonical_hit_first", first),
            ("canonical_hit_middle", middle),
            ("canonical_hit_last", last),
        ] {
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(candidate);
            let query = format!("bridge={token}");
            group.bench_function(BenchmarkId::new(name, profile_count), |b| {
                b.iter(|| {
                    let candidate = capability::bridge_candidate(black_box(Some(&query)));
                    telemetry.fetch_add(1, Ordering::Relaxed);
                    consume_scan(capability::scan_capabilities(
                        black_box(&capabilities),
                        candidate.scan_bytes(),
                    ));
                });
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_decoy_fasttrack);
criterion_main!(benches);

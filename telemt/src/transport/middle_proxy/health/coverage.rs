use super::*;
use std::sync::atomic::Ordering;

/// Selects globally because the Active cap is shared across DCs and address families.
pub(super) async fn transfer_coverage(
    pool: &Arc<MePool>,
    rng: &Arc<SecureRandom>,
    dc: i32,
    endpoint: SocketAddr,
    required: usize,
) -> Option<bool> {
    let capacity = pool
        .reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            dc,
            endpoint,
        )
        .await?;
    drop(capacity);
    let authority = pool.floor_authority();
    let endpoints = pool.endpoint_snapshot.load_full();
    let generation = pool.current_generation();
    let writers = pool.writers.read().await;
    let activity = pool.registry.writer_activity_snapshot().await;
    let mut counts = HashMap::new();
    for writer in writers.iter() {
        if !writer.draining.load(Ordering::Acquire)
            && writer.generation == generation
            && WriterContour::from_u8(writer.contour.load(Ordering::Acquire))
                == WriterContour::Active
            && endpoints.contains_dc_endpoint(writer.writer_dc, writer.addr)
        {
            *counts
                .entry((writer.writer_dc, writer.addr.is_ipv4()))
                .or_insert(0usize) += 1;
        }
    }
    let mut candidates = Vec::new();
    for writer in writers.iter() {
        if writer.draining.load(Ordering::Acquire)
            || WriterContour::from_u8(writer.contour.load(Ordering::Acquire))
                != WriterContour::Active
        {
            continue;
        }
        let role = WriterRole::from_writer(writer);
        let obsolete = writer.generation != generation
            || !endpoints.contains_dc_endpoint(writer.writer_dc, writer.addr);
        let protected = pool.required_writers_for_dc_with_floor_mode(
            endpoints
                .endpoints_for_dc_family(writer.writer_dc, role.family)
                .len(),
            false,
        );
        if !obsolete
            && counts
                .get(&(writer.writer_dc, writer.addr.is_ipv4()))
                .copied()
                .unwrap_or(0)
                <= protected
        {
            continue;
        }
        let busy = activity
            .bound_clients_by_writer
            .get(&writer.id)
            .copied()
            .unwrap_or(0)
            > 0;
        candidates.push((busy, !obsolete, writer.created_at, writer.id, role));
    }
    drop(writers);
    candidates
        .sort_unstable_by_key(|candidate| (candidate.0, candidate.1, candidate.2, candidate.3));
    for (busy, _, _, id, role) in candidates {
        let reservation = if busy {
            pool.registry
                .try_reserve_writer_replacement_preserving_clients(id)
                .await
        } else {
            pool.registry.try_reserve_writer_replacement(id).await
        };
        let Some(mut reservation) = reservation else {
            continue;
        };
        return Some(matches!(
            tokio::time::timeout(
                pool.reconnect_runtime.me_one_timeout,
                pool.replace_writer_with_generation_contour_for_dc(
                    endpoint,
                    rng.as_ref(),
                    generation,
                    WriterContour::Active,
                    dc,
                    role,
                    WriterReplacementPurpose::CoverageTransfer {
                        authority,
                        receiver_floor: required
                    },
                    &mut reservation,
                ),
            )
            .await,
            Ok(Ok(()))
        ));
    }
    None
}

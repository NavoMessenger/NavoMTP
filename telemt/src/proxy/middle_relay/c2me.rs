use super::*;

pub(in crate::proxy::middle_relay) enum C2MeCommand {
    Data {
        payload: PooledBuffer,
        flags: u32,
        _permit: OwnedSemaphorePermit,
    },
    Close,
}

pub(super) fn should_yield_c2me_sender(sent_since_yield: usize, has_backlog: bool) -> bool {
    has_backlog && sent_since_yield >= C2ME_SENDER_FAIRNESS_BUDGET
}

pub(super) fn c2me_payload_permits(payload_len: usize) -> u32 {
    payload_len
        .max(1)
        .div_ceil(C2ME_QUEUED_BYTE_PERMIT_UNIT)
        .min(u32::MAX as usize) as u32
}

pub(super) fn c2me_queued_permit_budget(channel_capacity: usize, frame_limit: usize) -> usize {
    channel_capacity
        .saturating_mul(C2ME_QUEUED_PERMITS_PER_SLOT)
        .max(c2me_payload_permits(frame_limit) as usize)
        .max(1)
}

pub(super) async fn acquire_c2me_payload_permit(
    semaphore: &Arc<Semaphore>,
    payload_len: usize,
    send_timeout: Option<Duration>,
    stats: &Stats,
) -> Result<OwnedSemaphorePermit> {
    let permits = c2me_payload_permits(payload_len);
    let acquire = semaphore.clone().acquire_many_owned(permits);
    match send_timeout {
        Some(send_timeout) => match timeout(send_timeout, acquire).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(ProxyError::Proxy("ME sender byte budget closed".into())),
            Err(_) => {
                stats.increment_me_c2me_send_timeout_total();
                Err(ProxyError::Proxy("ME sender byte budget timeout".into()))
            }
        },
        None => acquire
            .await
            .map_err(|_| ProxyError::Proxy("ME sender byte budget closed".into())),
    }
}

pub(super) async fn enqueue_c2me_command_in(
    shared: &ProxySharedState,
    tx: &mpsc::Sender<C2MeCommand>,
    cmd: C2MeCommand,
    send_timeout: Option<Duration>,
    stats: &Stats,
) -> std::result::Result<(), mpsc::error::SendError<C2MeCommand>> {
    match tx.try_send(cmd) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(cmd)) => Err(mpsc::error::SendError(cmd)),
        Err(mpsc::error::TrySendError::Full(cmd)) => {
            stats.increment_me_c2me_send_full_total();
            stats.increment_me_c2me_send_high_water_total();
            note_relay_pressure_event_in(shared);
            // Cooperative yield reduces burst catch-up when the per-conn queue is near saturation.
            if tx.capacity() <= C2ME_SOFT_PRESSURE_MIN_FREE_SLOTS {
                tokio::task::yield_now().await;
            }
            let reserve_result = match send_timeout {
                Some(send_timeout) => match timeout(send_timeout, tx.reserve()).await {
                    Ok(result) => result,
                    Err(_) => {
                        stats.increment_me_c2me_send_timeout_total();
                        return Err(mpsc::error::SendError(cmd));
                    }
                },
                None => tx.reserve().await,
            };
            match reserve_result {
                Ok(permit) => {
                    permit.send(cmd);
                    Ok(())
                }
                Err(_) => {
                    stats.increment_me_c2me_send_timeout_total();
                    Err(mpsc::error::SendError(cmd))
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn enqueue_c2me_command(
    tx: &mpsc::Sender<C2MeCommand>,
    cmd: C2MeCommand,
    send_timeout: Option<Duration>,
    stats: &Stats,
) -> std::result::Result<(), mpsc::error::SendError<C2MeCommand>> {
    let shared = ProxySharedState::new();
    enqueue_c2me_command_in(shared.as_ref(), tx, cmd, send_timeout, stats).await
}

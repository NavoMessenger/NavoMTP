use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc};

use super::super::codec::{WriterBytePermit, WriterCommand};
use crate::config::defaults::ME_WRITER_BYTE_PERMIT_UNIT_BYTES;
use crate::stats::Stats;
use crate::stream::PooledBuffer;

const RPC_WRITER_FRAME_CAPACITY_OVERHEAD_BYTES: usize = 27;
pub(super) const LEGACY_PROXY_REQ_SOURCE_CAPACITY_OVERHEAD_BYTES: usize = 128;

pub(super) enum WriterCommandReserveError {
    Closed,
    TimedOut,
}

pub(super) enum WriterByteReserveError {
    Closed,
    TimedOut,
}

pub(super) fn proxy_tag_array(tag: Option<&[u8]>) -> Option<[u8; 16]> {
    tag.and_then(|tag| <[u8; 16]>::try_from(tag).ok())
}

pub(super) fn proxy_req_payload_from_command(
    cmd: WriterCommand,
) -> Option<(PooledBuffer, OwnedSemaphorePermit)> {
    match cmd {
        WriterCommand::ProxyReq(command) => Some((command.payload, command._permit)),
        _ => None,
    }
}

pub(super) fn payload_permit_from_data_command(cmd: WriterCommand) -> Option<OwnedSemaphorePermit> {
    match cmd {
        WriterCommand::Data { _permit, .. } => _permit,
        _ => None,
    }
}

pub(super) async fn reserve_writer_command_slot(
    tx: &mpsc::Sender<WriterCommand>,
    deadline: Option<Instant>,
) -> std::result::Result<mpsc::OwnedPermit<WriterCommand>, WriterCommandReserveError> {
    let reserve = tx.clone().reserve_owned();
    match deadline {
        Some(deadline) => {
            match tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), reserve)
                .await
            {
                Ok(Ok(permit)) => Ok(permit),
                Ok(Err(_)) => Err(WriterCommandReserveError::Closed),
                Err(_) => Err(WriterCommandReserveError::TimedOut),
            }
        }
        None => reserve.await.map_err(|_| WriterCommandReserveError::Closed),
    }
}

pub(super) fn writer_send_deadline(wait: Option<Duration>) -> Option<Instant> {
    wait.map(|wait| Instant::now() + wait)
}

fn writer_resident_permits(
    source_capacity: usize,
    encoded_payload_len: usize,
) -> Option<(u32, usize)> {
    let resident_bytes = source_capacity
        .checked_add(encoded_payload_len)?
        .checked_add(RPC_WRITER_FRAME_CAPACITY_OVERHEAD_BYTES)?;
    let permits = resident_bytes.div_ceil(ME_WRITER_BYTE_PERMIT_UNIT_BYTES);
    let permits = u32::try_from(permits).ok()?;
    let reserved_bytes = (permits as usize).checked_mul(ME_WRITER_BYTE_PERMIT_UNIT_BYTES)?;
    Some((
        permits.max(1),
        reserved_bytes.max(ME_WRITER_BYTE_PERMIT_UNIT_BYTES),
    ))
}

pub(super) fn proxy_req_resident_permits(
    source_capacity: usize,
    data_len: usize,
    proxy_tag: Option<&[u8]>,
    proto_flags: u32,
) -> Option<(u32, usize)> {
    writer_resident_permits(
        source_capacity,
        super::super::wire::proxy_req_payload_len(data_len, proxy_tag, proto_flags),
    )
}

pub(super) fn try_reserve_writer_bytes(
    byte_budget: &Arc<Semaphore>,
    permits: u32,
    reserved_bytes: usize,
    stats: &Arc<Stats>,
) -> std::result::Result<WriterBytePermit, TryAcquireError> {
    byte_budget
        .clone()
        .try_acquire_many_owned(permits)
        .map(|permit| WriterBytePermit::new(permit, reserved_bytes, stats.clone()))
}

pub(super) async fn reserve_writer_bytes(
    byte_budget: &Arc<Semaphore>,
    permits: u32,
    reserved_bytes: usize,
    deadline: Option<Instant>,
    stats: &Arc<Stats>,
) -> std::result::Result<WriterBytePermit, WriterByteReserveError> {
    match try_reserve_writer_bytes(byte_budget, permits, reserved_bytes, stats) {
        Ok(permit) => return Ok(permit),
        Err(TryAcquireError::Closed) => return Err(WriterByteReserveError::Closed),
        Err(TryAcquireError::NoPermits) => {
            stats.increment_me_writer_byte_budget_wait_total();
        }
    }

    let acquire = byte_budget.clone().acquire_many_owned(permits);
    match deadline {
        Some(deadline) => {
            match tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), acquire)
                .await
            {
                Ok(Ok(permit)) => Ok(WriterBytePermit::new(permit, reserved_bytes, stats.clone())),
                Ok(Err(_)) => Err(WriterByteReserveError::Closed),
                Err(_) => {
                    stats.increment_me_writer_byte_budget_timeout_total();
                    Err(WriterByteReserveError::TimedOut)
                }
            }
        }
        None => acquire
            .await
            .map(|permit| WriterBytePermit::new(permit, reserved_bytes, stats.clone()))
            .map_err(|_| WriterByteReserveError::Closed),
    }
}

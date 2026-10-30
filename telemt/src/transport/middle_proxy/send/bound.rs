use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc::error::TrySendError;
use tracing::warn;

use super::super::MePool;
use super::super::codec::WriterCommand;
use super::super::wire::build_proxy_req_payload;
use super::reservation::{
    WriterByteReserveError, WriterCommandReserveError, payload_permit_from_data_command,
    reserve_writer_bytes, reserve_writer_command_slot, writer_send_deadline,
};
use crate::error::{ProxyError, Result};

pub(super) enum BoundWriterSendOutcome {
    Sent,
    Retry(Option<OwnedSemaphorePermit>),
}

impl MePool {
    pub(super) async fn try_send_bound_writer(
        self: &Arc<Self>,
        conn_id: u64,
        client_addr: SocketAddr,
        data: &[u8],
        proto_flags: u32,
        tag: Option<&[u8]>,
        writer_byte_permits: u32,
        writer_reserved_bytes: usize,
        payload_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<BoundWriterSendOutcome> {
        let Some((current, current_meta)) = self.registry.get_writer_with_meta(conn_id).await
        else {
            return Ok(BoundWriterSendOutcome::Retry(payload_permit));
        };
        let deadline = writer_send_deadline(self.route_runtime.me_route_blocking_send_timeout);
        let writer_permit = match reserve_writer_bytes(
            &current.byte_budget,
            writer_byte_permits,
            writer_reserved_bytes,
            deadline,
            &self.stats,
        )
        .await
        {
            Ok(permit) => permit,
            Err(WriterByteReserveError::TimedOut) => {
                self.stats
                    .increment_me_writer_pick_full_total(self.writer_pick_mode());
                return Err(ProxyError::Proxy(
                    "ME writer byte budget full within blocking send timeout".into(),
                ));
            }
            Err(WriterByteReserveError::Closed) => {
                warn!(
                    writer_id = current.writer_id,
                    "ME writer byte budget closed"
                );
                self.remove_writer_and_close_clients(current.writer_id)
                    .await;
                return Ok(BoundWriterSendOutcome::Retry(payload_permit));
            }
        };
        let payload = build_proxy_req_payload(
            conn_id,
            client_addr,
            current_meta.our_addr,
            data,
            tag,
            proto_flags,
        );
        let command = WriterCommand::Data {
            payload,
            _permit: payload_permit,
            writer_permit,
        };
        match current.tx.try_send(command) {
            Ok(()) => {
                self.note_hybrid_route_success();
                Ok(BoundWriterSendOutcome::Sent)
            }
            Err(TrySendError::Full(cmd)) => {
                match reserve_writer_command_slot(&current.tx, deadline).await {
                    Ok(permit) => {
                        permit.send(cmd);
                        self.note_hybrid_route_success();
                        return Ok(BoundWriterSendOutcome::Sent);
                    }
                    Err(WriterCommandReserveError::TimedOut) => {
                        self.stats
                            .increment_me_writer_pick_full_total(self.writer_pick_mode());
                        return Err(ProxyError::Proxy(
                            "ME writer channel full within blocking send timeout".into(),
                        ));
                    }
                    Err(WriterCommandReserveError::Closed) => {}
                }
                let payload_permit = payload_permit_from_data_command(cmd);
                warn!(writer_id = current.writer_id, "ME writer channel closed");
                self.remove_writer_and_close_clients(current.writer_id)
                    .await;
                Ok(BoundWriterSendOutcome::Retry(payload_permit))
            }
            Err(TrySendError::Closed(cmd)) => {
                let payload_permit = payload_permit_from_data_command(cmd);
                warn!(writer_id = current.writer_id, "ME writer channel closed");
                self.remove_writer_and_close_clients(current.writer_id)
                    .await;
                Ok(BoundWriterSendOutcome::Retry(payload_permit))
            }
        }
    }
}

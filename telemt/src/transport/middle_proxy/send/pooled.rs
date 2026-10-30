use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc::error::TrySendError;
use tracing::warn;

use super::super::MePool;
use super::super::codec::{ProxyReqCommand, WriterCommand};
use super::reservation::{
    WriterByteReserveError, WriterCommandReserveError, proxy_req_payload_from_command,
    proxy_req_resident_permits, proxy_tag_array, reserve_writer_bytes, reserve_writer_command_slot,
    writer_send_deadline,
};
use crate::error::{ProxyError, Result};
use crate::stream::PooledBuffer;

impl MePool {
    /// Send RPC_PROXY_REQ while keeping the first bound-writer path allocation-light.
    /// The client byte permit follows the payload until writer completion or command drop.
    pub async fn send_proxy_req_pooled(
        self: &Arc<Self>,
        conn_id: u64,
        target_dc: i16,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        payload: PooledBuffer,
        _permit: OwnedSemaphorePermit,
        proto_flags: u32,
        tag_override: Option<[u8; 16]>,
    ) -> Result<()> {
        let tag = tag_override.or_else(|| proxy_tag_array(self.proxy_tag.as_deref()));
        let Some((writer_byte_permits, writer_reserved_bytes)) = proxy_req_resident_permits(
            payload.capacity(),
            payload.len(),
            tag.as_ref().map(|tag| tag.as_slice()),
            proto_flags,
        ) else {
            self.stats.increment_me_writer_byte_budget_oversize_total();
            return Err(ProxyError::Proxy(
                "ME writer payload residency calculation overflow".into(),
            ));
        };
        if writer_byte_permits as usize > self.writer_lifecycle.writer_byte_budget_permits {
            self.stats.increment_me_writer_byte_budget_oversize_total();
            return Err(ProxyError::Proxy(
                "ME writer payload exceeds configured byte budget".into(),
            ));
        }

        if let Some((current, current_meta)) = self.registry.get_writer_with_meta(conn_id).await {
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
                    return self
                        .send_proxy_req(
                            conn_id,
                            target_dc,
                            client_addr,
                            our_addr,
                            payload.as_ref(),
                            proto_flags,
                            tag.as_ref().map(|tag| tag.as_slice()),
                            Some(_permit),
                        )
                        .await;
                }
            };
            let command = WriterCommand::ProxyReq(ProxyReqCommand {
                conn_id,
                client_addr,
                our_addr: current_meta.our_addr,
                proto_flags,
                proxy_tag: tag,
                payload,
                _permit,
                writer_permit,
            });
            match current.tx.try_send(command) {
                Ok(()) => {
                    self.note_hybrid_route_success();
                    return Ok(());
                }
                Err(TrySendError::Full(cmd)) => {
                    match reserve_writer_command_slot(&current.tx, deadline).await {
                        Ok(permit) => {
                            permit.send(cmd);
                            self.note_hybrid_route_success();
                            return Ok(());
                        }
                        Err(WriterCommandReserveError::TimedOut) => {
                            self.stats
                                .increment_me_writer_pick_full_total(self.writer_pick_mode());
                            return Err(ProxyError::Proxy(
                                "ME writer channel full within blocking send timeout".into(),
                            ));
                        }
                        Err(WriterCommandReserveError::Closed) => {
                            let Some((payload, _permit)) = proxy_req_payload_from_command(cmd)
                            else {
                                return Err(ProxyError::Proxy(
                                    "ME writer rejected unexpected command type".into(),
                                ));
                            };
                            warn!(writer_id = current.writer_id, "ME writer channel closed");
                            self.remove_writer_and_close_clients(current.writer_id)
                                .await;
                            return self
                                .send_proxy_req(
                                    conn_id,
                                    target_dc,
                                    client_addr,
                                    our_addr,
                                    payload.as_ref(),
                                    proto_flags,
                                    tag.as_ref().map(|tag| tag.as_slice()),
                                    Some(_permit),
                                )
                                .await;
                        }
                    }
                }
                Err(TrySendError::Closed(cmd)) => {
                    let Some((payload, _permit)) = proxy_req_payload_from_command(cmd) else {
                        return Err(ProxyError::Proxy(
                            "ME writer rejected unexpected command type".into(),
                        ));
                    };
                    warn!(writer_id = current.writer_id, "ME writer channel closed");
                    self.remove_writer_and_close_clients(current.writer_id)
                        .await;
                    return self
                        .send_proxy_req(
                            conn_id,
                            target_dc,
                            client_addr,
                            our_addr,
                            payload.as_ref(),
                            proto_flags,
                            tag.as_ref().map(|tag| tag.as_slice()),
                            Some(_permit),
                        )
                        .await;
                }
            }
        }

        self.send_proxy_req(
            conn_id,
            target_dc,
            client_addr,
            our_addr,
            payload.as_ref(),
            proto_flags,
            tag.as_ref().map(|tag| tag.as_slice()),
            Some(_permit),
        )
        .await
    }
}

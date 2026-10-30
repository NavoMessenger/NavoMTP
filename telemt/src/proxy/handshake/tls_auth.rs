use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::protocol::tls;

type HmacSha256 = Hmac<Sha256>;

/// Parsed TLS authentication material extracted from a ClientHello candidate.
#[derive(Clone, Copy)]
pub(super) struct ParsedTlsAuthMaterial {
    digest: [u8; tls::TLS_DIGEST_LEN],
    session_id: [u8; 32],
    session_id_len: usize,
    now: i64,
    ignore_time_skew: bool,
    boot_time_cap_secs: u32,
}

/// Successful TLS secret validation output used by the handshake state machine.
#[derive(Clone, Copy)]
pub(super) struct TlsCandidateValidation {
    pub(super) digest: [u8; tls::TLS_DIGEST_LEN],
    pub(super) session_id: [u8; 32],
    pub(super) session_id_len: usize,
}

/// Parse TLS auth digest and session-id material from a candidate handshake.
pub(super) fn parse_tls_auth_material(
    handshake: &[u8],
    ignore_time_skew: bool,
    replay_window_secs: u64,
) -> Option<ParsedTlsAuthMaterial> {
    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        return None;
    }

    let digest: [u8; tls::TLS_DIGEST_LEN] = handshake
        [tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .try_into()
        .ok()?;

    let session_id_len_pos = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN;
    let session_id_len = usize::from(handshake.get(session_id_len_pos).copied()?);
    if session_id_len > 32 {
        return None;
    }
    let session_id_start = session_id_len_pos + 1;
    if handshake.len() < session_id_start + session_id_len {
        return None;
    }

    let mut session_id = [0u8; 32];
    session_id[..session_id_len]
        .copy_from_slice(&handshake[session_id_start..session_id_start + session_id_len]);

    let now = if !ignore_time_skew {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        i64::try_from(d.as_secs()).ok()?
    } else {
        0_i64
    };

    let replay_window_u32 = u32::try_from(replay_window_secs).unwrap_or(u32::MAX);
    let boot_time_cap_secs = if ignore_time_skew {
        0
    } else {
        tls::BOOT_TIME_MAX_SECS
            .min(replay_window_u32)
            .min(tls::BOOT_TIME_COMPAT_MAX_SECS)
    };

    Some(ParsedTlsAuthMaterial {
        digest,
        session_id,
        session_id_len,
        now,
        ignore_time_skew,
        boot_time_cap_secs,
    })
}

fn compute_tls_hmac_zeroed_digest(secret: &[u8], handshake: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&handshake[..tls::TLS_DIGEST_POS]);
    mac.update(&[0u8; tls::TLS_DIGEST_LEN]);
    mac.update(&handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN..]);
    Some(mac.finalize().into_bytes().into())
}

/// Validate a candidate secret against parsed TLS authentication material.
pub(super) fn validate_tls_secret_candidate(
    parsed: &ParsedTlsAuthMaterial,
    handshake: &[u8],
    secret: &[u8],
) -> Option<TlsCandidateValidation> {
    let computed = compute_tls_hmac_zeroed_digest(secret, handshake)?;
    if !bool::from(parsed.digest[..28].ct_eq(&computed[..28])) {
        return None;
    }

    let timestamp = u32::from_le_bytes([
        parsed.digest[28] ^ computed[28],
        parsed.digest[29] ^ computed[29],
        parsed.digest[30] ^ computed[30],
        parsed.digest[31] ^ computed[31],
    ]);

    if !parsed.ignore_time_skew {
        let is_boot_time = parsed.boot_time_cap_secs > 0 && timestamp < parsed.boot_time_cap_secs;
        if !is_boot_time {
            let time_diff = parsed.now - i64::from(timestamp);
            if !(tls::TIME_SKEW_MIN..=tls::TIME_SKEW_MAX).contains(&time_diff) {
                return None;
            }
        }
    }

    Some(TlsCandidateValidation {
        digest: parsed.digest,
        session_id: parsed.session_id,
        session_id_len: parsed.session_id_len,
    })
}

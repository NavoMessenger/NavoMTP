use bytes::{BufMut, Bytes, BytesMut};

use crate::config::WebLimitsConfig;

/// Fixed WEB frame header size.
pub(crate) const HEADER_BYTES: usize = 8;
/// Largest stream identifier representable by the WEB frame header.
pub(crate) const MAX_STREAM_ID: u32 = 0x00ff_ffff;
/// Initial bidirectional stream credit.
pub(crate) const INITIAL_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
/// Maximum data chunk emitted by the server.
pub(crate) const DATA_CHUNK_BYTES: usize = 64 * 1024;

/// WEB frame type codes shared with Telegram Desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FrameType {
    /// Opens a logical MTProxy stream.
    Open = 0x01,
    /// Carries logical-stream payload bytes.
    Data = 0x02,
    /// Closes a logical stream.
    Close = 0x03,
    /// Returns consumed flow-control credit.
    Window = 0x04,
    /// Requests an application-level liveness response.
    Ping = 0x05,
    /// Answers application-level liveness traffic.
    Pong = 0x06,
    /// Starts one WEB carrier session.
    Hello = 0x10,
    /// Confirms WEB carrier session creation.
    Welcome = 0x11,
    /// Terminates a WEB carrier session.
    Bye = 0x1f,
}

impl FrameType {
    fn parse(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Open),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Close),
            0x04 => Some(Self::Window),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::Pong),
            0x10 => Some(Self::Hello),
            0x11 => Some(Self::Welcome),
            0x1f => Some(Self::Bye),
            _ => None,
        }
    }
}

/// One parsed frame borrowing its payload from the HTTP request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame<'a> {
    /// Parsed frame type.
    pub(crate) frame_type: FrameType,
    /// Logical 24-bit stream identifier.
    pub(crate) stream_id: u32,
    /// Borrowed frame payload.
    pub(crate) payload: &'a [u8],
}

/// Protocol parse or shape failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// A carrier body contained no frame.
    EmptyBatch,
    /// A carrier body exceeded the configured frame count.
    TooManyFrames,
    /// A frame header or payload was truncated.
    Incomplete,
    /// A frame payload exceeded its configured ceiling.
    PayloadLimit,
    /// The frame type code is not defined.
    UnknownType,
    /// A known frame violated direction-specific grammar.
    InvalidShape,
}

/// Parses and validates all frame boundaries without copying payloads.
pub(crate) fn parse_all<'a>(
    input: &'a [u8],
    limits: &WebLimitsConfig,
) -> std::result::Result<Vec<Frame<'a>>, FrameError> {
    if input.is_empty() {
        return Err(FrameError::EmptyBatch);
    }
    let mut remaining = input;
    let mut frames = Vec::with_capacity(remaining.len().div_ceil(HEADER_BYTES).min(16));
    while !remaining.is_empty() {
        if frames.len() >= limits.max_frames_per_body {
            return Err(FrameError::TooManyFrames);
        }
        if remaining.len() < HEADER_BYTES {
            return Err(FrameError::Incomplete);
        }
        let frame_type = FrameType::parse(remaining[0]).ok_or(FrameError::UnknownType)?;
        let stream_id =
            u32::from(remaining[1]) << 16 | u32::from(remaining[2]) << 8 | u32::from(remaining[3]);
        let payload_len =
            u32::from_be_bytes([remaining[4], remaining[5], remaining[6], remaining[7]]) as usize;
        if payload_len > limits.max_frame_payload_bytes {
            return Err(FrameError::PayloadLimit);
        }
        let frame_len = HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(FrameError::PayloadLimit)?;
        if frame_len > remaining.len() {
            return Err(FrameError::Incomplete);
        }
        frames.push(Frame {
            frame_type,
            stream_id,
            payload: &remaining[HEADER_BYTES..frame_len],
        });
        remaining = &remaining[frame_len..];
    }
    Ok(frames)
}

/// Enforces the client-to-server frame grammar.
pub(crate) fn validate_client_shape(frame: Frame<'_>) -> std::result::Result<(), FrameError> {
    if frame.stream_id == 0 {
        return if frame.frame_type == FrameType::Pong && frame.payload.len() <= 64 {
            Ok(())
        } else {
            Err(FrameError::InvalidShape)
        };
    }
    match frame.frame_type {
        FrameType::Open | FrameType::Close if frame.payload.is_empty() => Ok(()),
        FrameType::Data if !frame.payload.is_empty() => Ok(()),
        FrameType::Window => window_amount(frame.payload).map(|_| ()),
        _ => Err(FrameError::InvalidShape),
    }
}

/// Validates the exact first-session HELLO body.
pub(crate) fn validate_hello(input: &[u8], limits: &WebLimitsConfig) -> bool {
    let Ok(frames) = parse_all(input, limits) else {
        return false;
    };
    frames.len() == 1
        && frames[0].frame_type == FrameType::Hello
        && frames[0].stream_id == 0
        && frames[0].payload == [1]
}

/// Encodes one complete WEB frame.
pub(crate) fn encode(frame_type: FrameType, stream_id: u32, payload: &[u8]) -> Bytes {
    let mut output = BytesMut::with_capacity(HEADER_BYTES + payload.len());
    output.put_u8(frame_type as u8);
    output.put_u8((stream_id >> 16) as u8);
    output.put_u8((stream_id >> 8) as u8);
    output.put_u8(stream_id as u8);
    output.put_u32(payload.len() as u32);
    output.extend_from_slice(payload);
    output.freeze()
}

/// Decodes a non-zero WINDOW delta.
pub(crate) fn window_amount(payload: &[u8]) -> std::result::Result<u32, FrameError> {
    let bytes: [u8; 4] = payload.try_into().map_err(|_| FrameError::InvalidShape)?;
    let amount = u32::from_be_bytes(bytes);
    (amount != 0)
        .then_some(amount)
        .ok_or(FrameError::InvalidShape)
}

/// Encodes a WINDOW delta payload.
pub(crate) fn window_payload(amount: u32) -> [u8; 4] {
    amount.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_and_welcome_match_reference_bytes() {
        let limits = WebLimitsConfig::default();
        let hello = encode(FrameType::Hello, 0, &[1]);
        assert_eq!(hello.as_ref(), &hex::decode("100000000000000101").unwrap());
        assert!(validate_hello(&hello, &limits));
        assert_eq!(
            encode(FrameType::Welcome, 0, &[]).as_ref(),
            &hex::decode("1100000000000000").unwrap()
        );
    }

    #[test]
    fn parser_rejects_excessive_payload_before_slicing() {
        let limits = WebLimitsConfig {
            max_frame_payload_bytes: 4,
            ..WebLimitsConfig::default()
        };
        let frame = encode(FrameType::Data, 1, &[0; 5]);
        assert_eq!(parse_all(&frame, &limits), Err(FrameError::PayloadLimit));
    }

    #[test]
    fn client_shape_rejects_control_types_on_stream_zero() {
        let frame = Frame {
            frame_type: FrameType::Ping,
            stream_id: 0,
            payload: &[],
        };
        assert_eq!(validate_client_shape(frame), Err(FrameError::InvalidShape));
    }

    #[test]
    fn stream_frames_match_client_reference_vectors() {
        assert_eq!(
            encode(FrameType::Open, 17, &[]).as_ref(),
            &hex::decode("0100001100000000").unwrap()
        );
        assert_eq!(
            encode(FrameType::Data, 17, b"round trip").as_ref(),
            &hex::decode("020000110000000a726f756e642074726970").unwrap()
        );
        assert_eq!(
            encode(FrameType::Window, 17, &10u32.to_be_bytes()).as_ref(),
            &hex::decode("04000011000000040000000a").unwrap()
        );
        assert_eq!(
            encode(FrameType::Open, 0x00ff_ffff, &[]).as_ref(),
            &hex::decode("01ffffff00000000").unwrap()
        );
    }

    #[test]
    fn parser_rejects_empty_truncated_and_excessive_batches() {
        let mut limits = WebLimitsConfig::default();
        assert_eq!(parse_all(&[], &limits), Err(FrameError::EmptyBatch));
        assert_eq!(
            parse_all(&hex::decode("0200000100000001").unwrap(), &limits),
            Err(FrameError::Incomplete)
        );
        limits.max_frames_per_body = 1;
        let mut body = encode(FrameType::Pong, 0, &[]).to_vec();
        body.extend_from_slice(&encode(FrameType::Pong, 0, &[]));
        assert_eq!(parse_all(&body, &limits), Err(FrameError::TooManyFrames));
    }

    #[test]
    fn client_shape_rejects_empty_data_and_zero_window() {
        let empty_data = Frame {
            frame_type: FrameType::Data,
            stream_id: 1,
            payload: &[],
        };
        let zero_window = Frame {
            frame_type: FrameType::Window,
            stream_id: 1,
            payload: &[0; 4],
        };
        assert_eq!(
            validate_client_shape(empty_data),
            Err(FrameError::InvalidShape)
        );
        assert_eq!(
            validate_client_shape(zero_window),
            Err(FrameError::InvalidShape)
        );
    }
}

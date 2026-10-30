use base64::Engine as _;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const NON_CANONICAL_BRIDGE_CANDIDATE: [u8; 32] = [0; 32];

/// Parsed public bridge query without an allocated credential string.
#[derive(Clone, Copy)]
pub(super) enum BridgeCandidate {
    /// The query cannot authenticate a bridge under the public request grammar.
    NonCanonical,
    /// Exact canonical base64url capability bytes.
    Canonical([u8; 32]),
}

impl BridgeCandidate {
    /// Returns whether this query can authenticate a bridge.
    pub(super) const fn is_canonical(self) -> bool {
        matches!(self, Self::Canonical(_))
    }

    /// Returns the candidate used by the legacy full-scan path.
    pub(super) fn scan_bytes(&self) -> &[u8; 32] {
        match self {
            Self::NonCanonical => &NON_CANONICAL_BRIDGE_CANDIDATE,
            Self::Canonical(candidate) => candidate,
        }
    }
}

/// Decodes an exact canonical bridge query without allocating credential strings.
pub(super) fn bridge_candidate(query: Option<&str>) -> BridgeCandidate {
    let Some(value) = query.and_then(|query| query.strip_prefix("bridge=")) else {
        return BridgeCandidate::NonCanonical;
    };
    canonical_credential(value.as_bytes())
        .map(BridgeCandidate::Canonical)
        .unwrap_or(BridgeCandidate::NonCanonical)
}

/// Decodes one exact canonical 32-byte base64url credential.
pub(super) fn canonical_credential(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() != 43 {
        return None;
    }
    let mut decoded = [0u8; 32];
    let Ok(decoded_len) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode_slice(value, &mut decoded)
    else {
        return None;
    };
    let mut canonical = [0u8; 43];
    let Ok(encoded_len) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_slice(decoded, &mut canonical)
    else {
        return None;
    };
    if decoded_len != decoded.len()
        || encoded_len != canonical.len()
        || !bool::from(canonical.ct_eq(value))
    {
        return None;
    }
    Some(decoded)
}

/// Internal result of one complete capability-table scan.
pub(super) struct CapabilityScan {
    /// Whether any capability matched.
    pub(super) matched: Choice,
    /// Matching table position selected without a data-dependent branch.
    pub(super) matched_index: u64,
    #[cfg(test)]
    /// Exact comparison count exposed only to deterministic unit tests.
    pub(super) comparisons: usize,
}

/// Scans every configured capability without candidate-dependent control flow.
pub(super) fn scan_capabilities(capabilities: &[[u8; 32]], candidate: &[u8; 32]) -> CapabilityScan {
    let mut matched = Choice::from(0);
    let mut matched_index = 0u64;
    #[cfg(test)]
    let mut comparisons = 0usize;
    for (index, capability) in capabilities.iter().enumerate() {
        let equal = capability.ct_eq(candidate);
        matched_index = u64::conditional_select(&matched_index, &(index as u64), equal);
        matched |= equal;
        #[cfg(test)]
        {
            comparisons += 1;
        }
    }
    CapabilityScan {
        matched,
        matched_index,
        #[cfg(test)]
        comparisons,
    }
}

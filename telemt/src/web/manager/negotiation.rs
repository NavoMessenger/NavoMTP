use std::net::IpAddr;

use crate::config::WebCarrier;

/// Stable client classification used only for carrier negotiation and learning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CarrierClientClass {
    /// A client that did not present server-bridge negotiation metadata.
    Legacy,
    /// The generated bridge presented the explicit capability marker.
    Bridge,
    /// Strict same-origin browser metadata survived while the marker did not.
    BrowserHint,
    /// A native iOS client classified for diagnostics and learning only.
    Ios,
}

impl CarrierClientClass {
    /// Returns the non-sensitive token exposed by WEB debug lifecycle records.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Bridge => "bridge",
            Self::BrowserHint => "browser-hint",
            Self::Ios => "ios",
        }
    }
}

/// Canonical carrier failure category reported by the generated bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierFailure {
    /// The cumulative attempt deadline elapsed.
    Timeout,
    /// The browser observed a network failure.
    Network,
    /// A WebSocket upgrade or post-upgrade acknowledgement failed.
    Upgrade,
    /// The carrier returned an unexpected HTTP result.
    Http,
    /// The carrier violated its response or framing contract.
    Protocol,
}

impl CarrierFailure {
    /// Complete fixed bridge failure set in stable metric order.
    pub(crate) const ALL: [Self; 5] = [
        Self::Timeout,
        Self::Network,
        Self::Upgrade,
        Self::Http,
        Self::Protocol,
    ];

    /// Returns the stable fixed-slot index used by process telemetry.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Timeout => 0,
            Self::Network => 1,
            Self::Upgrade => 2,
            Self::Http => 3,
            Self::Protocol => 4,
        }
    }

    /// Parses one canonical bridge failure token.
    pub(crate) const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"timeout" => Some(Self::Timeout),
            b"network" => Some(Self::Network),
            b"upgrade" => Some(Self::Upgrade),
            b"http" => Some(Self::Http),
            b"protocol" => Some(Self::Protocol),
            _ => None,
        }
    }

    /// Returns the canonical non-sensitive failure token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Network => "network",
            Self::Upgrade => "upgrade",
            Self::Http => "http",
            Self::Protocol => "protocol",
        }
    }
}

/// Validated carrier capability set sent by a negotiation-capable client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierCapabilities(u8);

impl CarrierCapabilities {
    /// Returns a set containing every carrier implemented by the generated bridge.
    pub(crate) const fn all() -> Self {
        Self(0b1111)
    }

    /// Returns the current server-authoritative native iOS capability ceiling.
    pub(crate) const fn ios() -> Self {
        Self(1 << WebCarrier::Https.index())
    }

    /// Builds a set from a validated bit representation.
    pub(crate) const fn from_bits(bits: u8) -> Option<Self> {
        if bits != 0 && bits & !0b1111 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns whether the bridge can run one carrier.
    pub(crate) const fn contains(self, carrier: WebCarrier) -> bool {
        self.0 & (1 << carrier.index()) != 0
    }

    /// Intersects declared capabilities with an authoritative server ceiling.
    pub(crate) const fn intersection(self, ceiling: Self) -> Option<Self> {
        Self::from_bits(self.0 & ceiling.0)
    }
}

/// Immutable metadata attached to one session-creation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierRequest {
    class: CarrierClientClass,
    capabilities: Option<CarrierCapabilities>,
    attempt: Option<u8>,
    failure: Option<CarrierFailure>,
    user_agent_hash: [u8; 32],
    up_window: Option<u8>,
}

impl CarrierRequest {
    /// Constructs legacy metadata without enabling negotiation or learning.
    pub(crate) const fn legacy(user_agent_hash: [u8; 32]) -> Self {
        Self {
            class: CarrierClientClass::Legacy,
            capabilities: None,
            attempt: None,
            failure: None,
            user_agent_hash,
            up_window: None,
        }
    }

    /// Constructs a metadata-free native client without inferring capabilities.
    pub(crate) const fn ios(user_agent_hash: [u8; 32]) -> Self {
        Self {
            class: CarrierClientClass::Ios,
            capabilities: None,
            attempt: None,
            failure: None,
            user_agent_hash,
            up_window: None,
        }
    }

    /// Constructs validated automatic-negotiation metadata.
    pub(crate) const fn automatic(
        class: CarrierClientClass,
        capabilities: CarrierCapabilities,
        attempt: u8,
        failure: Option<CarrierFailure>,
        user_agent_hash: [u8; 32],
    ) -> Self {
        Self {
            class,
            capabilities: Some(capabilities),
            attempt: Some(attempt),
            failure,
            user_agent_hash,
            up_window: None,
        }
    }

    /// Attaches the separately validated HTTP conveyor capability.
    pub(crate) const fn with_up_window(mut self, window: Option<u8>) -> Self {
        self.up_window = window;
        self
    }

    /// Returns the separately advertised HTTP conveyor capability.
    pub(crate) const fn up_window(self) -> Option<u8> {
        self.up_window
    }

    /// Returns whether this request participates in server-side negotiation.
    pub(crate) const fn is_automatic(self) -> bool {
        self.capabilities.is_some()
    }

    /// Returns whether server capability filtering applies to this request.
    pub(crate) const fn uses_capabilities(self) -> bool {
        self.capabilities.is_some()
    }

    /// Returns the canonical attempt number when negotiation is active.
    pub(crate) const fn attempt(self) -> Option<u8> {
        self.attempt
    }

    /// Returns the reported reason for advancing from the previous candidate.
    pub(crate) const fn failure(self) -> Option<CarrierFailure> {
        self.failure
    }

    /// Returns whether a carrier is supported by this request.
    pub(crate) const fn supports(self, carrier: WebCarrier) -> bool {
        match self.capabilities {
            Some(capabilities) => capabilities.contains(carrier),
            None => false,
        }
    }

    /// Returns the stable non-sensitive client class.
    pub(crate) const fn class(self) -> CarrierClientClass {
        self.class
    }

    /// Returns the normalized User-Agent digest.
    pub(crate) const fn user_agent_hash(self) -> [u8; 32] {
        self.user_agent_hash
    }

    /// Checks the capability identity frozen across sequential attempts.
    pub(crate) fn matches_client(self, other: Self) -> bool {
        self.class == other.class
            && self.capabilities_bits() == other.capabilities_bits()
            && self.user_agent_hash == other.user_agent_hash
            && self.up_window == other.up_window
    }

    /// Checks the complete idempotent identity of one exact attempt request.
    pub(crate) fn matches_attempt(self, other: Self) -> bool {
        self.matches_client(other) && self.attempt == other.attempt && self.failure == other.failure
    }

    fn capabilities_bits(self) -> Option<u8> {
        self.capabilities.map(|capabilities| capabilities.0)
    }
}

/// Returns the cumulative deadline slot assigned to one carrier attempt.
pub(super) const fn carrier_attempt_deadline_index(
    candidate_count: u8,
    attempt: u8,
) -> Option<usize> {
    if candidate_count == 0 || candidate_count > 4 || attempt == 0 || attempt > candidate_count {
        return None;
    }
    if attempt == candidate_count {
        Some(3)
    } else {
        Some((attempt - 1) as usize)
    }
}

/// Secret-independent evidence owner frozen into an automatic session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CarrierLearningContext {
    /// Stable profile namespace.
    pub(crate) profile_key: super::ProfileKey,
    /// Effective client address from the trusted L7 boundary.
    pub(crate) client_ip: IpAddr,
    /// Client-class namespace for normalized User-Agent evidence.
    pub(crate) class: CarrierClientClass,
    /// Domain-separated normalized User-Agent digest.
    pub(crate) user_agent_hash: [u8; 32],
    /// Hot-reload epoch that rejects late outcomes from an older policy.
    pub(crate) epoch: u64,
    /// Whether the authoritative client address is safe to use as learning evidence.
    pub(crate) ip_learning_eligible: bool,
}

#[cfg(test)]
mod tests {
    use super::carrier_attempt_deadline_index;

    #[test]
    fn final_candidate_uses_the_final_cumulative_deadline_slot() {
        assert_eq!(carrier_attempt_deadline_index(1, 1), Some(3));
        assert_eq!(carrier_attempt_deadline_index(2, 1), Some(0));
        assert_eq!(carrier_attempt_deadline_index(2, 2), Some(3));
        assert_eq!(carrier_attempt_deadline_index(3, 1), Some(0));
        assert_eq!(carrier_attempt_deadline_index(3, 2), Some(1));
        assert_eq!(carrier_attempt_deadline_index(3, 3), Some(3));
        assert_eq!(carrier_attempt_deadline_index(4, 1), Some(0));
        assert_eq!(carrier_attempt_deadline_index(4, 2), Some(1));
        assert_eq!(carrier_attempt_deadline_index(4, 3), Some(2));
        assert_eq!(carrier_attempt_deadline_index(4, 4), Some(3));
    }

    #[test]
    fn invalid_candidate_or_attempt_counts_have_no_deadline_slot() {
        for (candidate_count, attempt) in [(0, 1), (5, 1), (1, 0), (1, 2), (3, 4)] {
            assert_eq!(
                carrier_attempt_deadline_index(candidate_count, attempt),
                None
            );
        }
    }
}

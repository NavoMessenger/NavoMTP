use std::time::Instant;

use super::{ManagerError, TokenHash, WebProcessRuntime};

/// Closed generated-bridge diagnostic vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BridgeDiagnosticEvent {
    /// The generated bridge runtime started executing.
    RuntimeStarted,
    /// The initial status control object was submitted to the native boundary.
    StatusPosted,
    /// The bridge received the first binary HELLO frame from the native client.
    HelloReceived,
    /// No supported native boundary appeared before the bridge request deadline.
    BoundaryTimeout,
    /// The native boundary did not provide HELLO before the bridge request deadline.
    HelloTimeout,
    /// The native boundary explicitly closed before providing HELLO.
    ClientCloseBeforeHello,
    /// The bridge document unloaded before receiving HELLO.
    DocumentUnloadedBeforeHello,
    /// The bridge runtime raised an error before receiving HELLO.
    RuntimeErrorBeforeHello,
}

impl BridgeDiagnosticEvent {
    /// Returns the fixed bootstrap-owned deduplication slot.
    const fn bit(self) -> u16 {
        match self {
            Self::RuntimeStarted => 1 << 0,
            Self::StatusPosted => 1 << 1,
            Self::HelloReceived => 1 << 2,
            Self::BoundaryTimeout => 1 << 3,
            Self::HelloTimeout => 1 << 4,
            Self::ClientCloseBeforeHello => 1 << 5,
            Self::DocumentUnloadedBeforeHello => 1 << 6,
            Self::RuntimeErrorBeforeHello => 1 << 7,
        }
    }

    /// Returns the stable trace label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeStarted => "runtime_started",
            Self::StatusPosted => "status_posted",
            Self::HelloReceived => "hello_received",
            Self::BoundaryTimeout => "boundary_timeout",
            Self::HelloTimeout => "hello_timeout",
            Self::ClientCloseBeforeHello => "client_close_before_hello",
            Self::DocumentUnloadedBeforeHello => "document_unloaded_before_hello",
            Self::RuntimeErrorBeforeHello => "runtime_error_before_hello",
        }
    }
}

impl WebProcessRuntime {
    /// Claims one authenticated diagnostic event without changing credential lifetime or state.
    pub(crate) fn claim_bridge_diagnostic(
        &self,
        hash: TokenHash,
        host: &str,
        event: BridgeDiagnosticEvent,
    ) -> Result<bool, ManagerError> {
        let active = self
            .active_generation()
            .config()
            .web
            .debug
            .bridge_diagnostics_enabled();
        let now = Instant::now();
        let mut state = self.state.lock();
        let entry = state
            .bootstraps
            .get_mut(&hash)
            .filter(|entry| entry.profile.host == host && now <= entry.expires_at)
            .ok_or(ManagerError::Authentication)?;
        if !active || !entry.bridge_diagnostics_enabled {
            return Ok(false);
        }
        let bit = event.bit();
        if entry.bridge_diagnostic_events & bit != 0 {
            return Ok(false);
        }
        entry.bridge_diagnostic_events |= bit;
        Ok(true)
    }
}

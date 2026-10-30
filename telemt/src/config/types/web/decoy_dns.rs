use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Configuration-time DNS policy for an HTTP decoy origin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebDecoyResolve {
    /// Accept IP literals only, without consulting DNS.
    #[default]
    Never,
    /// Pin validated DNS answers for the lifetime of the prepared configuration.
    Startup,
}

/// Complete resolver evidence, retained for validation against effective listeners.
#[derive(Debug, Clone, Default)]
pub(crate) struct WebDecoyDnsSnapshot {
    /// Resolver-order answers keyed by canonical URL hostname and effective port.
    pub(crate) origins: BTreeMap<(String, u16), Vec<SocketAddr>>,
}

use serde::{Deserialize, Serialize};

/// Minimum restart-owned entries required for one complete learning sample.
pub(crate) const WEB_CARRIER_LEARNING_MIN_ENTRIES: usize = 3;

/// HTTP method emitted by newly rendered HTTPS carrier bridges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebCarrierMethod {
    /// Preserve the original bridge request method.
    #[default]
    Post,
    /// Allow idempotent-method connection reuse in Linux WebKitGTK.
    Put,
}

impl WebCarrierMethod {
    /// Returns the HTTP token embedded in the page-owned carrier policy.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// Carrier selected for one newly issued WEB relay session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebCarrier {
    /// Serialize all logical streams through one uplink and one downlink sequence.
    #[default]
    Https,
    /// Give every logical stream independent HTTPS sequencing and polling state.
    HttpsLanes,
    /// Multiplex all logical streams over one ordered WebSocket.
    Websocket,
    /// Give every logical stream an independently owned WebSocket lane.
    WebsocketLanes,
}

impl WebCarrier {
    /// Every carrier supported by the WEB v1 bridge.
    pub(crate) const ALL: [Self; 4] = [
        Self::Https,
        Self::HttpsLanes,
        Self::Websocket,
        Self::WebsocketLanes,
    ];

    /// Returns the exact carrier token advertised to the browser bridge.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::HttpsLanes => "https-lanes",
            Self::Websocket => "websocket",
            Self::WebsocketLanes => "websocket-lanes",
        }
    }

    /// Returns the stable fixed-slot index used by bounded learning state.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Https => 0,
            Self::HttpsLanes => 1,
            Self::Websocket => 2,
            Self::WebsocketLanes => 3,
        }
    }

    /// Returns whether one carrier owns independent state per logical stream.
    pub(crate) const fn uses_lanes(self) -> bool {
        matches!(self, Self::HttpsLanes | Self::WebsocketLanes)
    }

    /// Returns whether carrier messages use RFC 6455 instead of HTTP bodies.
    pub(crate) const fn uses_websocket(self) -> bool {
        matches!(self, Self::Websocket | Self::WebsocketLanes)
    }

    /// Returns whether all logical streams share one carrier state machine.
    pub(crate) const fn is_multiplexed(self) -> bool {
        matches!(self, Self::Https | Self::Websocket)
    }
}

/// Optional ordered carrier list that enables server-side auto-negotiation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WebCarriers {
    /// Auto-negotiation is disabled and only `web.carrier` is used.
    #[default]
    Disabled,
    /// Auto-negotiation uses this ordered candidate list before the fallback.
    Enabled(Vec<WebCarrier>),
}

impl WebCarriers {
    /// Returns the explicit candidate list when negotiation is enabled.
    pub fn enabled(&self) -> Option<&[WebCarrier]> {
        match self {
            Self::Disabled => None,
            Self::Enabled(carriers) => Some(carriers),
        }
    }
}

impl Serialize for WebCarriers {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Disabled => false.serialize(serializer),
            Self::Enabled(carriers) => carriers.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for WebCarriers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Flag(bool),
            List(Vec<WebCarrier>),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Flag(false) => Ok(Self::Disabled),
            Repr::Flag(true) => Err(serde::de::Error::custom(
                "web.carriers accepts false or a non-empty carrier array",
            )),
            Repr::List(carriers) => Ok(Self::Enabled(carriers)),
        }
    }
}

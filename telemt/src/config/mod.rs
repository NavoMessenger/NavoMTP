//! Configuration.

pub(crate) mod defaults;
pub mod hot_reload;
mod load;
mod types;

pub use load::ProxyConfig;
pub(crate) use load::{ConfigSourceGraph, LoadedConfig, ParsedConfigSource};
pub use types::*;

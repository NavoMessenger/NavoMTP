use std::sync::Arc;

use tokio::sync::watch;

use crate::config::ProxyConfig;
use crate::protocol::constants::RPC_FLAG_HAS_AD_TAG;

/// Sender-local tag cache, refreshed only when its configuration watch changes.
pub(super) struct LiveAdTag {
    config_rx: Option<watch::Receiver<Arc<ProxyConfig>>>,
    tag: Option<[u8; 16]>,
}

impl LiveAdTag {
    pub(super) fn new(
        config_rx: Option<watch::Receiver<Arc<ProxyConfig>>>,
        tag: Option<[u8; 16]>,
        user: &str,
    ) -> Self {
        let mut cache = Self { config_rx, tag };
        // The watch may already be newer than the authenticated session snapshot.
        if let Some(rx) = cache.config_rx.as_mut() {
            cache.tag = Self::resolve(&rx.borrow_and_update(), user);
        }
        cache
    }

    pub(super) fn refresh(&mut self, user: &str) {
        let Some(rx) = self.config_rx.as_mut() else {
            return;
        };
        let closed = match rx.has_changed() {
            Ok(false) => return,
            Ok(true) => false,
            Err(_) => true,
        };
        self.tag = Self::resolve(&rx.borrow_and_update(), user);
        // Consume the final snapshot even if the publisher closed with an unseen
        // update, then preserve the cached value without ending the client stream.
        if closed {
            self.config_rx = None;
        }
    }

    pub(super) fn flags(&self, flags: u32) -> u32 {
        // The producer's flags may reflect tag presence at session creation.
        // Clearing the bit also suppresses the ME pool's immutable fallback tag.
        (flags & !RPC_FLAG_HAS_AD_TAG)
            | if self.tag.is_some() { RPC_FLAG_HAS_AD_TAG } else { 0 }
    }

    pub(super) fn tag(&self) -> Option<[u8; 16]> {
        self.tag
    }

    fn resolve(config: &ProxyConfig, user: &str) -> Option<[u8; 16]> {
        fn decode(value: &str) -> Option<[u8; 16]> {
            let mut tag = [0; 16];
            hex::decode_to_slice(value, &mut tag).ok()?;
            Some(tag)
        }
        config.access.user_ad_tags.get(user)
            .and_then(|tag| decode(tag))
            .or_else(|| config.general.ad_tag.as_deref().and_then(decode))
    }
}

#[cfg(test)]
mod tests;

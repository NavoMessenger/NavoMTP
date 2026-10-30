use super::*;
use crate::protocol::constants::{RPC_FLAG_NOT_ENCRYPTED, RPC_FLAG_QUICKACK};

fn config(user_tag: Option<&str>, global_tag: Option<&str>) -> Arc<ProxyConfig> {
    let mut config = ProxyConfig::default();
    if let Some(tag) = user_tag {
        config.access.user_ad_tags.insert("alice".to_string(), tag.to_string());
    }
    config.general.ad_tag = global_tag.map(str::to_string);
    Arc::new(config)
}

const A: &str = "11111111111111111111111111111111";
const B: &str = "22222222222222222222222222222222";

#[test]
fn same_connection_serializes_new_tag_without_changing_payload_or_other_metadata() {
    use crate::transport::middle_proxy::build_proxy_req_payload;
    let (tx, rx) = watch::channel(config(Some(A), None));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    let client = "203.0.113.1:12345".parse().unwrap();
    let local = "203.0.113.2:443".parse().unwrap();
    let flags = RPC_FLAG_QUICKACK | RPC_FLAG_NOT_ENCRYPTED;
    let before = build_proxy_req_payload(42, client, local, b"unchanged", cache.tag().as_ref().map(|t| t.as_slice()), cache.flags(flags));
    tx.send(config(Some(B), None)).unwrap();
    cache.refresh("alice");
    let after = build_proxy_req_payload(42, client, local, b"unchanged", cache.tag().as_ref().map(|t| t.as_slice()), cache.flags(flags));
    assert_eq!(&before[8..16], &42u64.to_le_bytes());
    assert_eq!(&after[..65], &before[..65]);
    assert_eq!(&before[65..81], &[0x11; 16]);
    assert_eq!(&after[65..81], &[0x22; 16]);
    assert_eq!(&after[81..], &before[81..]);
    tx.send(config(None, None)).unwrap();
    cache.refresh("alice");
    // Even an immutable old pool fallback cannot appear when HAS_AD_TAG is off.
    let without = build_proxy_req_payload(42, client, local, b"unchanged", Some(&[0x11; 16]), cache.flags(flags));
    assert_eq!(&without[56..], b"unchanged");
    assert_eq!(&without[8..16], &42u64.to_le_bytes());
}

#[test]
fn existing_sender_uses_updated_tag_without_being_recreated() {
    let (tx, rx) = watch::channel(config(Some(A), None));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    assert_eq!(cache.tag(), Some([0x11; 16]));
    tx.send(config(Some(B), None)).unwrap();
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
}

#[test]
fn sender_start_uses_latest_watch_not_stale_session_tag() {
    let (_tx, rx) = watch::channel(config(Some(B), None));
    let cache = LiveAdTag::new(Some(rx), Some([0x11; 16]), "alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
}

#[test]
fn removing_tag_clears_only_tag_flag_and_prevents_pool_fallback_serialization() {
    let (tx, rx) = watch::channel(config(Some(A), None));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    let other_flags = RPC_FLAG_NOT_ENCRYPTED | RPC_FLAG_QUICKACK | 0x40000000;
    tx.send(config(None, None)).unwrap();
    cache.refresh("alice");
    assert_eq!(cache.tag(), None);
    assert_eq!(cache.flags(other_flags | RPC_FLAG_HAS_AD_TAG), other_flags);
    tx.send(config(Some(B), None)).unwrap();
    cache.refresh("alice");
    assert_eq!(cache.flags(other_flags), other_flags | RPC_FLAG_HAS_AD_TAG);
}

#[test]
fn global_fallback_updates_and_user_override_takes_precedence() {
    let (tx, rx) = watch::channel(config(Some(A), Some(B)));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    assert_eq!(cache.tag(), Some([0x11; 16]));
    tx.send(config(None, Some(B))).unwrap();
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
    tx.send(config(Some("invalid"), Some(A))).unwrap();
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x11; 16]));
}

#[test]
fn missing_watch_keeps_standalone_handler_snapshot_behavior() {
    let mut cache = LiveAdTag::new(None, Some([0x11; 16]), "alice");
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x11; 16]));
}

#[test]
fn closed_watch_consumes_final_unseen_update_and_keeps_last_value() {
    let (tx, rx) = watch::channel(config(Some(A), None));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    tx.send(config(Some(B), None)).unwrap();
    drop(tx);
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
    assert!(cache.config_rx.is_none());
}

#[tokio::test]
async fn coalesced_updates_match_latest_snapshot_under_sender_pressure() {
    let (tx, rx) = watch::channel(config(Some(A), None));
    let mut cache = LiveAdTag::new(Some(rx), None, "alice");
    let producer = tokio::spawn(async move {
        for i in 0..1000 {
            tx.send_replace(config(Some(if i % 2 == 0 { A } else { B }), None));
            if i % 11 == 0 { tokio::task::yield_now().await; }
        }
        tx
    });
    for _ in 0..1000 {
        cache.refresh("alice");
        assert!(cache.tag() == Some([0x11; 16]) || cache.tag() == Some([0x22; 16]));
        tokio::task::yield_now().await;
    }
    let _tx = producer.await.unwrap();
    cache.refresh("alice");
    assert_eq!(cache.tag(), Some([0x22; 16]));
}

use super::*;

#[test]
fn conveyor_reload_is_hot_in_both_directions_and_preserves_process_limits() {
    let mut active = ProxyConfig::default();
    for enabled in [false, true] {
        let mut desired = active.clone();
        desired.web.conveyor = enabled;
        assert_eq!(classify_config_changes(&active, &desired).changed, ["web"]);
        assert!(!classify_config_changes(&active, &desired).restart_required);
        desired.web.limits.max_body_readers += 1;
        let applied = overlay_hot_fields(&active, &desired);
        assert_eq!(applied.web.conveyor, enabled);
        assert_eq!(
            applied.web.limits.max_body_readers,
            active.web.limits.max_body_readers
        );
        active = applied;
    }
}

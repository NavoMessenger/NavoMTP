use std::path::{Path, PathBuf};

use super::{
    expected_handshake_close_description, format_maestro_line, is_expected_handshake_eof,
    peer_close_description, resolve_runtime_base_dir, resolve_runtime_config_path,
};
use crate::error::{ProxyError, StreamError};

#[test]
fn maestro_line_formatter_respects_disabled_colors() {
    let plain = format_maestro_line("boot", false);
    assert_eq!(plain, "MAESTRO: boot");
    assert!(!plain.contains('\x1b'));
}

#[test]
fn maestro_line_formatter_keeps_color_when_enabled() {
    let colored = format_maestro_line("boot", true);
    assert!(colored.contains("\x1b[92mMAESTRO\x1b[0m"));
}

#[test]
fn resolve_runtime_config_path_anchors_relative_to_startup_cwd() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_path_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();
    let target = startup_cwd.join("config.toml");
    std::fs::write(&target, " ").unwrap();

    let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, true);
    assert_eq!(resolved, target.canonicalize().unwrap());

    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_config_path_keeps_absolute_for_missing_file() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_path_missing_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();

    let resolved = resolve_runtime_config_path("missing.toml", &startup_cwd, true);
    assert_eq!(resolved, startup_cwd.join("missing.toml"));

    let _ = std::fs::remove_dir(&startup_cwd);
}

#[cfg(unix)]
#[test]
fn runtime_paths_preserve_symlinks_for_descriptor_validation() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("real");
    let linked_dir = dir.path().join("linked");
    std::fs::create_dir(&real_dir).unwrap();
    std::fs::write(real_dir.join("config.toml"), " ").unwrap();
    symlink(&real_dir, &linked_dir).unwrap();
    let linked_config = linked_dir.join("config.toml");

    let config = resolve_runtime_config_path(linked_config.to_str().unwrap(), dir.path(), true);
    let runtime = resolve_runtime_base_dir(&linked_config, dir.path(), true, Some(&linked_dir));

    assert_eq!(config, linked_config);
    assert_eq!(runtime, linked_dir);
}

#[test]
fn resolve_runtime_config_path_uses_startup_candidates_when_not_explicit() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_startup_candidates_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();
    let telemt = startup_cwd.join("telemt.toml");
    std::fs::write(&telemt, " ").unwrap();

    let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, false);
    assert_eq!(resolved, telemt.canonicalize().unwrap());

    let _ = std::fs::remove_file(&telemt);
    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_config_path_defaults_to_startup_config_when_none_found() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_cfg_startup_default_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();

    let resolved = resolve_runtime_config_path("config.toml", &startup_cwd, false);
    assert_eq!(resolved, startup_cwd.join("config.toml"));

    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_base_dir_prefers_cli_data_path() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_runtime_base_cwd_{nonce}"));
    let data_path = std::env::temp_dir().join(format!("telemt_runtime_base_data_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();
    std::fs::create_dir_all(&data_path).unwrap();

    let resolved = resolve_runtime_base_dir(
        &startup_cwd.join("config.toml"),
        &startup_cwd,
        true,
        Some(&data_path),
    );
    assert_eq!(resolved, data_path.canonicalize().unwrap());

    let _ = std::fs::remove_dir(&data_path);
    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_base_dir_uses_working_directory_before_explicit_config_parent() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_runtime_base_start_{nonce}"));
    let config_dir = std::env::temp_dir().join(format!("telemt_runtime_base_cfg_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let resolved =
        resolve_runtime_base_dir(&config_dir.join("telemt.toml"), &startup_cwd, true, None);
    assert_eq!(resolved, startup_cwd.canonicalize().unwrap());

    let _ = std::fs::remove_dir(&config_dir);
    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_base_dir_uses_explicit_config_parent_from_root() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let config_dir = std::env::temp_dir().join(format!("telemt_runtime_base_root_cfg_{nonce}"));
    std::fs::create_dir_all(&config_dir).unwrap();

    let resolved =
        resolve_runtime_base_dir(&config_dir.join("telemt.toml"), Path::new("/"), true, None);
    assert_eq!(resolved, config_dir.canonicalize().unwrap());

    let _ = std::fs::remove_dir(&config_dir);
}

#[test]
fn resolve_runtime_base_dir_uses_systemd_working_directory_before_etc() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let startup_cwd = std::env::temp_dir().join(format!("telemt_runtime_base_systemd_{nonce}"));
    std::fs::create_dir_all(&startup_cwd).unwrap();

    let resolved =
        resolve_runtime_base_dir(&startup_cwd.join("config.toml"), &startup_cwd, false, None);
    assert_eq!(resolved, startup_cwd.canonicalize().unwrap());

    let _ = std::fs::remove_dir(&startup_cwd);
}

#[test]
fn resolve_runtime_base_dir_falls_back_to_etc_from_root() {
    let resolved = resolve_runtime_base_dir(
        Path::new("/etc/telemt/config.toml"),
        Path::new("/"),
        false,
        None,
    );
    assert_eq!(resolved, PathBuf::from("/etc/telemt"));
}

#[test]
fn expected_handshake_eof_matches_connection_reset() {
    let err = ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
    assert!(is_expected_handshake_eof(&err));
}

#[test]
fn expected_handshake_eof_matches_stream_io_unexpected_eof() {
    let err = ProxyError::Stream(StreamError::Io(std::io::Error::from(
        std::io::ErrorKind::UnexpectedEof,
    )));
    assert!(is_expected_handshake_eof(&err));
}

#[test]
fn peer_close_description_is_human_readable_for_all_peer_close_kinds() {
    let cases = [
        (
            std::io::ErrorKind::ConnectionReset,
            "Peer reset TCP connection (RST)",
        ),
        (
            std::io::ErrorKind::ConnectionAborted,
            "Peer aborted TCP connection during transport",
        ),
        (
            std::io::ErrorKind::BrokenPipe,
            "Peer closed write side (broken pipe)",
        ),
        (
            std::io::ErrorKind::NotConnected,
            "Socket was already closed by peer",
        ),
    ];

    for (kind, expected) in cases {
        let err = ProxyError::Io(std::io::Error::from(kind));
        assert_eq!(peer_close_description(&err), Some(expected));
    }
}

#[test]
fn handshake_close_description_is_human_readable_for_all_expected_kinds() {
    let cases = [
        (
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            "Peer closed before sending full 64-byte MTProto handshake",
        ),
        (
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            "Peer reset TCP connection during initial MTProto handshake",
        ),
        (
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionAborted)),
            "Peer aborted TCP connection during initial MTProto handshake",
        ),
        (
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            "Peer closed write side before MTProto handshake completed",
        ),
        (
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::NotConnected)),
            "Handshake socket was already closed by peer",
        ),
        (
            ProxyError::Stream(StreamError::UnexpectedEof),
            "Peer closed before sending full 64-byte MTProto handshake",
        ),
    ];

    for (err, expected) in cases {
        assert_eq!(expected_handshake_close_description(&err), Some(expected));
    }
}

#[cfg(unix)]
use std::os::unix::fs::symlink;

use super::*;

#[cfg(unix)]
#[test]
fn config_loader_rejects_final_and_intermediate_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let real_directory = directory.path().join("real");
    let linked_directory = directory.path().join("linked");
    std::fs::create_dir(&real_directory).unwrap();
    let real_config = real_directory.join("config.toml");
    let final_link = directory.path().join("config.toml");
    std::fs::write(&real_config, "[general]\n").unwrap();
    symlink(&real_config, &final_link).unwrap();
    symlink(&real_directory, &linked_directory).unwrap();

    assert!(ProxyConfig::load(&final_link).is_err());
    assert!(ProxyConfig::load(linked_directory.join("config.toml")).is_err());
}

#[test]
fn config_loader_rejects_oversized_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();

    let error = ProxyConfig::load(&path).unwrap_err().to_string();

    assert!(error.contains("size limit") || error.contains("exceeds"));
}

#[cfg(unix)]
#[test]
fn config_loader_rejects_fifo_without_blocking() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();

    assert!(ProxyConfig::load(&path).is_err());
}

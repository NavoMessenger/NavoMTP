use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use super::path::AnchoredPath;
use super::write::atomic_replace_after_anchor;
use super::*;

#[test]
fn directory_walk_rejects_intermediate_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    let link = directory.path().join("link");
    std::fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();

    assert!(open_dir_nofollow(&link).is_err());
}

#[test]
fn runtime_parent_policy_creates_and_reads_relative_paths() {
    use std::os::unix::fs::MetadataExt;

    let current = std::env::current_dir().unwrap();
    let directory = tempfile::tempdir_in(&current).unwrap();
    let relative = directory.path().strip_prefix(&current).unwrap();
    for strict_runtime_paths in [false, true] {
        let mode = if strict_runtime_paths {
            "strict"
        } else {
            "compatible"
        };
        let path = relative.join(mode).join("nested/telemt.pid");
        let created =
            AnchoredPath::open_runtime_parent(&path, Some(0o750), strict_runtime_paths).unwrap();
        let opened = AnchoredPath::open_runtime_parent(&path, None, strict_runtime_paths).unwrap();
        let created = std::fs::File::from(created.parent().try_clone().unwrap())
            .metadata()
            .unwrap();
        let opened = std::fs::File::from(opened.parent().try_clone().unwrap())
            .metadata()
            .unwrap();
        assert_eq!((created.dev(), created.ino()), (opened.dev(), opened.ino()));
        assert_eq!(created.permissions().mode() & 0o777, 0o750);
    }
    assert!(AnchoredPath::open_runtime_parent(Path::new("telemt.pid"), None, false).is_ok());
}

#[test]
fn runtime_parent_policy_only_requires_trusted_ownership_when_strict() {
    if !nix::unistd::Uid::effective().is_root() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("foreign-owner");
    std::fs::create_dir(&parent).unwrap();
    nix::unistd::chown(&parent, Some(nix::unistd::Uid::from_raw(65534)), None).unwrap();
    let path = parent.join("telemt.pid");

    assert!(AnchoredPath::open_runtime_parent(&path, None, false).is_ok());
    assert!(AnchoredPath::open_runtime_parent(&path, None, true).is_err());
}

#[test]
fn atomic_replace_does_not_follow_final_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = directory.path().join("sentinel");
    let target = directory.path().join("target");
    std::fs::write(&sentinel, b"preserve").unwrap();
    symlink(&sentinel, &target).unwrap();

    atomic_replace(&target, b"replacement", 0o600).unwrap();

    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve");
    assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
}

#[test]
fn append_open_rejects_final_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = directory.path().join("sentinel");
    let target = directory.path().join("target");
    std::fs::write(&sentinel, b"preserve").unwrap();
    symlink(&sentinel, &target).unwrap();

    assert!(open_append_regular(&target, 0o640).is_err());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve");
}

#[test]
fn trusted_parent_rejects_group_writable_directory() {
    let current = std::env::current_dir().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("telemt-insecure-parent-")
        .tempdir_in(current)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o770)).unwrap();

    assert!(AnchoredPath::open_trusted_parent(&directory.path().join("listener.sock")).is_err());
}

#[test]
fn anchored_replace_survives_parent_path_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original");
    let moved = directory.path().join("moved");
    let redirect = directory.path().join("redirect");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&redirect).unwrap();
    let target = original.join("state");
    let anchored = AnchoredPath::open(&target).unwrap();
    std::fs::rename(&original, &moved).unwrap();
    symlink(&redirect, &original).unwrap();

    atomic_replace_after_anchor(&anchored, b"anchored", 0o600).unwrap();

    assert_eq!(std::fs::read(moved.join("state")).unwrap(), b"anchored");
    assert!(!redirect.join("state").exists());
    let mode = std::fs::metadata(moved.join("state"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

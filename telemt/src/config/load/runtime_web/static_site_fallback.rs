use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::*;

/// Builds a bounded static-site snapshot on platforms without directory descriptors.
pub(super) fn load_static_site_by_path(
    root: &Path,
    limits: &WebLimitsConfig,
    assets: &mut BTreeMap<String, WebStaticAsset>,
    total_files: &mut usize,
    total_bytes: &mut usize,
) -> Result<()> {
    let root_metadata = fs::symlink_metadata(root).map_err(|error| {
        ProxyError::Config(format!(
            "failed to inspect WEB static directory `{}`: {error}",
            root.display()
        ))
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ProxyError::Config(format!(
            "WEB static directory `{}` must be a real directory, not a symlink",
            root.display()
        )));
    }
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        ProxyError::Config(format!(
            "failed to canonicalize WEB static directory `{}`: {error}",
            root.display()
        ))
    })?;
    load_static_directory(
        &canonical_root,
        &canonical_root,
        assets,
        total_files,
        total_bytes,
        limits,
        0,
    )
}

fn load_static_directory(
    root: &Path,
    directory: &Path,
    assets: &mut BTreeMap<String, WebStaticAsset>,
    total_files: &mut usize,
    total_bytes: &mut usize,
    limits: &WebLimitsConfig,
    depth: usize,
) -> Result<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ProxyError::Config(format!(
            "failed to read WEB static directory `{}`: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ProxyError::Config(format!("failed to read WEB static entry: {error}"))
        })?;
        if *total_files >= limits.max_static_files {
            return Err(ProxyError::Config(
                "WEB static entries exceed process-wide web.limits.max_static_files".to_string(),
            ));
        }
        *total_files += 1;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ProxyError::Config(format!(
                "failed to inspect WEB static entry `{}`: {error}",
                path.display()
            ))
        })?;
        if file_type.is_symlink() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` must not be a symlink",
                path.display()
            )));
        }
        if file_type.is_dir() {
            if depth >= MAX_WEB_STATIC_DEPTH {
                return Err(ProxyError::Config(format!(
                    "WEB static directory `{}` exceeds the maximum nesting depth",
                    path.display()
                )));
            }
            load_static_directory(
                root,
                &path,
                assets,
                total_files,
                total_bytes,
                limits,
                depth + 1,
            )?;
            continue;
        }
        if !file_type.is_file() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` must be a regular file",
                path.display()
            )));
        }
        let file = fs::File::open(&path).map_err(|error| {
            ProxyError::Config(format!(
                "failed to open WEB static file `{}`: {error}",
                path.display()
            ))
        })?;
        let metadata = file.metadata().map_err(|error| {
            ProxyError::Config(format!(
                "failed to inspect WEB static file `{}`: {error}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` changed before it was opened",
                path.display()
            )));
        }
        let relative = path.strip_prefix(root).map_err(|_| {
            ProxyError::Config("WEB static path escaped its configured root".to_string())
        })?;
        load_static_file(
            file,
            &metadata,
            relative,
            &path,
            assets,
            total_bytes,
            limits,
        )?;
    }
    Ok(())
}

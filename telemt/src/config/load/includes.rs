use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::error::{ProxyError, Result};

const MAX_CONFIG_SOURCE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn normalize_config_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

pub(super) fn hash_rendered_snapshot(rendered: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn read_config_source(path: &Path) -> Result<(PathBuf, String)> {
    #[cfg(unix)]
    let bytes = crate::util::secure_fs::read_regular_limited(path, MAX_CONFIG_SOURCE_BYTES)
        .map_err(|error| ProxyError::Config(error.to_string()))?;
    #[cfg(not(unix))]
    let bytes = std::fs::read(path).map_err(|error| ProxyError::Config(error.to_string()))?;
    if bytes.len() > MAX_CONFIG_SOURCE_BYTES {
        return Err(ProxyError::Config(format!(
            "config source `{}` exceeds {} bytes",
            path.display(),
            MAX_CONFIG_SOURCE_BYTES
        )));
    }
    let contents = String::from_utf8(bytes).map_err(|error| {
        ProxyError::Config(format!(
            "config source `{}` is not valid UTF-8: {error}",
            path.display()
        ))
    })?;
    let normalized = normalize_config_path(path);
    Ok((normalized, contents))
}

pub(super) fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    depth: u8,
    source_files: &mut BTreeSet<PathBuf>,
    source_contents: &mut BTreeMap<PathBuf, String>,
    source_overrides: &BTreeMap<PathBuf, String>,
) -> Result<String> {
    if depth > 10 {
        return Err(ProxyError::Config("Include depth > 10".into()));
    }
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("include") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let path_str = rest.trim().trim_matches('"');
                let resolved = base_dir.join(path_str);
                let (normalized, disk_contents) = read_config_source(&resolved)?;
                let included = source_overrides
                    .get(&normalized)
                    .cloned()
                    .or_else(|| source_contents.get(&normalized).cloned())
                    .unwrap_or(disk_contents);
                source_files.insert(normalized.clone());
                source_contents
                    .entry(normalized.clone())
                    .or_insert_with(|| included.clone());
                let included_dir = normalized.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(
                    &included,
                    included_dir,
                    depth + 1,
                    source_files,
                    source_contents,
                    source_overrides,
                )?);
                output.push('\n');
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}

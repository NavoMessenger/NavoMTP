use std::path::Path;

use super::*;
pub(super) async fn read_disk_entry_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        crate::util::secure_fs::read_regular_limited_async(
            path.to_path_buf(),
            TLS_FRONT_DISK_ENTRY_MAX_BYTES as usize,
        )
        .await
    }
    #[cfg(not(unix))]
    {
        let bytes = tokio::fs::read(path).await?;
        if bytes.len() as u64 > TLS_FRONT_DISK_ENTRY_MAX_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS cache entry exceeds the 1 MiB limit",
            ));
        }
        Ok(bytes)
    }
}

pub(super) fn cert_info_matches_domain(cached: &CachedTlsData) -> bool {
    let Some(cert_info) = cached.cert_info.as_ref() else {
        return true;
    };
    if !cert_info.san_names.is_empty() {
        return cert_info
            .san_names
            .iter()
            .any(|name| dns_name_matches_domain(name, &cached.domain));
    }
    cert_info
        .subject_cn
        .as_deref()
        .map_or(true, |name| dns_name_matches_domain(name, &cached.domain))
}

pub(super) fn dns_name_matches_domain(pattern: &str, domain: &str) -> bool {
    let pattern = normalize_dns_name(pattern);
    let domain = normalize_dns_name(domain);
    if pattern == domain {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(prefix) = domain.strip_suffix(suffix) else {
        return false;
    };
    prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
}

pub(super) fn normalize_dns_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

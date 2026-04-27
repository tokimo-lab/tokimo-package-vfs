use std::path::{Component, Path};

use tokimo_vfs_core::error::{Result, TokimoVfsError};

pub(super) fn optional_non_empty(params: &serde_json::Value, key: &str) -> Option<String> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(super) fn validate_cookie(cookie: &str) -> Result<()> {
    let mut has_uid = false;
    let mut has_cid = false;
    let mut has_seid = false;

    for pair in cookie.split(';') {
        let (key, value) = pair
            .trim()
            .split_once('=')
            .ok_or_else(|| TokimoVfsError::InvalidConfig("pan115 cookie format is invalid".into()))?;
        let key = key.trim().to_ascii_uppercase();
        let has_value = !value.trim().is_empty();
        match key.as_str() {
            "UID" => has_uid = has_value,
            "CID" => has_cid = has_value,
            "SEID" => has_seid = has_value,
            _ => {}
        }
    }

    if has_uid && has_cid && has_seid {
        return Ok(());
    }

    Err(TokimoVfsError::InvalidConfig(
        "pan115 cookie must include UID, CID and SEID".into(),
    ))
}

pub(super) fn build_range_header(offset: u64, limit: Option<u64>) -> Option<String> {
    if offset == 0 && limit.is_none() {
        return None;
    }

    Some(match limit {
        Some(length) if length > 0 => {
            format!("bytes={offset}-{}", offset.saturating_add(length).saturating_sub(1))
        }
        Some(_) => format!("bytes={offset}-{offset}"),
        None => format!("bytes={offset}-"),
    })
}

pub(super) fn collect_segments(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

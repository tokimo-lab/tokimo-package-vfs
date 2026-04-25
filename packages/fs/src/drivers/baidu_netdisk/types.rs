use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use tokimo_vfs_core::error::TokimoVfsError;
use tokimo_vfs_core::model::obj::FileInfo;

#[derive(Debug, Clone)]
pub(super) struct BaiduEntry {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenResponse {
    #[serde(default)]
    pub access_token: String,
    /// Baidu rotates the refresh token on every use; must be persisted.
    #[serde(default)]
    pub refresh_token: String,
    /// Seconds until the access token expires (Baidu returns ~2592000 = 30d).
    #[serde(default)]
    pub expires_in: i64,
    #[serde(default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ListResponse {
    #[serde(default)]
    pub errno: i64,
    #[serde(default)]
    pub list: Vec<ListItem>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ListItem {
    #[serde(default)]
    pub fs_id: i64,
    #[serde(default)]
    pub server_filename: String,
    #[serde(default)]
    pub isdir: i64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub server_mtime: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadMetaResponse {
    #[serde(default)]
    pub errno: i64,
    #[serde(default)]
    pub list: Vec<DownloadMetaItem>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct DownloadMetaItem {
    #[serde(default)]
    pub dlink: String,
}

impl From<ListItem> for BaiduEntry {
    fn from(value: ListItem) -> Self {
        Self {
            id: value.fs_id.to_string(),
            name: value.server_filename,
            size: value.size,
            is_dir: value.isdir == 1,
            modified: value
                .server_mtime
                .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0)),
        }
    }
}

pub(super) fn to_file_info(path: &Path, entry: &BaiduEntry) -> FileInfo {
    FileInfo {
        name: entry.name.clone(),
        path: child_display_path(path, &entry.name),
        size: if entry.is_dir { 0 } else { entry.size },
        is_dir: entry.is_dir,
        modified: entry.modified,
    }
}

pub(super) fn normalize_display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.is_empty() || text == "/" {
        "/".to_string()
    } else if text.starts_with('/') {
        text.into_owned()
    } else {
        format!("/{text}")
    }
}

pub(super) fn child_display_path(parent: &Path, name: &str) -> String {
    let base = normalize_display_path(parent);
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

/// Response for `method=filemanager` (rename / move / copy / delete).
#[derive(Debug, Deserialize)]
pub(super) struct ManageResponse {
    #[serde(default)]
    pub errno: i64,
    #[serde(default)]
    pub info: Vec<ManageItem>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ManageItem {
    #[serde(default)]
    pub errno: i64,
}

/// Response for `method=create` (mkdir).
#[derive(Debug, Deserialize)]
pub(super) struct CreateResponse {
    #[serde(default)]
    pub errno: i64,
}

pub(super) fn api_error(prefix: &str, message: Option<String>, code: i64) -> TokimoVfsError {
    match message.filter(|value| !value.is_empty()) {
        Some(message) => TokimoVfsError::Other(format!("{prefix}: [{code}] {message}")),
        None => TokimoVfsError::Other(format!("{prefix}: errno={code}")),
    }
}

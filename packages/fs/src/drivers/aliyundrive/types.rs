use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tokimo_vfs_core::error::TokimoVfsError;
use tokimo_vfs_core::model::obj::FileInfo;

#[derive(Debug, Clone)]
pub(super) struct AliyunEntry {
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
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub(super) struct UserResponse {
    #[serde(default)]
    pub default_drive_id: String,
    #[serde(default)]
    pub resource_drive_id: String,
    #[serde(default)]
    pub backup_drive_id: String,
}

impl UserResponse {
    pub(super) fn drive_id(&self) -> Option<String> {
        if !self.default_drive_id.is_empty() {
            return Some(self.default_drive_id.clone());
        }
        if !self.resource_drive_id.is_empty() {
            return Some(self.resource_drive_id.clone());
        }
        if !self.backup_drive_id.is_empty() {
            return Some(self.backup_drive_id.clone());
        }
        None
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct FileListResponse {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub items: Vec<FileListItem>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FileListItem {
    #[serde(default)]
    pub file_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct DownloadRequest<'a> {
    pub drive_id: &'a str,
    pub file_id: &'a str,
    pub expire_sec: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadResponse {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

impl From<FileListItem> for AliyunEntry {
    fn from(value: FileListItem) -> Self {
        Self {
            id: value.file_id,
            name: value.name,
            size: value.size,
            is_dir: value.entry_type == "folder",
            modified: parse_rfc3339(value.updated_at.as_deref()),
        }
    }
}

pub(super) fn to_file_info(path: &Path, entry: &AliyunEntry) -> FileInfo {
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

pub(super) fn parse_rfc3339(raw: Option<&str>) -> Option<DateTime<Utc>> {
    raw.and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

pub(super) fn api_error(prefix: &str, message: Option<String>, code: Option<&str>) -> TokimoVfsError {
    match (
        message.filter(|value| !value.is_empty()),
        code.filter(|value| !value.is_empty()),
    ) {
        (Some(message), Some(code)) => TokimoVfsError::Other(format!("{prefix}: [{code}] {message}")),
        (Some(message), None) => TokimoVfsError::Other(format!("{prefix}: {message}")),
        (None, Some(code)) => TokimoVfsError::Other(format!("{prefix}: code {code}")),
        (None, None) => TokimoVfsError::Other(prefix.to_string()),
    }
}

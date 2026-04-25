use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use tokimo_vfs_core::error::TokimoVfsError;
use tokimo_vfs_core::model::obj::FileInfo;

#[derive(Debug, Clone)]
pub(super) struct QuarkEntry {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApiResponse {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SortResponse {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Option<SortData>,
    #[serde(default)]
    pub list: Vec<SortItem>,
    #[serde(default)]
    pub metadata: Option<SortMetadata>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct SortData {
    #[serde(default)]
    pub list: Vec<SortItem>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct SortMetadata {
    #[serde(default, rename = "_total")]
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub(super) struct SortItem {
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub fid: String,
    #[serde(default)]
    pub dir: bool,
    /// `OpenList` uses `file: true` for files, `false` for directories.
    #[serde(default = "default_true")]
    pub file: bool,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub last_op_time: Option<serde_json::Value>,
    #[serde(default)]
    pub l_updated_at: Option<i64>,
    #[serde(default)]
    pub updated_at: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub(super) struct DownloadRequest<'a> {
    pub fids: Vec<&'a str>,
}

// ---- Write Operation Request Types ----

#[derive(Debug, Serialize)]
pub(super) struct CreateFolderRequest<'a> {
    pub dir_init_lock: bool,
    pub dir_path: &'a str,
    pub file_name: &'a str,
    pub pdir_fid: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateFolderResponse {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Option<CreateFolderData>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateFolderData {
    #[serde(default)]
    pub fid: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DeleteRequest<'a> {
    pub action_type: i32,
    pub exclude_fids: Vec<&'a str>,
    pub filelist: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
pub(super) struct RenameRequest<'a> {
    pub fid: &'a str,
    pub file_name: &'a str,
}

#[derive(Debug, Serialize)]
pub(super) struct MoveRequest<'a> {
    pub action_type: i32,
    pub exclude_fids: Vec<&'a str>,
    pub filelist: Vec<&'a str>,
    pub to_pdir_fid: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadResponse {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Vec<DownloadItem>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct DownloadItem {
    #[serde(default)]
    pub download_url: String,
}

impl SortResponse {
    pub(super) fn items(self) -> Vec<SortItem> {
        if let Some(data) = self.data
            && !data.list.is_empty()
        {
            return data.list;
        }
        self.list
    }

    pub(super) fn total(&self) -> i64 {
        self.metadata.as_ref().map_or(0, |m| m.total)
    }
}

impl From<SortItem> for QuarkEntry {
    fn from(value: SortItem) -> Self {
        let is_dir = !value.file || value.dir;
        let modified = parse_modified(value.last_op_time.as_ref())
            .or_else(|| value.l_updated_at.and_then(DateTime::<Utc>::from_timestamp_millis))
            .or_else(|| value.updated_at.and_then(DateTime::<Utc>::from_timestamp_millis));
        Self {
            id: value.fid,
            name: value.file_name,
            size: value.size.unwrap_or(0),
            is_dir,
            modified,
        }
    }
}

pub(super) fn to_file_info(path: &Path, entry: &QuarkEntry) -> FileInfo {
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

pub(super) fn parse_modified(raw: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    let value = raw?;
    if let Some(text) = value.as_str() {
        if let Ok(timestamp) = text.parse::<i64>() {
            return DateTime::<Utc>::from_timestamp_millis(timestamp);
        }
        return DateTime::parse_from_rfc3339(text).ok().map(|dt| dt.with_timezone(&Utc));
    }
    value.as_i64().and_then(DateTime::<Utc>::from_timestamp_millis)
}

pub(super) fn api_error(prefix: &str, message: Option<String>, code: i64) -> TokimoVfsError {
    match message.filter(|value| !value.is_empty()) {
        Some(message) => TokimoVfsError::Other(format!("{prefix}: [{code}] {message}")),
        None => TokimoVfsError::Other(format!("{prefix}: code {code}")),
    }
}

// ---- Upload Types ----

#[derive(Debug, Serialize)]
pub(super) struct UpPreRequest<'a> {
    pub ccp_hash_update: bool,
    pub dir_name: &'a str,
    pub file_name: &'a str,
    pub format_type: &'a str,
    pub l_created_at: i64,
    pub l_updated_at: i64,
    pub pdir_fid: &'a str,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpPreResp {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Option<UpPreData>,
    #[serde(default)]
    pub metadata: Option<UpPreMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub(super) struct UpPreData {
    pub task_id: String,
    #[serde(default)]
    pub finish: bool,
    #[serde(default)]
    pub upload_id: String,
    #[serde(default)]
    pub obj_key: String,
    #[serde(default)]
    pub upload_url: String,
    #[serde(default)]
    pub fid: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub callback: Option<UpCallback>,
    #[serde(default)]
    pub auth_info: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub(super) struct UpCallback {
    #[serde(rename = "callbackUrl")]
    pub callback_url: String,
    #[serde(rename = "callbackBody")]
    pub callback_body: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpPreMetadata {
    #[serde(default)]
    pub part_size: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct UpHashRequest<'a> {
    pub md5: &'a str,
    pub sha1: &'a str,
    pub task_id: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpHashResp {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Option<UpHashData>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpHashData {
    #[serde(default)]
    pub finish: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct UpAuthRequest<'a> {
    pub auth_info: &'a str,
    pub auth_meta: String,
    pub task_id: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpAuthResp {
    pub code: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub data: Option<UpAuthData>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpAuthData {
    pub auth_key: String,
}

#[derive(Debug, Serialize)]
pub(super) struct UpFinishRequest<'a> {
    pub obj_key: &'a str,
    pub task_id: &'a str,
}

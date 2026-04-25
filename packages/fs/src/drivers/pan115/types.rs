use std::path::Path;

use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};

use tokimo_vfs_core::error::TokimoVfsError;
use tokimo_vfs_core::model::obj::FileInfo;

#[derive(Debug, Clone)]
pub(super) struct Pan115Entry {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub pick_code: Option<String>,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginCheckResponse {
    pub state: i32,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct QrLoginResponse {
    pub state: i32,
    pub message: Option<String>,
    #[serde(default)]
    pub data: QrLoginData,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct QrLoginData {
    #[serde(default)]
    pub cookie: QrCredential,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct QrCredential {
    #[serde(default, rename = "UID")]
    pub uid: String,
    #[serde(default, rename = "CID")]
    pub cid: String,
    #[serde(default, rename = "SEID")]
    pub seid: String,
    #[serde(default, rename = "KID")]
    pub kid: String,
}

impl QrCredential {
    pub(super) fn to_cookie(&self) -> Option<String> {
        if self.uid.is_empty() || self.cid.is_empty() || self.seid.is_empty() {
            return None;
        }

        Some(format!(
            "UID={};CID={};SEID={};KID={}",
            self.uid, self.cid, self.seid, self.kid
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadResponse {
    pub state: bool,
    #[serde(default, alias = "msg")]
    pub message: Option<String>,
    #[serde(default, rename = "errNo")]
    pub err_no: Option<i64>,
    #[serde(default)]
    pub errno: Option<i64>,
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FileListResponse {
    pub state: bool,
    #[serde(default, alias = "msg")]
    pub message: Option<String>,
    #[serde(default, rename = "errNo")]
    pub err_no: Option<i64>,
    #[serde(default)]
    pub errno: Option<i64>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
    #[serde(default)]
    pub data: Vec<FileListItem>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FileListItem {
    #[serde(default)]
    pub cid: Option<String>,
    #[serde(default)]
    pub fid: Option<String>,
    #[serde(default, alias = "n")]
    pub name: String,
    #[serde(default, alias = "s")]
    pub size: StringOrNumber,
    #[serde(default, alias = "pc")]
    pub pick_code: Option<String>,
    #[serde(default, alias = "t")]
    pub modified: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct DownloadRequestPayload<'a> {
    pub pickcode: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadInfo {
    #[serde(default)]
    pub url: DownloadUrl,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct DownloadUrl {
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[derive(Default)]
pub(super) enum StringOrNumber {
    String(String),
    Number(u64),
    #[default]
    Empty,
}

impl StringOrNumber {
    pub(super) fn as_u64(&self) -> u64 {
        match self {
            Self::String(value) => value.parse::<u64>().unwrap_or(0),
            Self::Number(value) => *value,
            Self::Empty => 0,
        }
    }
}

impl From<FileListItem> for Pan115Entry {
    fn from(value: FileListItem) -> Self {
        let is_dir = value.fid.is_none();
        let id = value.fid.or(value.cid).unwrap_or_default();

        Self {
            id,
            name: value.name,
            size: if is_dir { 0 } else { value.size.as_u64() },
            is_dir,
            pick_code: value.pick_code,
            modified: parse_modified_time(value.modified.as_deref()),
        }
    }
}

pub(super) fn to_file_info(path: &Path, entry: &Pan115Entry) -> FileInfo {
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

pub(super) fn parse_modified_time(raw: Option<&str>) -> Option<DateTime<Utc>> {
    let value = raw?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<i64>() {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }

    let tz = FixedOffset::east_opt(8 * 3600)?;
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M")
        .ok()
        .and_then(|dt| dt.and_local_timezone(tz).single())
        .map(|dt| dt.with_timezone(&Utc))
}

pub(super) fn api_error(prefix: &str, message: Option<String>, code: Option<i64>) -> TokimoVfsError {
    match (message.filter(|value| !value.is_empty()), code) {
        (Some(message), Some(code)) => TokimoVfsError::Other(format!("{prefix}: [{code}] {message}")),
        (Some(message), None) => TokimoVfsError::Other(format!("{prefix}: {message}")),
        (None, Some(code)) => TokimoVfsError::Other(format!("{prefix}: code {code}")),
        (None, None) => TokimoVfsError::Other(prefix.to_string()),
    }
}

//! S3 compatible object storage driver powered by rust-s3.
//!
//! JSON config fields:
//!   endpoint            — S3 endpoint, optional; empty means AWS default endpoint
//!   bucket              — bucket name
//!   `access_key_id`       — access key id
//!   `secret_access_key`   — secret access key
//!   region              — region, optional; known endpoints like Aliyun OSS are inferred
//!   `session_token`       — STS session token, optional
//!   `root_folder_path`    — source root prefix, optional, defaults to "/"
//!   `force_path_style`    — force path-style ("true"/"false" or boolean)

use std::path::Path;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use reqwest::Client as HttpClient;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use tokio::sync::mpsc::Sender;
use tracing::error;

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{DeleteFile, Driver, Meta, PutFile, PutStream, Reader};
use tokimo_vfs_core::error::{TokimoVfsError, Result};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

pub const CONFIG: DriverConfig = DriverConfig {
    name: "s3",
    description: "S3 compatible object storage (rust-s3)",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

const PRESIGN_EXPIRY_SECS: u32 = 3600;
const STREAM_CHUNK_SIZE: u64 = 8 * 1024 * 1024;

pub struct S3Driver {
    bucket: Box<Bucket>,
    http: HttpClient,
    /// Normalized root prefix without leading/trailing slashes.
    /// Empty string means bucket root.
    root: String,
    caps: StorageCapabilities,
}

impl S3Driver {
    /// Build full S3 object key for a file path.
    fn file_key(&self, path: &Path) -> Option<String> {
        let relative = op_file_path(path);
        if relative.is_empty() {
            return None;
        }
        Some(self.prefixed_key(&relative))
    }

    /// Build S3 prefix for listing a directory.
    fn dir_prefix(&self, path: &Path) -> String {
        let normalized = normalize_display_path(path);
        if normalized == "/" {
            if self.root.is_empty() {
                String::new()
            } else {
                format!("{}/", self.root)
            }
        } else {
            let relative = normalized.trim_matches('/');
            if self.root.is_empty() {
                format!("{relative}/")
            } else {
                format!("{}/{}/", self.root, relative)
            }
        }
    }

    /// Prepend root prefix to a relative key.
    fn prefixed_key(&self, relative: &str) -> String {
        if self.root.is_empty() {
            relative.to_string()
        } else {
            format!("{}/{}", self.root, relative)
        }
    }

    /// Strip root prefix from an S3 key to get display path.
    fn display_path(&self, key: &str) -> String {
        let stripped = if self.root.is_empty() {
            key.to_string()
        } else {
            let prefix = format!("{}/", self.root);
            key.strip_prefix(&prefix).unwrap_or(key).to_string()
        };
        let trimmed = stripped.trim_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            format!("/{trimmed}")
        }
    }

    /// Fallback streaming via chunked range reads.
    async fn stream_chunked(&self, s3_key: &str, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let total_size = match self.bucket.head_object(s3_key).await {
            Ok((head, _)) => head.content_length.unwrap_or(0).max(0) as u64,
            Err(err) => {
                error!("s3 stream_chunked head failed: {}", err);
                return;
            }
        };

        let end = match limit {
            Some(length) => offset.saturating_add(length).min(total_size),
            None => total_size,
        };

        let mut pos = offset;
        while pos < end {
            let chunk_end = (pos + STREAM_CHUNK_SIZE).min(end);
            let range_end = chunk_end.saturating_sub(1);

            match self.bucket.get_object_range(s3_key, pos, Some(range_end)).await {
                Ok(resp) => {
                    if tx.send(resp.to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    error!("s3 stream_chunked read failed: {}", err);
                    break;
                }
            }

            pos = chunk_end;
        }
    }
}

fn build_driver(params: &serde_json::Value) -> Result<S3Driver> {
    let bucket_name = require_str(params, "bucket")?.to_string();
    let access_key_id = require_str(params, "access_key_id")?.to_string();
    let secret_access_key = require_str(params, "secret_access_key")?.to_string();
    let endpoint = optional_str(params, "endpoint").map(normalize_endpoint);
    let region_str = optional_str(params, "region")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default_region(endpoint.as_deref()));
    let session_token = optional_str(params, "session_token");
    let root = normalize_root(optional_str(params, "root_folder_path").as_deref().unwrap_or("/"));
    let force_path_style = read_bool(params, "force_path_style").unwrap_or(false);

    let region = match &endpoint {
        Some(ep) => Region::Custom {
            region: region_str,
            endpoint: ep.clone(),
        },
        None => region_str.parse().unwrap_or(Region::UsEast1),
    };

    let credentials = Credentials::new(
        Some(&access_key_id),
        Some(&secret_access_key),
        session_token.as_deref(),
        None,
        None,
    )
    .map_err(|e| TokimoVfsError::InvalidConfig(format!("S3 credentials error: {e}")))?;

    let mut bucket = Bucket::new(&bucket_name, region, credentials)
        .map_err(|e| TokimoVfsError::InvalidConfig(format!("S3 bucket error: {e}")))?;

    let use_path_style = force_path_style && !is_aliyun_oss_endpoint(endpoint.as_deref());
    if use_path_style {
        bucket = bucket.with_path_style();
    }

    let root_prefix = root.trim_matches('/').to_string();
    let http = HttpClient::new();

    let caps = StorageCapabilities {
        list: true,
        read: true,
        mkdir: false,
        delete_file: true,
        delete_dir: false,
        rename: false,
        write: true,
        symlink: false,
        range_read: true,
    };

    Ok(S3Driver {
        bucket,
        http,
        root: root_prefix,
        caps,
    })
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    Ok(Box::new(build_driver(params)?))
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("s3 driver is missing '{key}'")))
}

fn optional_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn read_bool(v: &serde_json::Value, key: &str) -> Option<bool> {
    match &v[key] {
        serde_json::Value::Bool(value) => Some(*value),
        serde_json::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Region / endpoint helpers
// ---------------------------------------------------------------------------

fn default_region(endpoint: Option<&str>) -> String {
    if let Some(region) = infer_region_from_endpoint(endpoint) {
        return region;
    }
    match endpoint {
        Some(value) if !value.contains("amazonaws.com") => "auto".to_string(),
        _ => "us-east-1".to_string(),
    }
}

fn is_aliyun_oss_endpoint(endpoint: Option<&str>) -> bool {
    endpoint
        .and_then(endpoint_host)
        .is_some_and(|host| host.ends_with(".aliyuncs.com"))
}

fn infer_region_from_endpoint(endpoint: Option<&str>) -> Option<String> {
    let host = endpoint.and_then(endpoint_host)?;
    infer_aliyun_region_from_host(host)
}

fn infer_aliyun_region_from_host(host: &str) -> Option<String> {
    let without_suffix = host.strip_suffix(".aliyuncs.com")?;
    let region = without_suffix
        .strip_prefix("s3.oss-")
        .or_else(|| without_suffix.strip_prefix("oss-"))?;
    let region = region.strip_suffix("-internal").unwrap_or(region);
    Some(region.to_string())
}

fn normalize_endpoint(endpoint: String) -> String {
    let Some(host) = endpoint_host(&endpoint) else {
        return endpoint;
    };

    if let Some(region) = host
        .strip_suffix(".aliyuncs.com")
        .and_then(|value| value.strip_prefix("oss-"))
    {
        let region = region.strip_suffix("-internal").unwrap_or(region);
        let has_internal = host.contains("-internal.aliyuncs.com");
        let normalized_host = if has_internal {
            format!("s3.oss-{region}-internal.aliyuncs.com")
        } else {
            format!("s3.oss-{region}.aliyuncs.com")
        };
        return replace_endpoint_host(&endpoint, &normalized_host);
    }

    endpoint
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    let without_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let host = without_scheme.split('/').next()?.trim();
    if host.is_empty() { None } else { Some(host) }
}

fn replace_endpoint_host(endpoint: &str, new_host: &str) -> String {
    if let Some((scheme, rest)) = endpoint.split_once("://") {
        let suffix = rest.find('/').map_or("", |idx| &rest[idx..]);
        format!("{scheme}://{new_host}{suffix}")
    } else {
        let suffix = endpoint.find('/').map_or("", |idx| &endpoint[idx..]);
        format!("{new_host}{suffix}")
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn normalize_root(raw: &str) -> String {
    let mut parts = Vec::new();
    for segment in raw.split('/') {
        let trimmed = segment.trim();
        if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
            continue;
        }
        parts.push(trimmed);
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn normalize_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }

    let mut parts = Vec::new();
    for segment in trimmed.split('/') {
        let seg = segment.trim();
        if seg.is_empty() || seg == "." || seg == ".." {
            continue;
        }
        parts.push(seg);
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn op_file_path(path: &Path) -> String {
    let normalized = normalize_display_path(path);
    if normalized == "/" {
        String::new()
    } else {
        normalized.trim_start_matches('/').to_string()
    }
}

fn file_name_from_display(path: &str) -> String {
    if path == "/" {
        return String::new();
    }
    path.rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Date / error helpers
// ---------------------------------------------------------------------------

fn parse_last_modified(s: &str) -> Option<DateTime<Utc>> {
    // ISO 8601 (from ListObjectsV2)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // RFC 2822 (from HEAD response)
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Common S3 format without timezone offset
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ") {
        return Some(dt.and_utc());
    }
    None
}

fn s3_to_nextfs(err: s3::error::S3Error) -> TokimoVfsError {
    let message = err.to_string();
    if message.contains("SignatureDoesNotMatch") {
        return TokimoVfsError::ConnectionError(format!(
            "S3 签名校验失败，请检查 AccessKey / SecretAccessKey、bucket、endpoint 是否彼此匹配；原始错误: {message}"
        ));
    }
    if message.contains("NoSuchKey") || message.contains("Not Found") {
        return TokimoVfsError::NotFound(message);
    }
    if message.contains("AccessDenied") || message.contains("Forbidden") {
        return TokimoVfsError::ConnectionError(message);
    }
    if message.contains("NoSuchBucket") {
        return TokimoVfsError::InvalidConfig(format!("Bucket 不存在: {message}"));
    }
    TokimoVfsError::Other(message)
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

#[async_trait]
impl Meta for S3Driver {
    fn driver_name(&self) -> &'static str {
        "s3"
    }

    async fn init(&self) -> Result<()> {
        let prefix = if self.root.is_empty() {
            String::new()
        } else {
            format!("{}/", self.root)
        };
        self.bucket
            .list(prefix, Some("/".to_string()))
            .await
            .map_err(s3_to_nextfs)?;
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let prefix = if self.root.is_empty() {
            String::new()
        } else {
            format!("{}/", self.root)
        };
        match self.bucket.list(prefix, Some("/".to_string())).await {
            Ok(_) => StorageStatus {
                driver: "s3".into(),
                state: ConnectionState::Connected,
                error: None,
                capabilities: self.capabilities(),
            },
            Err(err) => StorageStatus {
                driver: "s3".into(),
                state: ConnectionState::Error,
                error: Some(err.to_string()),
                capabilities: self.capabilities(),
            },
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        self.caps.clone()
    }
}

#[async_trait]
impl Reader for S3Driver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let prefix = self.dir_prefix(path);
        let results = self
            .bucket
            .list(prefix.clone(), Some("/".to_string()))
            .await
            .map_err(s3_to_nextfs)?;

        let mut entries = Vec::new();

        for page in &results {
            // Files (objects)
            for obj in &page.contents {
                let key = &obj.key;
                // Skip the prefix itself (some S3 implementations return it)
                if key.trim_end_matches('/') == prefix.trim_end_matches('/') {
                    continue;
                }
                let display = self.display_path(key);
                let name = file_name_from_display(&display);
                if name.is_empty() {
                    continue;
                }
                entries.push(FileInfo {
                    name,
                    path: display,
                    size: obj.size,
                    is_dir: false,
                    modified: parse_last_modified(&obj.last_modified),
                });
            }

            // Directories (common prefixes)
            if let Some(prefixes) = &page.common_prefixes {
                for cp in prefixes {
                    let display = self.display_path(&cp.prefix);
                    let name = file_name_from_display(&display);
                    if name.is_empty() {
                        continue;
                    }
                    entries.push(FileInfo {
                        name,
                        path: display,
                        size: 0,
                        is_dir: true,
                        modified: None,
                    });
                }
            }
        }

        Ok(entries)
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let display_path = normalize_display_path(path);
        if display_path == "/" {
            return Ok(FileInfo {
                name: String::new(),
                path: "/".to_string(),
                size: 0,
                is_dir: true,
                modified: None,
            });
        }

        let Some(s3_key) = self.file_key(path) else {
            return Err(TokimoVfsError::Other("invalid path".into()));
        };

        // Try as file first (HEAD object)
        if let Ok((head, code)) = self.bucket.head_object(&s3_key).await
            && (200..300).contains(&code)
        {
            return Ok(FileInfo {
                name: file_name_from_display(&display_path),
                path: display_path,
                size: head.content_length.unwrap_or(0).max(0) as u64,
                is_dir: false,
                modified: head.last_modified.as_deref().and_then(parse_last_modified),
            });
        }

        // Not a file — check if it's a virtual directory
        let prefix = self.dir_prefix(path);
        let results = self
            .bucket
            .list(prefix, Some("/".to_string()))
            .await
            .map_err(s3_to_nextfs)?;
        let has_children = results
            .iter()
            .any(|page| !page.contents.is_empty() || page.common_prefixes.as_ref().is_some_and(|p| !p.is_empty()));
        if has_children {
            Ok(FileInfo {
                name: file_name_from_display(&display_path),
                path: display_path,
                size: 0,
                is_dir: true,
                modified: None,
            })
        } else {
            Err(TokimoVfsError::NotFound(format!("path not found: {display_path}")))
        }
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let Some(s3_key) = self.file_key(path) else {
            return Err(TokimoVfsError::Other("s3 directory paths cannot be read".into()));
        };

        let resp = match limit {
            Some(length) => {
                let end = offset.saturating_add(length).saturating_sub(1);
                self.bucket.get_object_range(&s3_key, offset, Some(end)).await
            }
            None if offset > 0 => self.bucket.get_object_range(&s3_key, offset, None).await,
            None => self.bucket.get_object(&s3_key).await,
        }
        .map_err(s3_to_nextfs)?;

        Ok(resp.to_vec())
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let Some(s3_key) = self.file_key(path) else {
            error!("s3 stream_to: directory path is not readable");
            return;
        };

        // Generate presigned URL for true streaming via reqwest
        let presigned_url = match self.bucket.presign_get(&s3_key, PRESIGN_EXPIRY_SECS, None).await {
            Ok(url) => url,
            Err(err) => {
                error!("s3 stream_to presign failed: {err}");
                self.stream_chunked(&s3_key, offset, limit, tx).await;
                return;
            }
        };

        let mut request = self.http.get(&presigned_url);
        let range_header = match limit {
            Some(length) => Some(format!(
                "bytes={}-{}",
                offset,
                offset.saturating_add(length).saturating_sub(1)
            )),
            None if offset > 0 => Some(format!("bytes={offset}-")),
            None => None,
        };
        if let Some(range) = range_header {
            request = request.header("Range", range);
        }

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(err) => {
                error!("s3 stream_to request failed: {err}");
                return;
            }
        };

        let status = response.status().as_u16();
        if status != 200 && status != 206 {
            error!("s3 stream_to got status {status} for {s3_key}");
            return;
        }

        let mut stream = response.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    if tx.send(bytes.to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    error!("s3 stream_to read failed: {err}");
                    break;
                }
            }
        }
    }
}

impl Driver for S3Driver {
    fn as_put(&self) -> Option<&dyn PutFile> {
        Some(self)
    }

    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }

    fn as_delete_file(&self) -> Option<&dyn DeleteFile> {
        Some(self)
    }
}

#[async_trait]
impl PutFile for S3Driver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let Some(s3_key) = self.file_key(path) else {
            return Err(TokimoVfsError::Other("invalid path for put".into()));
        };
        let content_type = mime_from_path(path);
        self.bucket
            .put_object_with_content_type(&s3_key, &data, &content_type)
            .await
            .map_err(s3_to_nextfs)?;
        Ok(())
    }
}

#[async_trait]
impl PutStream for S3Driver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let mut buf = Vec::new();
        while let Some(chunk) = rx.recv().await {
            buf.extend_from_slice(&chunk);
        }
        self.put(path, buf).await
    }
}

#[async_trait]
impl DeleteFile for S3Driver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let Some(s3_key) = self.file_key(path) else {
            return Err(TokimoVfsError::Other("invalid path for delete".into()));
        };
        self.bucket.delete_object(&s3_key).await.map_err(s3_to_nextfs)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Direct S3 operations (bypassing virtual path normalization)
// ---------------------------------------------------------------------------

impl S3Driver {
    /// Create an `S3Driver` from a JSON config value.
    ///
    /// Same config fields as the registry factory:
    /// `bucket`, `access_key_id`, `secret_access_key`, `endpoint`, `region`,
    /// `session_token`, `root_folder_path`, `force_path_style`.
    pub fn from_config(config: &serde_json::Value) -> Result<Self> {
        build_driver(config)
    }

    /// Upload bytes to a raw S3 key (no path normalization).
    pub async fn put_object(&self, key: &str, data: &[u8], content_type: &str) -> Result<()> {
        let s3_key = self.prefixed_key(key);
        self.bucket
            .put_object_with_content_type(&s3_key, data, content_type)
            .await
            .map_err(s3_to_nextfs)?;
        Ok(())
    }

    /// Delete an object by raw S3 key (no path normalization).
    pub async fn delete_key(&self, key: &str) -> Result<()> {
        let s3_key = self.prefixed_key(key);
        self.bucket.delete_object(&s3_key).await.map_err(s3_to_nextfs)?;
        Ok(())
    }

    /// Check if an object exists by raw S3 key.
    pub async fn head_key(&self, key: &str) -> Result<bool> {
        let s3_key = self.prefixed_key(key);
        match self.bucket.head_object(&s3_key).await {
            Ok((_, code)) => Ok((200..300).contains(&code)),
            Err(_) => Ok(false),
        }
    }

    /// Download an object by raw S3 key.
    pub async fn get_key(&self, key: &str) -> Result<Vec<u8>> {
        let s3_key = self.prefixed_key(key);
        let resp = self.bucket.get_object(&s3_key).await.map_err(s3_to_nextfs)?;
        Ok(resp.to_vec())
    }

    /// List objects under a raw S3 key prefix.
    pub async fn list_prefix(&self, prefix: Option<&str>) -> Result<Vec<(String, u64)>> {
        let s3_prefix = match prefix {
            Some(p) => self.prefixed_key(p),
            None => {
                if self.root.is_empty() {
                    String::new()
                } else {
                    format!("{}/", self.root)
                }
            }
        };
        let results = self.bucket.list(s3_prefix, None).await.map_err(s3_to_nextfs)?;
        let objects = results
            .into_iter()
            .flat_map(|page| page.contents)
            .map(|obj| (obj.key, obj.size))
            .collect();
        Ok(objects)
    }
}

fn mime_from_path(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "json" => "application/json",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

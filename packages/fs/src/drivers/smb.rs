//! SMB/CIFS 驱动 — 基于 smb-rs（纯 Rust async，支持单连接并发多路复用）。
//!
//! JSON 配置字段：
//!   host      — SMB 服务器地址，如 "10.0.0.10"
//!   share     — 共享名称，如 "media"；逗号分隔多个：如 "public, media"；
//!              "*, hidden$" 自动列出所有 + 追加隐藏共享；留空或 "*" 列出所有
//!   username  — 用户名（可选；默认当前用户）
//!   password  — 密码（可选；未提供时按 libsmb2 风格读取 `NTLM_USER_FILE`）
//!   domain    — 域/工作组（可选；未提供时兼容旧行为，默认 "WORKGROUP"）
//!   root      — 共享内根目录（可选，默认 "/"）

use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use std::{collections::BTreeMap, pin::Pin};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokimo_vfs_core::driver::traits::{
    DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename,
};
use smb::connection::EncryptionMode;
use smb::resource::Directory;
use smb::{
    Client, ClientConfig, ConnectionConfig, CreateDisposition, CreateOptions, Dialect, FileAccessMask,
    FileAllInformation, FileCreateArgs, FileIdBothDirectoryInformation, FileStandardInformation, Resource, UncPath,
};
use smb_fscc::{FileAttributes, FileDispositionInformation, FileRenameInformation};
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::error::{TokimoVfsError, Result};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

pub const CONFIG: DriverConfig = DriverConfig {
    name: "smb",
    description: "SMB/CIFS 网络共享（smb-rs，纯 Rust async，并发多路复用）",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

#[derive(Clone)]
struct SmbParams {
    host: String,
    share: String,
    username: String,
    password: String,
    domain: String,
    root_path: String,
}

struct SmbState {
    client: Arc<Client>,
    base_unc: UncPath,
    root_path: String,
    read_chunk_size: usize,
    read_parallelism: usize,
    stream_chunk_size: usize,
    stream_parallelism: usize,
    write_chunk_size: usize,
    /// Per-connection file handle cache — eliminates the open/close round-trip
    /// on every sequential `read_bytes` call (e.g., the AVIO path reads 4 MB
    /// at a time, each previously paying ~140 ms for `CreateFile` + `CloseFile`).
    ///
    /// Safety: handles are bound to this `SmbState`'s client connection.
    /// When the connection is rotated, `SmbState` is replaced; the old
    /// `Arc<SmbState>` — and therefore this cache — is dropped when the last
    /// in-flight reference is released. `ResourceHandle::Drop` spawns an async
    /// close task for every evicted / dropped handle, so nothing leaks.
    read_handles: ReadHandleCache,
}

// ── ReadHandleCache ────────────────────────────────────────────────────────

/// Maximum number of simultaneously-cached open file handles per connection.
const READ_HANDLE_CACHE_CAPACITY: usize = 16;

/// LRU-by-insertion file handle cache backed by a `VecDeque`.
///
/// Capacity is small enough that linear search is faster than a hash map in
/// practice. Eviction drops the `Arc<File>`; `ResourceHandle::Drop` spawns the
/// async close automatically — no explicit `close()` needed here.
struct ReadHandleCache {
    entries: Mutex<VecDeque<(String, Arc<smb::resource::File>)>>,
}

impl ReadHandleCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(READ_HANDLE_CACHE_CAPACITY)),
        }
    }

    /// Return a clone of the cached `Arc<File>` for `path`, if present.
    fn get(&self, path: &str) -> Option<Arc<smb::resource::File>> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, h)| Arc::clone(h))
    }

    /// Insert (or replace) the handle for `path`.
    /// Evicts the oldest entry when capacity is exceeded; the evicted
    /// `Arc<File>` is dropped here, triggering `ResourceHandle::Drop`.
    fn insert(&self, path: String, handle: Arc<smb::resource::File>) {
        let mut entries = self.entries.lock().unwrap();
        // Remove existing entry for the same path to avoid duplicates.
        entries.retain(|(p, _)| p != &path);
        if entries.len() >= READ_HANDLE_CACHE_CAPACITY {
            entries.pop_front(); // oldest entry dropped → ResourceHandle::Drop closes it
        }
        entries.push_back((path, handle));
    }

    /// Remove the cached handle for `path` (e.g., after a read error).
    /// The dropped `Arc<File>` triggers `ResourceHandle::Drop`.
    fn evict(&self, path: &str) {
        self.entries.lock().unwrap().retain(|(p, _)| p != path);
    }
}

#[derive(Default)]
struct SmbReadUsage {
    ops: u64,
    bytes: u64,
}

pub struct NativeSmbDriver {
    params: SmbParams,
    caps: StorageCapabilities,
    inner: Arc<Mutex<Option<Arc<SmbState>>>>,
    read_usage: Arc<Mutex<SmbReadUsage>>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let host = require_str(params, "host")?.trim().to_string();
    let share = params["share"]
        .as_str()
        .unwrap_or("")
        .trim()
        .trim_matches(|c| c == '/' || c == '\\')
        .to_string();
    let username = params["username"].as_str().unwrap_or("").trim().to_string();
    let password = params["password"].as_str().unwrap_or("").trim().to_string();
    let domain = params["domain"].as_str().unwrap_or("").trim().to_string();
    let root_path = normalize_root(params["root"].as_str().unwrap_or("/"));

    if share.is_empty() || share == "*" {
        return Ok(Box::new(SmbMultiShareDriver::new(host, username, password, domain, ShareMode::EnumerateAll)));
    }

    // Comma-separated share names → multi-share driver
    if share.contains(',') {
        let names: Vec<String> = share
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if names.is_empty() {
            return Ok(Box::new(SmbMultiShareDriver::new(host, username, password, domain, ShareMode::EnumerateAll)));
        }

        let has_wildcard = names.iter().any(|n| n == "*");
        if has_wildcard {
            // "*, hidden$, admin$" → enumerate all + extra manual entries
            let extras: Vec<String> = names.into_iter().filter(|n| n != "*").collect();
            return Ok(Box::new(SmbMultiShareDriver::new(host, username, password, domain, ShareMode::EnumeratePlusExtra(extras))));
        }

        if names.len() == 1 {
            // Single share after trimming — use direct driver
            let p = SmbParams {
                host,
                share: names.into_iter().next().unwrap(),
                username,
                password,
                domain,
                root_path,
            };
            let caps = StorageCapabilities {
                list: true,
                read: true,
                mkdir: true,
                delete_file: true,
                delete_dir: true,
                rename: true,
                write: true,
                symlink: false,
                range_read: true,
            };
            return Ok(Box::new(NativeSmbDriver {
                params: p,
                caps,
                inner: Arc::new(Mutex::new(None)),
                read_usage: Arc::new(Mutex::new(SmbReadUsage::default())),
            }));
        }
        return Ok(Box::new(SmbMultiShareDriver::new(host, username, password, domain, ShareMode::Explicit(names))));
    }

    let p = SmbParams {
        host,
        share,
        username,
        password,
        domain,
        root_path,
    };
    let caps = StorageCapabilities {
        list: true,
        read: true,
        mkdir: true,
        delete_file: true,
        delete_dir: true,
        rename: true,
        write: true,
        symlink: false,
        range_read: true,
    };
    Ok(Box::new(NativeSmbDriver {
        params: p,
        caps,
        inner: Arc::new(Mutex::new(None)),
        read_usage: Arc::new(Mutex::new(SmbReadUsage::default())),
    }))
}

fn require_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("smb 驱动缺少 '{key}' 字段")))
}

fn normalize_root(root: &str) -> String {
    let trimmed = root.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.trim_end_matches('/').to_string()
    } else {
        format!("/{}", trimmed.trim_end_matches('/'))
    }
}

fn current_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("LOGNAME").ok().filter(|value| !value.trim().is_empty()))
}

fn read_ntlm_password_from_file(domain: &str, server: &str) -> Option<String> {
    let path = std::env::var("NTLM_USER_FILE").ok()?;
    let contents = std::fs::read_to_string(path).ok()?;
    let mut wildcard_password = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }

        let mut parts = line.splitn(3, ':');
        let entry_domain = parts.next()?;
        let _entry_user = parts.next()?;
        let entry_password = parts.next()?;

        if !entry_domain.is_empty() && !domain.is_empty() && entry_domain == domain {
            return Some(entry_password.to_string());
        }

        if !entry_domain.is_empty() && entry_domain == server {
            return Some(entry_password.to_string());
        }

        if entry_domain.is_empty() {
            wildcard_password = Some(entry_password.to_string());
        }
    }

    wildcard_password
}

fn effective_domain(domain: &str) -> &str {
    domain
}

const SMB_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const SMB_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

fn smb_operation_timeout() -> Duration {
    SMB_OPERATION_TIMEOUT
}

fn smb_dialect_label(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Smb0202 => "SMB 2.0.2",
        Dialect::Smb021 => "SMB 2.1",
        Dialect::Smb030 => "SMB 3.0",
        Dialect::Smb0302 => "SMB 3.0.2",
        Dialect::Smb0311 => "SMB 3.1.1",
    }
}

const SMB_MIN_READ_CHUNK: usize = 1024 * 1024;
const SMB_MAX_READ_CHUNK: usize = 8 * 1024 * 1024;
const SMB_MAX_STREAM_CHUNK: usize = 1024 * 1024;
const SMB_TARGET_INFLIGHT_BYTES: usize = 512 * 1024 * 1024;
const SMB_STREAM_TARGET_INFLIGHT_BYTES: usize = 128 * 1024 * 1024;
const SMB_MIN_READ_PARALLELISM: usize = 8;
const SMB_MAX_READ_PARALLELISM: usize = 128;
const SMB_MIN_STREAM_PARALLELISM: usize = 4;
const SMB_MAX_STREAM_PARALLELISM: usize = 32;
const SMB_OPEN_ENDED_STREAM_PARALLELISM_CAP: usize = 4;
const SMB_CREDITS_BACKLOG: u16 = 2048;

fn compute_read_window(max_read_size: usize) -> (usize, usize) {
    let chunk_size = max_read_size
        .max(SMB_MIN_READ_CHUNK)
        .clamp(SMB_MIN_READ_CHUNK, SMB_MAX_READ_CHUNK);
    let parallelism = SMB_TARGET_INFLIGHT_BYTES
        .div_ceil(chunk_size)
        .clamp(SMB_MIN_READ_PARALLELISM, SMB_MAX_READ_PARALLELISM);
    (chunk_size, parallelism)
}

fn compute_stream_window(max_read_size: usize) -> (usize, usize) {
    let chunk_size = max_read_size
        .max(SMB_MIN_READ_CHUNK)
        .clamp(SMB_MIN_READ_CHUNK, SMB_MAX_STREAM_CHUNK);
    let parallelism = SMB_STREAM_TARGET_INFLIGHT_BYTES
        .div_ceil(chunk_size)
        .clamp(SMB_MIN_STREAM_PARALLELISM, SMB_MAX_STREAM_PARALLELISM);
    (chunk_size, parallelism)
}

fn build_client() -> Arc<Client> {
    Arc::new(Client::new(ClientConfig {
        dfs: false,
        connection: ConnectionConfig {
            timeout: Some(SMB_CONNECTION_TIMEOUT),
            encryption_mode: EncryptionMode::Disabled,
            disable_notifications: true,
            smb2_only_negotiate: true,
            credits_backlog: Some(SMB_CREDITS_BACKLOG),
            ..Default::default()
        },
        ..Default::default()
    }))
}

/// Classify an NT status code (from `UnexpectedMessageStatus` / `ReceivedErrorMessage`)
/// into the correct `TokimoVfsError` variant.
fn classify_nt_status(status: u32, context: &str, err: &smb::Error) -> TokimoVfsError {
    let msg = format!("smb {context}: {err}");
    match status {
        // Not-found — the path/name simply doesn't exist; never retry.
        smb::Status::U32_OBJECT_NAME_NOT_FOUND | smb::Status::U32_OBJECT_PATH_NOT_FOUND => TokimoVfsError::NotFound(msg),
        // Session/connection torn down by the server — worth a reconnect.
        smb::Status::U32_NETWORK_NAME_DELETED
        | smb::Status::U32_NETWORK_SESSION_EXPIRED
        | smb::Status::U32_USER_SESSION_DELETED
        | smb::Status::U32_IO_TIMEOUT => TokimoVfsError::ConnectionError(msg),
        // Everything else (access-denied, sharing-violation, etc.) — not retryable.
        _ => TokimoVfsError::Other(msg),
    }
}

/// Central mapping from `smb::Error` → `TokimoVfsError`.
///
/// All SMB operations must use this instead of ad-hoc string wrapping so that
/// `should_retry_smb` can rely purely on the `TokimoVfsError` variant without
/// fragile string matching.
fn smb_err(context: &str, err: smb::Error) -> TokimoVfsError {
    match &err {
        // NT status codes carried in two different smb::Error variants.
        smb::Error::UnexpectedMessageStatus(status) | smb::Error::ReceivedErrorMessage(status, _) => {
            classify_nt_status(*status, context, &err)
        }

        // Clearly connection-level failures.
        smb::Error::ConnectionStopped
        | smb::Error::OperationTimeout(_, _)
        | smb::Error::IoError(_)
        | smb::Error::TransportError(_) => TokimoVfsError::ConnectionError(format!("smb {context}: {err}")),

        // Anything else is a non-retryable operational error.
        _ => TokimoVfsError::Other(format!("smb {context}: {err}")),
    }
}

/// Only connection-level errors warrant a reconnect + retry.
fn should_retry_smb(err: &TokimoVfsError) -> bool {
    matches!(err, TokimoVfsError::ConnectionError(_))
}

async fn run_with_smb_timeout<T, Fut>(label: &str, timeout: Duration, fut: Fut) -> Result<T>
where
    Fut: Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(TokimoVfsError::ConnectionError(format!(
            "smb {} timed out after {}s",
            label,
            timeout.as_secs()
        ))),
    }
}

fn filetime_to_datetime(ft_dur: Duration) -> DateTime<Utc> {
    const WINDOWS_TO_UNIX_SECS: u64 = 11_644_473_600;
    let unix_secs = ft_dur.as_secs().saturating_sub(WINDOWS_TO_UNIX_SECS);
    DateTime::<Utc>::from(UNIX_EPOCH + Duration::new(unix_secs, ft_dur.subsec_nanos()))
}

fn build_unc(base: &UncPath, root_path: &str, sub_path: &str) -> UncPath {
    let root = root_path.trim_matches('/');
    let sub = sub_path.trim_matches('/');
    let full = match (root.is_empty(), sub.is_empty()) {
        (true, true) => String::new(),
        (true, false) => sub.to_string(),
        (false, true) => root.to_string(),
        (false, false) => format!("{root}/{sub}"),
    };
    if full.is_empty() {
        base.clone()
    } else {
        base.clone().with_path(&full)
    }
}

fn get_state(inner: &Arc<Mutex<Option<Arc<SmbState>>>>) -> Result<Arc<SmbState>> {
    inner
        .lock()
        .map_err(|_| TokimoVfsError::ConnectionError("mutex poisoned".into()))?
        .as_ref()
        .cloned()
        .ok_or_else(|| TokimoVfsError::ConnectionError("未连接".into()))
}

fn open_file_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        attributes: FileAttributes::default(),
        options: CreateOptions::new().with_non_directory_file(true),
        desired_access: FileAccessMask::new().with_generic_read(true),
    }
}

fn open_dir_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        attributes: FileAttributes::default(),
        options: CreateOptions::new().with_directory_file(true),
        desired_access: FileAccessMask::new().with_generic_read(true),
    }
}

fn mkdir_dir_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Create,
        attributes: FileAttributes::default(),
        options: CreateOptions::new().with_directory_file(true),
        desired_access: FileAccessMask::new().with_generic_read(true).with_generic_write(true),
    }
}

fn open_mutable_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        attributes: FileAttributes::default(),
        options: CreateOptions::new(),
        desired_access: FileAccessMask::new().with_generic_read(true).with_delete(true),
    }
}

fn open_mutable_dir_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        attributes: FileAttributes::default(),
        options: CreateOptions::new().with_directory_file(true),
        desired_access: FileAccessMask::new().with_generic_read(true).with_delete(true),
    }
}

fn overwrite_file_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::OverwriteIf,
        attributes: FileAttributes::default(),
        options: CreateOptions::new().with_non_directory_file(true),
        desired_access: FileAccessMask::new().with_generic_read(true).with_generic_write(true),
    }
}

fn child_path(parent: &Path, name: &str) -> String {
    let base = parent.to_string_lossy();
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

fn share_relative_path(root_path: &str, path: &Path) -> String {
    let root = root_path.trim_matches('/');
    let sub = path.to_string_lossy();
    let sub = sub.trim_matches('/');
    let full = match (root.is_empty(), sub.is_empty()) {
        (true, true) => String::new(),
        (true, false) => sub.to_string(),
        (false, true) => root.to_string(),
        (false, false) => format!("{root}/{sub}"),
    };
    if full.is_empty() {
        "\\".to_string()
    } else {
        format!(r"\{}", full.replace('/', "\\"))
    }
}

fn move_destination(from: &Path, to_dir: &Path) -> Result<std::path::PathBuf> {
    let name = from
        .file_name()
        .ok_or_else(|| TokimoVfsError::Other(format!("smb move: 无法确定源文件名: {}", from.display())))?;
    Ok(if to_dir == Path::new("/") {
        Path::new("/").join(name)
    } else {
        to_dir.join(name)
    })
}

fn ensure_non_root_path(path: &Path, action: &str) -> Result<()> {
    if path == Path::new("/") {
        return Err(TokimoVfsError::Other(format!("smb {action}: 根目录不允许此操作")));
    }
    Ok(())
}

async fn open_file_resource(state: &SmbState, path: &Path) -> Result<smb::resource::File> {
    let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
    let resource = state
        .client
        .create_file(&unc, &open_file_args())
        .await
        .map_err(|e| smb_err("open file", e))?;
    match resource {
        Resource::File(file) => Ok(file),
        _ => Err(TokimoVfsError::Other(format!(
            "smb open file: {} 不是普通文件",
            path.display()
        ))),
    }
}

async fn read_chunk(
    file: Arc<smb::resource::File>,
    pos: u64,
    step: usize,
    context: &'static str,
) -> Result<(Vec<u8>, usize)> {
    // SMB2 reads can return fewer bytes than requested (short reads) without
    // indicating EOF. Retry until the full chunk is filled or true EOF (0).
    let mut out = Vec::with_capacity(step);
    let mut remaining = step;
    let mut current_pos = pos;

    while remaining > 0 {
        let mut buf = vec![0u8; remaining];
        match file.read_block(&mut buf, current_pos, None, false).await {
            Ok(0) => {
                tracing::debug!(
                    "{}: read_block returned 0 at pos={} (started at pos={}, step={}, got {}B so far)",
                    context,
                    current_pos,
                    pos,
                    step,
                    out.len()
                );
                break;
            }
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                remaining -= n;
                current_pos += n as u64;
            }
            Err(err) => {
                tracing::error!(
                    "{}: read_block error at pos={} (started at pos={}, step={}, got {}B so far): {}",
                    context,
                    current_pos,
                    pos,
                    step,
                    out.len(),
                    err
                );
                return Err(smb_err(context, smb::Error::IoError(err)));
            }
        }
    }

    if out.is_empty() {
        Ok((Vec::new(), step))
    } else {
        Ok((out, step))
    }
}

#[allow(clippy::type_complexity)]
fn spawn_read(
    file: Arc<smb::resource::File>,
    idx: usize,
    pos: u64,
    end: u64,
    chunk_size: usize,
    context: &'static str,
) -> Pin<Box<dyn Future<Output = Result<(usize, Vec<u8>, usize)>> + Send>> {
    let step = ((end - pos) as usize).min(chunk_size);
    Box::pin(async move {
        let (chunk, expected) = read_chunk(file, pos, step, context).await?;
        Ok((idx, chunk, expected))
    })
}

impl NativeSmbDriver {
    fn reset_read_usage(&self) {
        *self.read_usage.lock().unwrap() = SmbReadUsage::default();
    }

    async fn maybe_rotate_read_connection(&self, requested_bytes: u64) -> Result<()> {
        const READ_ROTATE_INTERVAL_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
        const READ_ROTATE_INTERVAL_OPS: u64 = 2048;

        let should_rotate = {
            let usage = self.read_usage.lock().unwrap();
            usage.ops > 0 && (usage.bytes >= READ_ROTATE_INTERVAL_BYTES || usage.ops >= READ_ROTATE_INTERVAL_OPS)
        };

        if should_rotate {
            self.reconnect_state().await?;
        }

        let mut usage = self.read_usage.lock().unwrap();
        usage.ops = usage.ops.saturating_add(1);
        usage.bytes = usage.bytes.saturating_add(requested_bytes);
        Ok(())
    }

    async fn ensure_state(&self) -> Result<Arc<SmbState>> {
        let needs_init = { self.inner.lock().unwrap().is_none() };
        if needs_init {
            self.init().await?;
        }
        get_state(&self.inner)
    }

    #[allow(clippy::unused_async)]
    async fn clear_state(&self) {
        // Only remove the state from the mutex — do NOT close the client.
        // Active stream_to tasks hold Arc<SmbState> clones with open file
        // handles. Calling client.close() here would kill their underlying
        // TCP connection mid-stream. Instead, let the old client be cleaned
        // up naturally when the last Arc reference (from stream_to's file
        // handle) is dropped.
        let _old_state = { self.inner.lock().unwrap().take() };
    }

    async fn reconnect_state(&self) -> Result<Arc<SmbState>> {
        self.clear_state().await;
        self.init().await?;
        self.reset_read_usage();
        get_state(&self.inner)
    }

    async fn with_retry<T, Op, Fut>(&self, op: Op) -> Result<T>
    where
        Op: Fn(Arc<SmbState>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.with_retry_timeout(smb_operation_timeout(), op).await
    }

    async fn with_retry_timeout<T, Op, Fut>(&self, timeout: Duration, op: Op) -> Result<T>
    where
        Op: Fn(Arc<SmbState>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let state = self.ensure_state().await?;
        match run_with_smb_timeout("operation", timeout, op(state)).await {
            Ok(value) => Ok(value),
            Err(err) if should_retry_smb(&err) => {
                warn!("SMB operation failed, reconnecting and retrying once: {}", err);
                let state = self.reconnect_state().await?;
                run_with_smb_timeout("retry", timeout, op(state)).await
            }
            Err(err) => Err(err),
        }
    }

    async fn list_with_state(state: Arc<SmbState>, path: &Path) -> Result<Vec<FileInfo>> {
        let dir_unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&dir_unc, &open_dir_args())
            .await
            .map_err(|e| smb_err("list open", e))?;

        let Resource::Directory(dir) = resource else {
            return Err(TokimoVfsError::Other(format!("smb list: {} 不是目录", path.display())));
        };

        let dir = Arc::new(dir);

        // 不在 query/iterate 时直接 ?，而是收集错误后再统一 close dir。
        // SMB resource 的 Drop 会通过 tokio::spawn 发起 TreeDisconnect，若
        // close 前 worker 已停止（如 clear_state 触发重连），后台任务会失败。
        // 显式 close 保证 TreeDisconnect 在 worker 停止前完成。
        let mut stream = match Directory::query::<FileIdBothDirectoryInformation>(&dir, "*").await {
            Ok(s) => s,
            Err(e) => {
                // query 失败时 worker 仍在运行，dir 的异步 Drop 能正常完成 TreeDisconnect。
                return Err(smb_err("list query", e));
            }
        };

        let mut entries = Vec::new();
        let mut list_error: Option<TokimoVfsError> = None;
        while let Some(entry_res) = stream.next().await {
            match entry_res {
                Ok(entry) => {
                    let name = entry.file_name.to_string();
                    if name.is_empty() || name == "." || name == ".." {
                        continue;
                    }
                    entries.push(FileInfo {
                        path: child_path(path, &name),
                        name,
                        size: entry.end_of_file,
                        is_dir: entry.file_attributes.directory(),
                        modified: Some(filetime_to_datetime(entry.last_write_time.since_epoch())),
                    });
                }
                Err(e) => {
                    list_error = Some(smb_err("list entry", e));
                    break;
                }
            }
        }
        drop(stream);
        if let Ok(d) = Arc::try_unwrap(dir) {
            let _ = d.close().await;
        }
        if let Some(e) = list_error {
            return Err(e);
        }
        Ok(entries)
    }

    async fn stat_with_state(state: Arc<SmbState>, path: &Path) -> Result<FileInfo> {
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = match state.client.create_file(&unc, &open_file_args()).await {
            Ok(resource) => resource,
            Err(smb::Error::UnexpectedMessageStatus(status)) if status == smb::Status::U32_FILE_IS_A_DIRECTORY => state
                .client
                .create_file(&unc, &open_dir_args())
                .await
                .map_err(|e| smb_err("stat open dir", e))?,
            Err(err) => return Err(smb_err("stat open", err)),
        };

        // 先查询，不用 ? 直接返回，query 完成后再显式 close resource。
        let query_result = match &resource {
            Resource::File(file) => file
                .query_info::<FileAllInformation>()
                .await
                .map_err(|e| smb_err("stat query", e)),
            Resource::Directory(dir) => dir
                .query_info::<FileAllInformation>()
                .await
                .map_err(|e| smb_err("stat query", e)),
            Resource::Pipe(_) => Err(TokimoVfsError::Other(format!(
                "smb stat: {} 资源类型不支持",
                path.display()
            ))),
        };
        match resource {
            Resource::File(f) => {
                let _ = f.close().await;
            }
            Resource::Directory(d) => {
                let _ = d.close().await;
            }
            Resource::Pipe(_) => {}
        }
        let info = query_result?;

        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("").to_string();

        Ok(FileInfo {
            name,
            path: path.to_string_lossy().to_string(),
            size: info.standard.end_of_file,
            is_dir: bool::from(info.standard.directory),
            modified: Some(filetime_to_datetime(info.basic.last_write_time.since_epoch())),
        })
    }

    async fn read_bytes_with_state(
        state: Arc<SmbState>,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
    ) -> Result<Vec<u8>> {
        let path_key = path.to_string_lossy().into_owned();

        // ── get or open the file handle ────────────────────────────────────
        // Re-use a cached handle to avoid the ~140 ms CreateFile + CloseFile
        // round-trip that previously occurred on every 4 MB AVIO read.
        let file = if let Some(cached) = state.read_handles.get(&path_key) {
            cached
        } else {
            let handle = Arc::new(open_file_resource(&state, path).await?);
            state.read_handles.insert(path_key.clone(), Arc::clone(&handle));
            handle
        };

        // ── resolve how many bytes to read ────────────────────────────────
        let to_read = if let Some(limit) = limit {
            limit
        } else {
            match file.query_info::<FileStandardInformation>().await {
                Err(e) => {
                    state.read_handles.evict(&path_key);
                    return Err(smb_err("query size", e));
                }
                Ok(info) => {
                    if offset >= info.end_of_file {
                        return Ok(Vec::new());
                    }
                    info.end_of_file - offset
                }
            }
        };
        if to_read == 0 {
            return Ok(Vec::new());
        }

        // ── parallel chunked read ──────────────────────────────────────────
        let end = offset + to_read;
        let chunk_size = state.read_chunk_size;
        let parallelism = state.read_parallelism;
        let mut out = Vec::with_capacity(to_read.min((chunk_size * parallelism) as u64) as usize);
        let mut positions = std::iter::successors(Some(offset), move |pos| {
            let next = *pos + chunk_size as u64;
            (next < end).then_some(next)
        })
        .enumerate();
        let mut reads = FuturesUnordered::new();
        let mut ready = BTreeMap::new();
        let mut next_idx = 0usize;
        let mut stop_scheduling = false;

        for _ in 0..parallelism {
            let Some((idx, pos)) = positions.next() else {
                break;
            };
            reads.push(spawn_read(Arc::clone(&file), idx, pos, end, chunk_size, "read"));
        }

        let mut read_error: Option<TokimoVfsError> = None;
        'read_loop: while let Some(chunk_res) = reads.next().await {
            let (idx, chunk, expected) = match chunk_res {
                Ok(v) => v,
                Err(e) => {
                    read_error = Some(e);
                    break 'read_loop;
                }
            };
            ready.insert(idx, (chunk, expected));

            if !stop_scheduling && let Some((next_read_idx, next_pos)) = positions.next() {
                reads.push(spawn_read(
                    Arc::clone(&file),
                    next_read_idx,
                    next_pos,
                    end,
                    chunk_size,
                    "read",
                ));
            }

            while let Some((chunk, expected)) = ready.remove(&next_idx) {
                next_idx += 1;
                if chunk.is_empty() {
                    stop_scheduling = true;
                    continue;
                }
                let actual = chunk.len();
                out.extend_from_slice(&chunk);
                if actual < expected {
                    stop_scheduling = true;
                }
            }
        }

        drop(reads);

        if let Some(e) = read_error {
            // Evict the handle so the next call opens a fresh one.
            // ResourceHandle::Drop sends the async close via tokio::spawn.
            state.read_handles.evict(&path_key);
            return Err(e);
        }

        // Handle stays in cache — no explicit close needed here.
        // When the cache evicts it (capacity exceeded, connection rotated, or
        // driver dropped), ResourceHandle::Drop spawns the close task.
        Ok(out)
    }

    async fn mkdir_with_state(state: Arc<SmbState>, path: &Path) -> Result<()> {
        ensure_non_root_path(path, "mkdir")?;
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&unc, &mkdir_dir_args())
            .await
            .map_err(|err| smb_err("mkdir", err))?;
        match resource {
            Resource::Directory(dir) => dir.close().await.map_err(|err| smb_err("mkdir close", err)),
            _ => Err(TokimoVfsError::Other(format!(
                "smb mkdir: {} 返回了非目录资源",
                path.display()
            ))),
        }
    }

    async fn delete_file_with_state(state: Arc<SmbState>, path: &Path) -> Result<()> {
        ensure_non_root_path(path, "delete_file")?;
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&unc, &open_mutable_args())
            .await
            .map_err(|err| smb_err("delete file open", err))?;
        match resource {
            Resource::File(file) => {
                file.set_info(FileDispositionInformation {
                    delete_pending: true.into(),
                })
                .await
                .map_err(|err| smb_err("delete file set_info", err))?;
                file.close().await.map_err(|err| smb_err("delete file close", err))
            }
            _ => Err(TokimoVfsError::Other(format!(
                "smb delete_file: {} 不是普通文件",
                path.display()
            ))),
        }
    }

    async fn delete_dir_with_state(state: Arc<SmbState>, path: &Path) -> Result<()> {
        ensure_non_root_path(path, "delete_dir")?;
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&unc, &open_mutable_dir_args())
            .await
            .map_err(|err| smb_err("delete dir open", err))?;
        match resource {
            Resource::Directory(dir) => {
                dir.set_info(FileDispositionInformation {
                    delete_pending: true.into(),
                })
                .await
                .map_err(|err| smb_err("delete dir set_info", err))?;
                dir.close().await.map_err(|err| smb_err("delete dir close", err))
            }
            _ => Err(TokimoVfsError::Other(format!(
                "smb delete_dir: {} 不是目录",
                path.display()
            ))),
        }
    }

    async fn rename_with_state(state: Arc<SmbState>, from: &Path, to: &Path) -> Result<()> {
        ensure_non_root_path(from, "rename")?;
        ensure_non_root_path(to, "rename")?;
        let from_unc = build_unc(&state.base_unc, &state.root_path, &from.to_string_lossy());
        let target_name = share_relative_path(&state.root_path, to);
        let file_open = state.client.create_file(&from_unc, &open_mutable_args()).await;
        let resource = match file_open {
            Ok(resource) => resource,
            Err(smb::Error::UnexpectedMessageStatus(status)) if status == smb::Status::U32_FILE_IS_A_DIRECTORY => state
                .client
                .create_file(&from_unc, &open_mutable_dir_args())
                .await
                .map_err(|err| smb_err("rename open dir", err))?,
            Err(err) => return Err(smb_err("rename open", err)),
        };
        let rename = FileRenameInformation {
            replace_if_exists: false.into(),
            root_directory: 0,
            file_name: target_name.into(),
        };
        match resource {
            Resource::File(file) => {
                file.set_info(rename)
                    .await
                    .map_err(|err| smb_err("rename set_info", err))?;
                file.close().await.map_err(|err| smb_err("rename close", err))
            }
            Resource::Directory(dir) => {
                dir.set_info(rename)
                    .await
                    .map_err(|err| smb_err("rename set_info", err))?;
                dir.close().await.map_err(|err| smb_err("rename close", err))
            }
            Resource::Pipe(_) => Err(TokimoVfsError::Other(format!(
                "smb rename: {} 资源类型不支持",
                from.display()
            ))),
        }
    }

    async fn move_with_state(state: Arc<SmbState>, from: &Path, to_dir: &Path) -> Result<()> {
        let destination = move_destination(from, to_dir)?;
        Self::rename_with_state(state, from, &destination).await
    }

    async fn put_with_state(state: Arc<SmbState>, path: &Path, data: &[u8]) -> Result<()> {
        ensure_non_root_path(path, "put")?;
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&unc, &overwrite_file_args())
            .await
            .map_err(|err| smb_err("put open", err))?;
        let Resource::File(file) = resource else {
            return Err(TokimoVfsError::Other(format!(
                "smb put: {} 返回了非文件资源",
                path.display()
            )));
        };

        let chunk_size = state.write_chunk_size;
        let mut offset = 0u64;
        while (offset as usize) < data.len() {
            let end = (offset as usize + chunk_size).min(data.len());
            let written = file
                .write_block(&data[offset as usize..end], offset, None)
                .await
                .map_err(|err| smb_err("put write", smb::Error::IoError(err)))?;
            if written == 0 {
                return Err(TokimoVfsError::Other(format!(
                    "smb put: {} 写入返回 0 字节",
                    path.display()
                )));
            }
            offset += written as u64;
        }

        file.close().await.map_err(|err| smb_err("put close", err))
    }
}

#[async_trait]
impl Meta for NativeSmbDriver {
    fn driver_name(&self) -> &'static str {
        "smb"
    }

    async fn init(&self) -> Result<()> {
        if self.inner.lock().unwrap().is_some() {
            return Ok(());
        }

        let params = self.params.clone();
        let unc_str = format!(r"\\{}\{}", params.host, params.share);
        let base_unc =
            UncPath::from_str(&unc_str).map_err(|e| TokimoVfsError::InvalidConfig(format!("非法 SMB UNC 路径: {e}")))?;

        let user_name = if params.username.is_empty() {
            current_username().unwrap_or_else(|| "guest".to_string())
        } else {
            params.username.clone()
        };

        let effective_domain = effective_domain(&params.domain);
        let qualified_user = if user_name.contains('\\') || user_name.contains('@') || effective_domain.is_empty() {
            user_name.clone()
        } else {
            format!(r"{effective_domain}\{user_name}")
        };
        let password = if params.password.is_empty() {
            read_ntlm_password_from_file(effective_domain, &params.host).unwrap_or_default()
        } else {
            params.password.clone()
        };

        let client = build_client();
        client
            .share_connect(&base_unc, &qualified_user, password.clone())
            .await
            .map_err(|err| TokimoVfsError::ConnectionError(format!("SMB connect failed: {err}")))?;

        let root_unc = build_unc(&base_unc, &params.root_path, "");
        client
            .create_file(&root_unc, &open_dir_args())
            .await
            .map_err(|e| smb_err("open root", e))?;

        let conn = client
            .get_connection(base_unc.server())
            .await
            .map_err(|e| smb_err("get connection info", e))?;
        let negotiated = conn
            .conn_info()
            .ok_or_else(|| TokimoVfsError::Other("smb get connection info: 未完成协商".into()))?;
        let smb_version = smb_dialect_label(negotiated.negotiation.dialect_rev);
        let (read_chunk_size, read_parallelism) = compute_read_window(negotiated.negotiation.max_read_size as usize);
        let (stream_chunk_size, stream_parallelism) =
            compute_stream_window(negotiated.negotiation.max_read_size as usize);
        // Cap write chunks at the server's negotiated max_write_size (usually 1-8 MB).
        let write_chunk_size = (negotiated.negotiation.max_write_size as usize).clamp(65536, SMB_MAX_READ_CHUNK);
        info!(
            host = %params.host,
            share = %params.share,
            smb_version,
            dialect = ?negotiated.negotiation.dialect_rev,
            max_read_size = negotiated.negotiation.max_read_size,
            max_write_size = negotiated.negotiation.max_write_size,
            write_chunk_size,
            read_chunk_size,
            read_parallelism,
            stream_chunk_size,
            stream_parallelism,
            "SMB negotiated read/write window"
        );

        let state = Arc::new(SmbState {
            client,
            base_unc,
            root_path: params.root_path,
            read_chunk_size,
            read_parallelism,
            stream_chunk_size,
            stream_parallelism,
            write_chunk_size,
            read_handles: ReadHandleCache::new(),
        });
        *self.inner.lock().unwrap() = Some(state);
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        let state = { self.inner.lock().unwrap().take() };
        if let Some(state) = state {
            run_with_smb_timeout("close", smb_operation_timeout(), async {
                state.client.close().await.map_err(|e| smb_err("close", e))
            })
            .await?;
        }
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let connected = self.inner.lock().unwrap().is_some();
        StorageStatus {
            driver: "smb".into(),
            state: if connected {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            },
            error: None,
            capabilities: self.caps.clone(),
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        self.caps.clone()
    }
}

#[async_trait]
impl Reader for NativeSmbDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        Box::pin(self.with_retry(|state| Self::list_with_state(state, path))).await
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        Box::pin(self.with_retry(|state| Self::stat_with_state(state, path))).await
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        self.maybe_rotate_read_connection(limit.unwrap_or(0)).await?;
        self.with_retry(|state| Self::read_bytes_with_state(state, path, offset, limit))
            .await
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let state = match self.ensure_state().await {
            Ok(state) => state,
            Err(err) => {
                error!("stream_to ensure state: {}", err);
                return;
            }
        };
        let file = match open_file_resource(&state, path).await {
            Ok(file) => Arc::new(file),
            Err(err) => {
                error!("stream_to open file: {}", err);
                return;
            }
        };
        let end = match limit {
            Some(0) => return,
            Some(limit) => offset.saturating_add(limit),
            None => {
                let file_size = match file.query_info::<FileStandardInformation>().await {
                    Ok(info) => info.end_of_file,
                    Err(err) => {
                        error!("stream_to query size: {}", smb_err("stream query size", err));
                        return;
                    }
                };

                if offset >= file_size {
                    return;
                }

                file_size
            }
        };
        let chunk_size = state.stream_chunk_size;
        // Cap parallelism for all stream_to calls. High parallelism (32)
        // overwhelms SMB servers, causing read failures after ~85MB.
        let parallelism = state.stream_parallelism.min(SMB_OPEN_ENDED_STREAM_PARALLELISM_CAP);
        let mut positions = std::iter::successors(Some(offset), move |pos| {
            let next = *pos + chunk_size as u64;
            (next < end).then_some(next)
        })
        .enumerate();
        let mut reads = FuturesUnordered::new();
        let mut ready = BTreeMap::new();
        let mut next_idx = 0usize;
        let mut receiver_dropped = false;
        let mut stop_scheduling = false;
        let mut read_error = false;

        for _ in 0..parallelism {
            let Some((idx, pos)) = positions.next() else {
                break;
            };
            reads.push(spawn_read(Arc::clone(&file), idx, pos, end, chunk_size, "stream read"));
        }

        while let Some(chunk_res) = reads.next().await {
            match chunk_res {
                Ok((idx, chunk, expected)) => {
                    ready.insert(idx, (chunk, expected));

                    if !stop_scheduling && let Some((next_read_idx, next_pos)) = positions.next() {
                        reads.push(spawn_read(
                            Arc::clone(&file),
                            next_read_idx,
                            next_pos,
                            end,
                            chunk_size,
                            "stream read",
                        ));
                    }

                    while let Some((chunk, expected)) = ready.remove(&next_idx) {
                        next_idx += 1;
                        if chunk.is_empty() {
                            stop_scheduling = true;
                            continue;
                        }
                        let actual = chunk.len();
                        if !receiver_dropped {
                            let mut to_send = Some(chunk);
                            loop {
                                tokio::select! {
                                    biased;
                                    permit = tx.reserve() => {
                                        if let Ok(permit) = permit {
                                            permit.send(to_send.take().unwrap());
                                        } else {
                                            receiver_dropped = true;
                                            stop_scheduling = true;
                                        }
                                        break;
                                    }
                                    drain = reads.next(), if !reads.is_empty() => {
                                        match drain {
                                            Some(Ok((didx, dc, de))) => {
                                                ready.insert(didx, (dc, de));
                                                if !stop_scheduling && ready.len() <= parallelism
                                                    && let Some((nri, np)) = positions.next() {
                                                        reads.push(spawn_read(
                                                            Arc::clone(&file),
                                                            nri,
                                                            np,
                                                            end,
                                                            chunk_size,
                                                            "stream read",
                                                        ));
                                                    }
                                            }
                                            Some(Err(err)) => {
                                                if receiver_dropped {
                                                    warn!(
                                                        "stream_to drain after receiver drop failed: {}; closing idle SMB connection",
                                                        err
                                                    );
                                                } else {
                                                    error!("stream_to read: {}", err);
                                                }
                                                read_error = true;
                                                break;
                                            }
                                            None => {}
                                        }
                                    }
                                }
                            }
                            if read_error {
                                break;
                            }
                        }
                        if actual < expected {
                            stop_scheduling = true;
                        }
                    }
                    if read_error {
                        break;
                    }

                    // Refill the read pipeline if it was depleted during
                    // sustained backpressure. Without this, the outer
                    // `reads.next().await` would return None and the
                    // stream would terminate prematurely.
                    while reads.len() < parallelism && !stop_scheduling {
                        if let Some((nri, np)) = positions.next() {
                            reads.push(spawn_read(Arc::clone(&file), nri, np, end, chunk_size, "stream read"));
                        } else {
                            break;
                        }
                    }
                }
                Err(err) => {
                    if receiver_dropped {
                        warn!(
                            "stream_to drain after receiver drop failed: {}; closing idle SMB connection",
                            err
                        );
                    } else {
                        error!("stream_to read: {}", err);
                    }
                    read_error = true;
                    break;
                }
            }
        }
        // Drop in-flight reads first to release their Arc<File> references,
        // then close the file explicitly.
        drop(reads);
        if let Ok(f) = Arc::try_unwrap(file) {
            let _ = f.close().await;
        }
        // On genuine read errors (not receiver drops), remove the stale state
        // so the next operation reconnects. clear_state() does NOT close the
        // old client — it stays alive until all Arc references are released.
        if read_error && !receiver_dropped {
            self.clear_state().await;
        }
    }
}

#[async_trait]
impl Mkdir for NativeSmbDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        self.with_retry(|state| Self::mkdir_with_state(state, path)).await
    }
}

#[async_trait]
impl DeleteFile for NativeSmbDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        Box::pin(self.with_retry(|state| Self::delete_file_with_state(state, path))).await
    }
}

#[async_trait]
impl DeleteDir for NativeSmbDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        Box::pin(self.with_retry(|state| Self::delete_dir_with_state(state, path))).await
    }
}

#[async_trait]
impl Rename for NativeSmbDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        Box::pin(self.with_retry(|state| Self::rename_with_state(state, from, to))).await
    }
}

#[async_trait]
impl MoveFile for NativeSmbDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        Box::pin(self.with_retry(|state| Self::move_with_state(state, from, to_dir))).await
    }
}

#[async_trait]
impl PutFile for NativeSmbDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        Box::pin(self.with_retry(|state| Self::put_with_state(state, path, &data))).await
    }
}

#[async_trait]
impl PutStream for NativeSmbDriver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        ensure_non_root_path(path, "put_stream")?;
        let state = self.ensure_state().await?;
        let unc = build_unc(&state.base_unc, &state.root_path, &path.to_string_lossy());
        let resource = state
            .client
            .create_file(&unc, &overwrite_file_args())
            .await
            .map_err(|err| smb_err("put_stream open", err))?;
        let Resource::File(file) = resource else {
            return Err(TokimoVfsError::Other(format!(
                "smb put_stream: {} 返回了非文件资源",
                path.display()
            )));
        };

        let mut offset = 0u64;
        while let Some(chunk) = rx.recv().await {
            let mut pos = 0usize;
            while pos < chunk.len() {
                let end = (pos + state.write_chunk_size).min(chunk.len());
                let written = file
                    .write_block(&chunk[pos..end], offset, None)
                    .await
                    .map_err(|err| smb_err("put_stream write", smb::Error::IoError(err)))?;
                if written == 0 {
                    return Err(TokimoVfsError::Other(format!(
                        "smb put_stream: {} 写入返回 0 字节",
                        path.display()
                    )));
                }
                pos += written;
                offset += written as u64;
            }
        }

        file.close().await.map_err(|err| smb_err("put_stream close", err))
    }
}

impl Driver for NativeSmbDriver {
    fn as_mkdir(&self) -> Option<&dyn Mkdir> {
        Some(self)
    }

    fn as_delete_file(&self) -> Option<&dyn DeleteFile> {
        Some(self)
    }

    fn as_delete_dir(&self) -> Option<&dyn DeleteDir> {
        Some(self)
    }

    fn as_rename(&self) -> Option<&dyn Rename> {
        Some(self)
    }

    fn as_move(&self) -> Option<&dyn MoveFile> {
        Some(self)
    }

    fn as_put(&self) -> Option<&dyn PutFile> {
        Some(self)
    }

    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }
}

// ── Multi-share driver (share field left empty) ───────────────────────────────

/// Controls which shares the multi-share driver exposes.
enum ShareMode {
    /// Enumerate all visible shares via IPC$/srvsvc.
    EnumerateAll,
    /// Enumerate visible shares AND add extra manual entries (for hidden shares).
    /// Triggered by `*, hidden$, admin$` syntax.
    EnumeratePlusExtra(Vec<String>),
    /// Only expose these specific shares (no enumeration).
    /// Triggered by `public, media` syntax (no `*`).
    Explicit(Vec<String>),
}

/// When the user leaves the SMB share field empty, this driver presents every
/// share on the server as a top-level directory.  Sub-paths like
/// `/sharename/dir/file` are transparently routed to a per-share
/// `NativeSmbDriver` (lazily created and cached).
struct SmbMultiShareDriver {
    host: String,
    username: String,
    password: String,
    domain: String,
    mode: ShareMode,
    /// Cached per-share drivers, keyed by share name (lowercased).
    shares: tokio::sync::RwLock<std::collections::HashMap<String, Arc<NativeSmbDriver>>>,
}

impl SmbMultiShareDriver {
    fn new(host: String, username: String, password: String, domain: String, mode: ShareMode) -> Self {
        Self {
            host,
            username,
            password,
            domain,
            mode,
            shares: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Parse `/sharename/rest/of/path` → `("sharename", "rest/of/path")`.
    fn split_share_path(path: &Path) -> Result<(String, std::path::PathBuf)> {
        let s = path.to_string_lossy();
        let trimmed = s.trim_start_matches('/');
        if trimmed.is_empty() {
            return Err(TokimoVfsError::Other("smb multi-share: 请指定共享名称".into()));
        }
        let (share, rest) = match trimmed.find('/') {
            Some(pos) => (&trimmed[..pos], &trimmed[pos + 1..]),
            None => (trimmed, ""),
        };
        let rest_path = if rest.is_empty() {
            PathBuf::from("/")
        } else {
            PathBuf::from(format!("/{rest}"))
        };
        Ok((share.to_string(), rest_path))
    }

    async fn get_or_create_driver(&self, share: &str) -> Result<Arc<NativeSmbDriver>> {
        let key = share.to_ascii_lowercase();

        // Reject shares not in the allow-list (Explicit mode only;
        // EnumerateAll and EnumeratePlusExtra allow any share by name)
        if let ShareMode::Explicit(ref allowed) = self.mode
            && !allowed.iter().any(|a| a.eq_ignore_ascii_case(share))
        {
            return Err(TokimoVfsError::NotFound(format!(
                "共享 '{share}' 不在允许列表中"
            )));
        }

        // Fast path
        {
            let map = self.shares.read().await;
            if let Some(drv) = map.get(&key) {
                return Ok(Arc::clone(drv));
            }
        }

        // Slow path
        let mut map = self.shares.write().await;
        if let Some(drv) = map.get(&key) {
            return Ok(Arc::clone(drv));
        }

        let p = SmbParams {
            host: self.host.clone(),
            share: share.to_string(),
            username: self.username.clone(),
            password: self.password.clone(),
            domain: self.domain.clone(),
            root_path: "/".to_string(),
        };
        let caps = StorageCapabilities {
            list: true,
            read: true,
            mkdir: true,
            delete_file: true,
            delete_dir: true,
            rename: true,
            write: true,
            symlink: false,
            range_read: true,
        };
        let drv = Arc::new(NativeSmbDriver {
            params: p,
            caps,
            inner: Arc::new(Mutex::new(None)),
            read_usage: Arc::new(Mutex::new(SmbReadUsage::default())),
        });
        map.insert(key, Arc::clone(&drv));
        Ok(drv)
    }

    /// List available shares on the server via IPC$.
    ///
    /// Behavior depends on `ShareMode`:
    /// - `Explicit` — returns those shares directly as virtual directories
    ///   without querying the server (avoids IPC$/srvsvc).
    /// - `EnumerateAll` — queries IPC$/srvsvc to discover all visible shares.
    /// - `EnumeratePlusExtra` — enumerates visible shares, then merges in
    ///   extra entries (for hidden shares like `backup$`).
    async fn list_shares_as_dirs(&self) -> Result<Vec<FileInfo>> {
        let now = Utc::now();

        let make_entry = |name: String| FileInfo {
            path: format!("/{name}"),
            name,
            size: 0,
            is_dir: true,
            modified: Some(now),
        };

        match &self.mode {
            ShareMode::Explicit(names) => {
                Ok(names.iter().map(|n| make_entry(n.clone())).collect())
            }
            ShareMode::EnumerateAll => {
                self.enumerate_shares_via_ipc().await
            }
            ShareMode::EnumeratePlusExtra(extras) => {
                let mut shares = self.enumerate_shares_via_ipc().await?;
                let existing: std::collections::HashSet<String> = shares
                    .iter()
                    .map(|f| f.name.to_ascii_lowercase())
                    .collect();
                for extra in extras {
                    if !existing.contains(&extra.to_ascii_lowercase()) {
                        shares.push(make_entry(extra.clone()));
                    }
                }
                Ok(shares)
            }
        }
    }

    /// Raw IPC$/srvsvc enumeration (the original logic, extracted).
    async fn enumerate_shares_via_ipc(&self) -> Result<Vec<FileInfo>> {
        let client = build_client();

        let effective_domain = effective_domain(&self.domain);
        let user_name = if self.username.is_empty() {
            current_username().ok_or_else(|| {
                TokimoVfsError::InvalidConfig("smb 驱动缺少 'username'，且无法从环境变量推导当前用户".into())
            })?
        } else {
            self.username.clone()
        };
        let qualified_user = if user_name.contains('\\') || user_name.contains('@') || effective_domain.is_empty() {
            user_name.clone()
        } else {
            format!(r"{effective_domain}\{user_name}")
        };
        let password = if self.password.is_empty() {
            read_ntlm_password_from_file(effective_domain, &self.host).unwrap_or_default()
        } else {
            self.password.clone()
        };

        info!(
            host = %self.host,
            user = %qualified_user,
            "SMB multi-share: connecting to IPC$ for share enumeration"
        );

        run_with_smb_timeout("ipc_connect", SMB_CONNECTION_TIMEOUT, async {
            client
                .ipc_connect(&self.host, &qualified_user, password)
                .await
                .map_err(|e| smb_err("ipc_connect", e))
        })
        .await?;

        info!(host = %self.host, "SMB multi-share: IPC$ connected, opening srvsvc pipe");

        let mut pipe = run_with_smb_timeout("open_pipe srvsvc", smb_operation_timeout(), async {
            client
                .open_pipe(&self.host, "srvsvc")
                .await
                .map_err(|e| smb_err("open_pipe srvsvc", e))
        })
        .await?;

        info!(host = %self.host, "SMB multi-share: srvsvc pipe opened, binding NDR32");

        let share_names = ndr32_srvsvc::enumerate_shares(&mut pipe, &self.host).await?;

        let _ = client.close().await;

        let now = Utc::now();
        let entries = share_names
            .into_iter()
            .filter(|name| !name.ends_with('$'))
            .map(|name| FileInfo {
                path: format!("/{name}"),
                name,
                size: 0,
                is_dir: true,
                modified: Some(now),
            })
            .collect();

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Raw DCERPC / NDR32 implementation for SRVSVC NetrShareEnum (opnum 15).
//
// The high-level smb-rpc crate only supports NDR64 transfer syntax, which
// Samba servers commonly reject. This module implements just enough of the
// DCERPC bind + NetrShareEnum call using NDR32 (the universally supported
// transfer syntax) to enumerate shares.
// ---------------------------------------------------------------------------
mod ndr32_srvsvc {
    use smb::{IoctlBuffer, Pipe, PipeTransceiveRequest};

    use super::{TokimoVfsError, Result};

    // ---- Constants ----

    /// NDR32 transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860 v2
    const NDR32_UUID: [u8; 16] = [
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    ];
    const NDR32_VERSION: u32 = 2;

    /// SRVSVC abstract syntax UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3
    const SRVSVC_UUID: [u8; 16] = [
        0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    ];
    const SRVSVC_VERSION: u32 = 3;

    const DCERPC_VERSION: u8 = 5;
    const DCERPC_VERSION_MINOR: u8 = 0;
    const PTYPE_BIND: u8 = 11;
    const PTYPE_BIND_ACK: u8 = 12;
    const PTYPE_REQUEST: u8 = 0;
    const PTYPE_RESPONSE: u8 = 2;
    const PFC_FIRST_LAST: u8 = 0x03;
    const PACKED_DREP_LE: [u8; 4] = [0x10, 0x00, 0x00, 0x00];
    const MAX_FRAG: u16 = 4280;

    /// Build a DCE/RPC Bind PDU with a single NDR32 transfer-syntax context.
    fn build_bind_pdu() -> Vec<u8> {
        // Context element: 1 item
        //   context_id=0, num_transfer_syn=1
        //   abstract_syntax = SRVSVC
        //   transfer_syntax = NDR32
        let mut ctx = Vec::with_capacity(44);
        ctx.extend_from_slice(&0u16.to_le_bytes()); // context_id
        ctx.push(1); // num_transfer_syn
        ctx.push(0); // reserved
        ctx.extend_from_slice(&SRVSVC_UUID);
        ctx.extend_from_slice(&SRVSVC_VERSION.to_le_bytes());
        ctx.extend_from_slice(&NDR32_UUID);
        ctx.extend_from_slice(&NDR32_VERSION.to_le_bytes());

        let body_len = 12 + ctx.len(); // max_xmit_frag(2) + max_recv_frag(2) + assoc(4) + num_ctx(1) + reserved(3) + ctx
        let frag_len = 16 + body_len; // 16-byte header

        let mut pdu = Vec::with_capacity(frag_len);
        // -- Common header (16 bytes) --
        pdu.push(DCERPC_VERSION);
        pdu.push(DCERPC_VERSION_MINOR);
        pdu.push(PTYPE_BIND);
        pdu.push(PFC_FIRST_LAST);
        pdu.extend_from_slice(&PACKED_DREP_LE);
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&2u32.to_le_bytes()); // call_id
        // -- Bind body --
        pdu.extend_from_slice(&MAX_FRAG.to_le_bytes()); // max_xmit_frag
        pdu.extend_from_slice(&MAX_FRAG.to_le_bytes()); // max_recv_frag
        pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
        pdu.push(1); // num_ctx_items
        pdu.push(0); // reserved
        pdu.extend_from_slice(&0u16.to_le_bytes()); // reserved2
        pdu.extend_from_slice(&ctx);
        pdu
    }

    /// Verify `BindAck`: check ptype and first result is Acceptance (0).
    fn verify_bind_ack(data: &[u8]) -> Result<()> {
        if data.len() < 28 {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc BindAck too short: {} bytes",
                data.len()
            )));
        }
        let ptype = data[2];
        if ptype != PTYPE_BIND_ACK {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc expected BindAck (ptype={PTYPE_BIND_ACK}), got ptype={ptype}"
            )));
        }
        // Skip header (16) + max_xmit(2) + max_recv(2) + assoc(4) + sec_addr len(2)
        // then variable-length secondary address, then padding, then results.
        // Secondary address: u16 length + string + pad to 4 bytes
        let sec_len = u16::from_le_bytes([data[24], data[25]]) as usize;
        let sec_end = 26 + sec_len;
        // Pad to 4-byte boundary
        let padded = (sec_end + 3) & !3;
        // num_results at padded, result[0] at padded+4
        if data.len() < padded + 4 + 2 {
            return Err(TokimoVfsError::Other("SMB srvsvc BindAck response truncated".into()));
        }
        let result_code = u16::from_le_bytes([data[padded + 4], data[padded + 5]]);
        if result_code != 0 {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc NDR32 bind rejected: result_code={result_code}"
            )));
        }
        Ok(())
    }

    /// Build a DCE/RPC Request PDU for `NetrShareEnum` (opnum 15) with NDR32 stub.
    fn build_share_enum_request(server_name: &str) -> Vec<u8> {
        let mut stub = Vec::with_capacity(128);

        // -- ServerName: [in, string, unique] wchar_t* --
        // Referent ID (non-null)
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        let server_utf16: Vec<u16> = server_name.encode_utf16().chain(std::iter::once(0)).collect();
        let max_count = server_utf16.len() as u32;
        stub.extend_from_slice(&max_count.to_le_bytes()); // MaxCount
        stub.extend_from_slice(&0u32.to_le_bytes()); // Offset
        stub.extend_from_slice(&max_count.to_le_bytes()); // ActualCount
        for ch in &server_utf16 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        // Pad to 4-byte boundary
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // -- InfoStruct (SHARE_ENUM_STRUCT) --
        // Level: u32 = 1
        stub.extend_from_slice(&1u32.to_le_bytes());
        // Union discriminant: u32 = 1 (Info1)
        stub.extend_from_slice(&1u32.to_le_bytes());
        // Unique pointer to SHARE_INFO_1_CONTAINER: referent ID
        stub.extend_from_slice(&0x0002_0004u32.to_le_bytes());
        // Deferred: SHARE_INFO_1_CONTAINER
        // EntriesRead: u32 = 0
        stub.extend_from_slice(&0u32.to_le_bytes());
        // Buffer pointer: NULL (u32 = 0)
        stub.extend_from_slice(&0u32.to_le_bytes());

        // -- PreferedMaximumLength: u32 = MAX --
        stub.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        // -- ResumeHandle: [unique] DWORD* --
        // Referent ID (non-null)
        stub.extend_from_slice(&0x0002_0008u32.to_le_bytes());
        // Value: u32 = 0
        stub.extend_from_slice(&0u32.to_le_bytes());

        // Now wrap in DCE/RPC Request PDU
        let alloc_hint = stub.len() as u32;
        let frag_len = (16 + 8 + stub.len()) as u16; // header(16) + req_specific(8) + stub

        let mut pdu = Vec::with_capacity(frag_len as usize);
        // Common header
        pdu.push(DCERPC_VERSION);
        pdu.push(DCERPC_VERSION_MINOR);
        pdu.push(PTYPE_REQUEST);
        pdu.push(PFC_FIRST_LAST);
        pdu.extend_from_slice(&PACKED_DREP_LE);
        pdu.extend_from_slice(&frag_len.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&3u32.to_le_bytes()); // call_id
        // Request-specific
        pdu.extend_from_slice(&alloc_hint.to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id = 0
        pdu.extend_from_slice(&15u16.to_le_bytes()); // opnum = 15 (NetrShareEnum)
        pdu.extend_from_slice(&stub);
        pdu
    }

    /// Parse the response stub data (NDR32) to extract share names.
    ///
    /// Response format (NDR32):
    ///   `InfoStruct`:
    ///     Level: u32
    ///     Union discriminant: u32
    ///     Container pointer: u32 (referent)
    ///     --- deferred ---
    ///     `EntriesRead`: u32
    ///     Buffer pointer: u32 (referent)
    ///     --- deferred buffer ---
    ///     `MaxCount`: u32 (conformant array)
    ///     For each entry (fixed part):
    ///       `netname_ptr`: u32 (referent)
    ///       `share_type`: u32
    ///       `remark_ptr`: u32 (referent)
    ///     For each entry (deferred strings):
    ///       `MaxCount`: u32, Offset: u32, `ActualCount`: u32, UTF-16LE data, padding
    ///   `TotalEntries`: u32
    ///   `ResumeHandle` ptr: u32
    ///   `ResumeHandle` value: u32
    ///   `WindowsError`: u32
    fn parse_share_enum_response(data: &[u8]) -> Result<Vec<String>> {
        // Validate response PDU header
        if data.len() < 24 {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc response too short: {} bytes",
                data.len()
            )));
        }
        let ptype = data[2];
        if ptype != PTYPE_RESPONSE {
            // Check for fault
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc expected Response (ptype={PTYPE_RESPONSE}), got ptype={ptype}"
            )));
        }
        // Stub data starts at offset 24 (16 header + 8 response fields)
        let stub = &data[24..];
        parse_stub_ndr32(stub)
    }

    fn read_u32(buf: &[u8], off: &mut usize) -> Result<u32> {
        // Align to 4
        *off = (*off + 3) & !3;
        if *off + 4 > buf.len() {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc NDR32 read_u32 out of bounds at offset {off}"
            )));
        }
        let v = u32::from_le_bytes([buf[*off], buf[*off + 1], buf[*off + 2], buf[*off + 3]]);
        *off += 4;
        Ok(v)
    }

    fn read_ndr32_string(buf: &[u8], off: &mut usize) -> Result<String> {
        let _max_count = read_u32(buf, off)?;
        let _offset = read_u32(buf, off)?;
        let actual_count = read_u32(buf, off)? as usize;
        if *off + actual_count * 2 > buf.len() {
            return Err(TokimoVfsError::Other(format!(
                "SMB srvsvc NDR32 string data out of bounds at offset {} (need {} bytes)",
                off,
                actual_count * 2
            )));
        }
        let mut chars = Vec::with_capacity(actual_count);
        for i in 0..actual_count {
            let ch = u16::from_le_bytes([buf[*off + i * 2], buf[*off + i * 2 + 1]]);
            chars.push(ch);
        }
        *off += actual_count * 2;
        // Pad to 4-byte boundary
        *off = (*off + 3) & !3;
        // Strip null terminator
        if chars.last() == Some(&0) {
            chars.pop();
        }
        Ok(String::from_utf16_lossy(&chars))
    }

    fn parse_stub_ndr32(stub: &[u8]) -> Result<Vec<String>> {
        let mut off = 0;

        // InfoStruct
        let _level = read_u32(stub, &mut off)?; // Level (should be 1)
        let _discriminant = read_u32(stub, &mut off)?; // Union discriminant
        let container_ptr = read_u32(stub, &mut off)?; // Container pointer

        if container_ptr == 0 {
            return Ok(vec![]);
        }

        // Deferred container data
        let entries_read = read_u32(stub, &mut off)? as usize;
        let buffer_ptr = read_u32(stub, &mut off)?;

        if buffer_ptr == 0 || entries_read == 0 {
            return Ok(vec![]);
        }

        // Deferred buffer: conformant array
        let max_count = read_u32(stub, &mut off)? as usize;
        let count = max_count.min(entries_read);

        // Fixed parts of each SHARE_INFO_1 entry
        struct EntryFixed {
            has_netname: bool,
            has_remark: bool,
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let netname_ptr = read_u32(stub, &mut off)?;
            let _share_type = read_u32(stub, &mut off)?;
            let remark_ptr = read_u32(stub, &mut off)?;
            entries.push(EntryFixed {
                has_netname: netname_ptr != 0,
                has_remark: remark_ptr != 0,
            });
        }

        // Deferred referents are interleaved per element in NDR32:
        // netname0, remark0, netname1, remark1, ...
        let mut names = Vec::with_capacity(count);
        for entry in &entries {
            if entry.has_netname {
                let name = read_ndr32_string(stub, &mut off)?;
                names.push(name);
            } else {
                names.push(String::new());
            }
            if entry.has_remark {
                let _ = read_ndr32_string(stub, &mut off)?;
            }
        }

        Ok(names)
    }

    /// Perform the full NDR32 DCERPC sequence to enumerate shares.
    pub(super) async fn enumerate_shares(pipe: &mut Pipe, host: &str) -> Result<Vec<String>> {
        const MAX_RESPONSE: u32 = 65536;

        // Step 1: Bind with NDR32
        let bind_pdu = build_bind_pdu();
        let bind_ack_raw = pipe
            .fsctl_with_options(PipeTransceiveRequest::from(IoctlBuffer::from(bind_pdu)), MAX_RESPONSE)
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("SMB srvsvc NDR32 bind FSCTL failed: {e}")))?;
        verify_bind_ack(&bind_ack_raw)?;

        // Step 2: NetrShareEnum request
        let req_pdu = build_share_enum_request(host);
        let resp_raw = pipe
            .fsctl_with_options(PipeTransceiveRequest::from(IoctlBuffer::from(req_pdu)), MAX_RESPONSE)
            .await
            .map_err(|e| TokimoVfsError::Other(format!("SMB srvsvc NetrShareEnum FSCTL failed: {e}")))?;
        parse_share_enum_response(&resp_raw)
    }
}

#[async_trait]
impl Meta for SmbMultiShareDriver {
    fn driver_name(&self) -> &'static str {
        "smb"
    }

    async fn init(&self) -> Result<()> {
        match &self.mode {
            ShareMode::Explicit(names) => {
                info!(
                    host = %self.host,
                    shares = ?names,
                    "SMB multi-share: configured with {} explicit share(s)",
                    names.len()
                );
                return Ok(());
            }
            ShareMode::EnumeratePlusExtra(extras) => {
                info!(
                    host = %self.host,
                    extras = ?extras,
                    "SMB multi-share: will enumerate all shares + {} extra",
                    extras.len()
                );
            }
            ShareMode::EnumerateAll => {}
        }

        // Try to list shares to validate connectivity.
        // If enumeration fails (some servers restrict IPC$/srvsvc),
        // just warn — the user can still access shares by path.
        match self.list_shares_as_dirs().await {
            Ok(shares) => {
                info!(
                    host = %self.host,
                    count = shares.len(),
                    "SMB multi-share: enumerated {} shares",
                    shares.len()
                );
            }
            Err(e) => {
                warn!(
                    host = %self.host,
                    error = %e,
                    "SMB multi-share: failed to enumerate shares (server may restrict IPC$/srvsvc). \
                     Users can still access shares by navigating to /sharename/"
                );
            }
        }
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        let drivers: Vec<_> = {
            let mut map = self.shares.write().await;
            map.drain().map(|(_, d)| d).collect()
        };
        for drv in drivers {
            let _ = drv.drop_driver().await;
        }
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        StorageStatus {
            driver: "smb".into(),
            state: ConnectionState::Connected,
            error: None,
            capabilities: self.capabilities(),
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        StorageCapabilities {
            list: true,
            read: true,
            mkdir: true,
            delete_file: true,
            delete_dir: true,
            rename: true,
            write: true,
            symlink: false,
            range_read: true,
        }
    }
}

#[async_trait]
impl Reader for SmbMultiShareDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        if path == Path::new("/") || path == Path::new("") {
            return self.list_shares_as_dirs().await;
        }
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share).await?.list(&sub).await
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        if path == Path::new("/") || path == Path::new("") {
            return Ok(FileInfo {
                path: "/".into(),
                name: String::new(),
                size: 0,
                is_dir: true,
                modified: None,
            });
        }
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share).await?.stat(&sub).await
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .read_bytes(&sub, offset, limit)
            .await
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let (share, sub) = match Self::split_share_path(path) {
            Ok(v) => v,
            Err(e) => {
                error!("multi-share stream_to path error: {}", e);
                return;
            }
        };
        match self.get_or_create_driver(&share).await {
            Ok(drv) => drv.stream_to(&sub, offset, limit, tx).await,
            Err(e) => error!("multi-share stream_to driver error: {}", e),
        }
    }
}

#[async_trait]
impl Mkdir for SmbMultiShareDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .as_mkdir()
            .ok_or_else(|| TokimoVfsError::Other("mkdir not supported".into()))?
            .mkdir(&sub)
            .await
    }
}

#[async_trait]
impl DeleteFile for SmbMultiShareDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .as_delete_file()
            .ok_or_else(|| TokimoVfsError::Other("delete_file not supported".into()))?
            .delete_file(&sub)
            .await
    }
}

#[async_trait]
impl DeleteDir for SmbMultiShareDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .as_delete_dir()
            .ok_or_else(|| TokimoVfsError::Other("delete_dir not supported".into()))?
            .delete_dir(&sub)
            .await
    }
}

#[async_trait]
impl Rename for SmbMultiShareDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let (share_from, sub_from) = Self::split_share_path(from)?;
        let (share_to, sub_to) = Self::split_share_path(to)?;
        if !share_from.eq_ignore_ascii_case(&share_to) {
            return Err(TokimoVfsError::Other("smb: 不支持跨共享重命名".into()));
        }
        self.get_or_create_driver(&share_from)
            .await?
            .as_rename()
            .ok_or_else(|| TokimoVfsError::Other("rename not supported".into()))?
            .rename(&sub_from, &sub_to)
            .await
    }
}

#[async_trait]
impl MoveFile for SmbMultiShareDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let (share_from, sub_from) = Self::split_share_path(from)?;
        let (share_to, sub_to) = Self::split_share_path(to_dir)?;
        if !share_from.eq_ignore_ascii_case(&share_to) {
            return Err(TokimoVfsError::Other("smb: 不支持跨共享移动文件".into()));
        }
        self.get_or_create_driver(&share_from)
            .await?
            .as_move()
            .ok_or_else(|| TokimoVfsError::Other("move not supported".into()))?
            .move_file(&sub_from, &sub_to)
            .await
    }
}

#[async_trait]
impl PutFile for SmbMultiShareDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .as_put()
            .ok_or_else(|| TokimoVfsError::Other("put not supported".into()))?
            .put(&sub, data)
            .await
    }
}

#[async_trait]
impl PutStream for SmbMultiShareDriver {
    async fn put_stream(&self, path: &Path, size: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let (share, sub) = Self::split_share_path(path)?;
        self.get_or_create_driver(&share)
            .await?
            .as_put_stream()
            .ok_or_else(|| TokimoVfsError::Other("put_stream not supported".into()))?
            .put_stream(&sub, size, rx)
            .await
    }
}

impl Driver for SmbMultiShareDriver {
    fn as_mkdir(&self) -> Option<&dyn Mkdir> {
        Some(self)
    }
    fn as_delete_file(&self) -> Option<&dyn DeleteFile> {
        Some(self)
    }
    fn as_delete_dir(&self) -> Option<&dyn DeleteDir> {
        Some(self)
    }
    fn as_rename(&self) -> Option<&dyn Rename> {
        Some(self)
    }
    fn as_move(&self) -> Option<&dyn MoveFile> {
        Some(self)
    }
    fn as_put(&self) -> Option<&dyn PutFile> {
        Some(self)
    }
    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }
}

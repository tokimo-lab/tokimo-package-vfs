//! SFTP 驱动 — 基于 russh + russh-sftp（纯 Rust async，无 C 绑定）。
//!
//! JSON 配置字段：
//!   host        — SFTP 服务器地址，如 "192.168.1.10"
//!   port        — SSH 端口（可选，默认 22）
//!   username    — 用户名
//!   password    — 密码（与 `private_key` 二选一）
//!   `private_key` — 本地私钥路径或私钥文本（可选，如 "/`home/user/.ssh/id_rsa`"）
//!   passphrase  — 私钥密码（可选）
//!   root        — 远端根目录，如 "/srv/media"（可选，默认 "/"）

use std::env;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use russh::client::{self, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::StatusCode;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc::Sender};
use tracing::{error, warn};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename,
};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

pub const CONFIG: DriverConfig = DriverConfig {
    name: "sftp",
    description: "SFTP（纯 Rust async，基于 russh）",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

// ---- SSH 客户端处理器 -----------------------------------------------------

struct SftpClientHandler;

#[async_trait::async_trait]
impl client::Handler for SftpClientHandler {
    type Error = russh::Error;

    #[allow(clippy::manual_async_fn)]
    fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

// ---- 参数 ----------------------------------------------------------------

#[derive(Clone)]
struct SftpParams {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    private_key: Option<String>,
    passphrase: Option<String>,
    root: String,
}

// ---- 内部状态 -------------------------------------------------------------

struct Inner {
    #[allow(dead_code)]
    handle: Handle<SftpClientHandler>,
    /// Arc 包装使并发调用者可以在不持锁的情况下共享同一 `SftpSession`。
    /// `SftpSession` 内部通过 Arc<RawSftpSession> 实现协议复用，天然支持并发。
    sftp: Arc<SftpSession>,
}

// ---- 驱动结构 -------------------------------------------------------------

pub struct NativeSftpDriver {
    params: SftpParams,
    caps: StorageCapabilities,
    inner: Arc<Mutex<Option<Inner>>>,
}

// ---- 工厂 ----------------------------------------------------------------

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let host = require_str(params, "host")?.to_string();
    let port = params["port"].as_u64().unwrap_or(22) as u16;
    let username = require_str(params, "username")?.to_string();
    let password = params["password"].as_str().map(str::to_string);
    let private_key = params["privateKey"].as_str().map(str::to_string);
    let passphrase = params["passphrase"].as_str().map(str::to_string);
    let root = params["root_folder_path"].as_str().unwrap_or("/").to_string();

    let p = SftpParams {
        host,
        port,
        username,
        password,
        private_key,
        passphrase,
        root,
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
    Ok(Box::new(NativeSftpDriver {
        params: p,
        caps,
        inner: Arc::new(Mutex::new(None)),
    }))
}

// ---- 辅助函数 -------------------------------------------------------------

fn require_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("sftp 驱动缺少 '{key}' 字段")))
}

/// Map SSH-level errors (`russh::Error`) to `TokimoVfsError`.
fn ssh_err(context: &str, err: russh::Error) -> TokimoVfsError {
    match &err {
        russh::Error::Disconnect
        | russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::HUP
        | russh::Error::SendError
        | russh::Error::RecvError
        | russh::Error::IO(_) => TokimoVfsError::ConnectionError(format!("sftp {context}: {err}")),
        _ => TokimoVfsError::Other(format!("sftp {context}: {err}")),
    }
}

/// Map SFTP operation errors (`russh_sftp::client::error::Error`) to `TokimoVfsError`.
fn sftp_op_err(context: &str, err: russh_sftp::client::error::Error) -> TokimoVfsError {
    match &err {
        russh_sftp::client::error::Error::Status(status) => match status.status_code {
            StatusCode::NoSuchFile => TokimoVfsError::NotFound(format!("sftp {context}: {err}")),
            StatusCode::NoConnection | StatusCode::ConnectionLost => {
                TokimoVfsError::ConnectionError(format!("sftp {context}: {err}"))
            }
            _ => TokimoVfsError::Other(format!("sftp {context}: {err}")),
        },
        russh_sftp::client::error::Error::Timeout | russh_sftp::client::error::Error::IO(_) => {
            TokimoVfsError::ConnectionError(format!("sftp {context}: {err}"))
        }
        _ => TokimoVfsError::Other(format!("sftp {context}: {err}")),
    }
}

/// Only connection-level errors warrant a reconnect + retry.
fn should_retry_sftp(err: &TokimoVfsError) -> bool {
    matches!(err, TokimoVfsError::ConnectionError(_))
}

fn looks_like_private_key(value: &str) -> bool {
    value.contains("-----BEGIN ") || value.contains('\n')
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(path)
}

fn default_key_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = env::var_os("HOME") {
        let ssh_dir = PathBuf::from(home).join(".ssh");
        for name in ["id_ed25519", "id_rsa", "id_ecdsa"] {
            paths.push(ssh_dir.join(name));
        }
    }
    paths
}

fn load_private_key(p: &SftpParams) -> Result<PrivateKey> {
    let passphrase = p.passphrase.as_deref();

    if let Some(value) = p.private_key.as_deref() {
        if looks_like_private_key(value) {
            return russh::keys::decode_secret_key(value, passphrase)
                .map_err(|e| TokimoVfsError::ConnectionError(format!("解析内联私钥失败: {e}")));
        }

        let path = expand_home(value);
        if path.exists() {
            return russh::keys::load_secret_key(&path, passphrase)
                .map_err(|e| TokimoVfsError::ConnectionError(format!("加载私钥失败 ({}): {e}", path.display())));
        }

        warn!("configured sftp private key not found: {}", path.display());
    }

    for path in default_key_paths() {
        if path.exists() {
            warn!("falling back to default sftp private key: {}", path.display());
            return russh::keys::load_secret_key(&path, passphrase)
                .map_err(|e| TokimoVfsError::ConnectionError(format!("加载默认私钥失败 ({}): {e}", path.display())));
        }
    }

    Err(TokimoVfsError::ConnectionError(
        "加载私钥失败: 配置路径不存在，且未找到可用的默认私钥".into(),
    ))
}

/// 建立 SSH 连接并打开 SFTP 子系统。
async fn connect(p: &SftpParams) -> Result<Inner> {
    let config = Arc::new(client::Config::default());
    let addr = (p.host.as_str(), p.port);

    let mut handle = client::connect(config, addr, SftpClientHandler)
        .await
        .map_err(|e| ssh_err("connect", e))?;

    // 认证：优先私钥，其次密码
    let authenticated = if p.private_key.is_some() {
        let key = load_private_key(p)?;
        handle
            .authenticate_publickey(
                &p.username,
                PrivateKeyWithHashAlg::new(
                    Arc::new(key),
                    handle
                        .best_supported_rsa_hash()
                        .await
                        .map_err(|e| ssh_err("rsa hash", e))?
                        .flatten(),
                ),
            )
            .await
            .map_err(|e| ssh_err("auth publickey", e))?
    } else if let Some(ref pw) = p.password {
        handle
            .authenticate_password(&p.username, pw)
            .await
            .map_err(|e| ssh_err("auth password", e))?
    } else {
        return Err(TokimoVfsError::ConnectionError(
            "sftp 驱动需要 'password' 或 'private_key' 之一".into(),
        ));
    };

    if !authenticated.success() {
        return Err(TokimoVfsError::ConnectionError("SSH 认证失败".into()));
    }

    // 开启 SFTP 子系统
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| ssh_err("channel open", e))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| ssh_err("request subsystem", e))?;
    let sftp = Arc::new(
        SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| sftp_op_err("session init", e))?,
    );

    Ok(Inner { handle, sftp })
}

fn metadata_to_fileinfo(name: &str, path_str: &str, meta: &russh_sftp::client::fs::Metadata) -> FileInfo {
    let is_dir = meta.file_type().is_dir();
    let size = meta.len();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| DateTime::<Utc>::from(std::time::UNIX_EPOCH + d));
    FileInfo {
        name: name.to_string(),
        path: path_str.to_string(),
        size,
        is_dir,
        modified,
    }
}

// ---- 驱动实现 -------------------------------------------------------------

impl NativeSftpDriver {
    fn full_path(&self, rel: &Path) -> String {
        format!(
            "{}/{}",
            self.params.root.trim_end_matches('/'),
            rel.to_string_lossy().trim_start_matches('/')
        )
    }

    async fn ensure_connected(&self) -> Result<()> {
        let mut g = self.inner.lock().await;
        if g.is_none() {
            *g = Some(connect(&self.params).await?);
        }
        Ok(())
    }

    async fn clear_connection(&self) {
        *self.inner.lock().await = None;
    }

    async fn reconnect_session(&self) -> Result<Arc<SftpSession>> {
        self.clear_connection().await;
        self.ensure_connected().await?;
        self.sftp_arc().await
    }

    async fn with_retry<T, Op, Fut>(&self, op: Op) -> Result<T>
    where
        Op: Fn(Arc<SftpSession>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let sftp = self.sftp_arc().await?;
        match op(sftp).await {
            Ok(value) => Ok(value),
            Err(err) if should_retry_sftp(&err) => {
                warn!("SFTP operation failed, reconnecting and retrying once: {}", err);
                let sftp = self.reconnect_session().await?;
                op(sftp).await
            }
            Err(err) => Err(err),
        }
    }

    /// 短暂加锁，取出 Arc<SftpSession>，随即释放锁。
    /// 调用者持有 Arc 期间完全不持锁，多个请求可并发进行。
    async fn sftp_arc(&self) -> Result<Arc<SftpSession>> {
        self.ensure_connected().await?;
        let g = self.inner.lock().await;
        g.as_ref()
            .map(|inner| Arc::clone(&inner.sftp))
            .ok_or_else(|| TokimoVfsError::ConnectionError("未连接".into()))
    }

    async fn list_with_session(sftp: Arc<SftpSession>, full: String) -> Result<Vec<FileInfo>> {
        let entries = sftp.read_dir(&full).await.map_err(|e| sftp_op_err("list", e))?;
        Ok(entries
            .map(|entry| {
                let name = entry.file_name();
                let child = format!("{}/{}", full.trim_end_matches('/'), name);
                let meta = entry.metadata();
                metadata_to_fileinfo(&name, &child, &meta)
            })
            .collect())
    }

    async fn stat_with_session(sftp: Arc<SftpSession>, full: String) -> Result<FileInfo> {
        let meta = sftp.metadata(&full).await.map_err(|e| sftp_op_err("stat", e))?;
        let name = Path::new(&full)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(metadata_to_fileinfo(&name, &full, &meta))
    }

    async fn read_bytes_with_session(
        sftp: Arc<SftpSession>,
        full: String,
        offset: u64,
        limit: Option<u64>,
    ) -> Result<Vec<u8>> {
        let mut file = sftp.open(&full).await.map_err(|e| sftp_op_err("open", e))?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| TokimoVfsError::Other(format!("seek: {e}")))?;
        }
        let mut buf = Vec::new();
        match limit {
            Some(n) => {
                file.take(n)
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| TokimoVfsError::Other(e.to_string()))?;
            }
            None => {
                file.read_to_end(&mut buf)
                    .await
                    .map_err(|e| TokimoVfsError::Other(e.to_string()))?;
            }
        }
        Ok(buf)
    }

    async fn mkdir_with_session(sftp: Arc<SftpSession>, full: String) -> Result<()> {
        sftp.create_dir(&full).await.map_err(|e| sftp_op_err("mkdir", e))
    }

    async fn delete_file_with_session(sftp: Arc<SftpSession>, full: String) -> Result<()> {
        sftp.remove_file(&full).await.map_err(|e| sftp_op_err("remove file", e))
    }

    async fn delete_dir_with_session(sftp: Arc<SftpSession>, full: String) -> Result<()> {
        sftp.remove_dir(&full).await.map_err(|e| sftp_op_err("remove dir", e))
    }

    async fn rename_with_session(sftp: Arc<SftpSession>, from_full: String, to_full: String) -> Result<()> {
        sftp.rename(&from_full, &to_full)
            .await
            .map_err(|e| sftp_op_err("rename", e))
    }

    async fn move_with_session(
        sftp: Arc<SftpSession>,
        from_full: String,
        to_dir_full: String,
        from_name: &Path,
    ) -> Result<()> {
        let destination = Path::new(&to_dir_full).join(from_name);
        let destination = destination.to_string_lossy().into_owned();
        sftp.rename(&from_full, destination)
            .await
            .map_err(|e| sftp_op_err("move rename", e))
    }

    async fn put_with_session(sftp: Arc<SftpSession>, full: String, data: Vec<u8>) -> Result<()> {
        let mut file = sftp.create(&full).await.map_err(|e| sftp_op_err("create", e))?;
        file.write_all(&data)
            .await
            .map_err(|e| TokimoVfsError::Other(format!("sftp write: {e}")))?;
        file.flush()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("sftp flush: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl Meta for NativeSftpDriver {
    fn driver_name(&self) -> &'static str {
        "sftp"
    }

    async fn init(&self) -> Result<()> {
        self.ensure_connected().await
    }

    async fn drop_driver(&self) -> Result<()> {
        *self.inner.lock().await = None;
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let connected = self.inner.lock().await.is_some();
        StorageStatus {
            driver: "sftp".into(),
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
impl Reader for NativeSftpDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::list_with_session(sftp, full.clone()))
            .await
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::stat_with_session(sftp, full.clone()))
            .await
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::read_bytes_with_session(sftp, full.clone(), offset, limit))
            .await
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let full = self.full_path(path);
        let Ok(sftp) = self.sftp_arc().await else {
            error!("stream_to: 未连接");
            return;
        };
        let mut file = match sftp.open(&full).await {
            Ok(f) => f,
            Err(e) => {
                error!("stream_to open: {e}");
                return;
            }
        };
        if offset > 0
            && let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await
        {
            error!("stream_to seek: {e}");
            return;
        }

        const CHUNK: usize = 256 * 1024;
        let mut sent = 0u64;
        loop {
            let to_read = match limit {
                Some(lim) if sent >= lim => break,
                Some(lim) => ((lim - sent) as usize).min(CHUNK),
                None => CHUNK,
            };
            let mut chunk = vec![0u8; to_read];
            match file.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    sent += n as u64;
                    chunk.truncate(n);
                    if tx.send(chunk).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("stream_to read: {e}");
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl Mkdir for NativeSftpDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::mkdir_with_session(sftp, full.clone()))
            .await
    }
}

#[async_trait]
impl DeleteFile for NativeSftpDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::delete_file_with_session(sftp, full.clone()))
            .await
    }
}

#[async_trait]
impl DeleteDir for NativeSftpDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::delete_dir_with_session(sftp, full.clone()))
            .await
    }
}

#[async_trait]
impl Rename for NativeSftpDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let from_full = self.full_path(from);
        let to_full = self.full_path(to);
        self.with_retry(|sftp| Self::rename_with_session(sftp, from_full.clone(), to_full.clone()))
            .await
    }
}

#[async_trait]
impl MoveFile for NativeSftpDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let from_full = self.full_path(from);
        let to_dir_full = self.full_path(to_dir);
        let from_name = from
            .file_name()
            .ok_or_else(|| TokimoVfsError::Other(format!("sftp move: 无法确定源文件名: {}", from.display())))?;
        self.with_retry(|sftp| {
            Self::move_with_session(sftp, from_full.clone(), to_dir_full.clone(), Path::new(from_name))
        })
        .await
    }
}

#[async_trait]
impl PutFile for NativeSftpDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let full = self.full_path(path);
        self.with_retry(|sftp| Self::put_with_session(sftp, full.clone(), data.clone()))
            .await
    }
}

#[async_trait]
impl PutStream for NativeSftpDriver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let full = self.full_path(path);
        let sftp = self.sftp_arc().await?;
        let mut file = sftp.create(&full).await.map_err(|e| sftp_op_err("create", e))?;
        while let Some(chunk) = rx.recv().await {
            file.write_all(&chunk)
                .await
                .map_err(|e| TokimoVfsError::Other(format!("sftp write: {e}")))?;
        }
        file.flush()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("sftp flush: {e}")))?;
        Ok(())
    }
}

impl Driver for NativeSftpDriver {
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

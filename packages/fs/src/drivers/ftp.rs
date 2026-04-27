//! FTP 驱动 — 基于 suppaftp（async，纯 Rust）。
//!
//! JSON 配置字段：
//!   host              — FTP 服务器地址，如 "192.168.1.10"
//!   port              — 端口（可选，默认 21）
//!   username          — 用户名
//!   password          — 密码
//!   `root_folder_path`  — 远端根目录（可选，默认 "/"）
//!   encoding          — 字符编码（可选，默认 UTF-8；部分旧服务器使用 GBK）
//!   `use_ftps`          — 是否使用 FTPS 加密连接（可选，默认 false）

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use suppaftp::tokio::{AsyncFtpStream, AsyncNativeTlsFtpStream};
use suppaftp::types::FileType;
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc::Sender};
use tracing::error;

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename,
};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

pub const CONFIG: DriverConfig = DriverConfig {
    name: "ftp",
    description: "FTP/FTPS（基于 suppaftp）",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

// ---- 参数 ----------------------------------------------------------------

#[derive(Clone)]
struct FtpParams {
    address: String,
    username: String,
    password: String,
    root: String,
    use_ftps: bool,
}

// ---- 驱动结构 -------------------------------------------------------------

/// An enum to unify plain FTP and FTPS connections.
enum FtpConn {
    Plain(AsyncFtpStream),
    Tls(AsyncNativeTlsFtpStream),
}

impl FtpConn {
    async fn cwd(&mut self, path: &str) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.cwd(path).await,
            FtpConn::Tls(c) => c.cwd(path).await,
        }
    }

    async fn list(&mut self, path: Option<&str>) -> std::result::Result<Vec<String>, suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.list(path).await,
            FtpConn::Tls(c) => c.list(path).await,
        }
    }

    async fn retr_as_bytes(&mut self, path: &str) -> std::result::Result<Vec<u8>, suppaftp::FtpError> {
        let mut buf = Vec::new();
        match self {
            FtpConn::Plain(c) => {
                let mut stream = c.retr_as_stream(path).await?;
                stream
                    .read_to_end(&mut buf)
                    .await
                    .map_err(suppaftp::FtpError::ConnectionError)?;
                c.finalize_retr_stream(stream).await?;
            }
            FtpConn::Tls(c) => {
                let mut stream = c.retr_as_stream(path).await?;
                stream
                    .read_to_end(&mut buf)
                    .await
                    .map_err(suppaftp::FtpError::ConnectionError)?;
                c.finalize_retr_stream(stream).await?;
            }
        }
        Ok(buf)
    }

    async fn mkdir(&mut self, path: &str) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.mkdir(path).await,
            FtpConn::Tls(c) => c.mkdir(path).await,
        }
    }

    async fn rm(&mut self, path: &str) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.rm(path).await,
            FtpConn::Tls(c) => c.rm(path).await,
        }
    }

    async fn rmdir(&mut self, path: &str) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.rmdir(path).await,
            FtpConn::Tls(c) => c.rmdir(path).await,
        }
    }

    async fn rename(&mut self, from: &str, to: &str) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.rename(from, to).await,
            FtpConn::Tls(c) => c.rename(from, to).await,
        }
    }

    async fn put_file(&mut self, path: &str, data: &mut &[u8]) -> std::result::Result<u64, suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.put_file(path, data).await,
            FtpConn::Tls(c) => c.put_file(path, data).await,
        }
    }

    async fn quit(&mut self) -> std::result::Result<(), suppaftp::FtpError> {
        match self {
            FtpConn::Plain(c) => c.quit().await,
            FtpConn::Tls(c) => c.quit().await,
        }
    }
}

pub struct FtpDriver {
    params: FtpParams,
    caps: StorageCapabilities,
    conn: Arc<Mutex<Option<FtpConn>>>,
}

// ---- 工厂 ----------------------------------------------------------------

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let host = require_str(params, "host")?.to_string();
    let port = params["port"].as_u64().unwrap_or(21) as u16;
    let address = format!("{host}:{port}");
    let username = require_str(params, "username")?.to_string();
    let password = require_str(params, "password")?.to_string();
    let root = params["root_folder_path"].as_str().unwrap_or("/").trim().to_string();
    let use_ftps = params["use_ftps"].as_bool().unwrap_or(false);

    let p = FtpParams {
        address,
        username,
        password,
        root,
        use_ftps,
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
        range_read: false, // FTP doesn't support range read well
    };

    Ok(Box::new(FtpDriver {
        params: p,
        caps,
        conn: Arc::new(Mutex::new(None)),
    }))
}

// ---- 辅助函数 -------------------------------------------------------------

fn require_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("ftp 驱动缺少 '{key}' 字段")))
}

fn ftp_err(context: &str, err: suppaftp::FtpError) -> TokimoVfsError {
    let msg = format!("ftp {context}: {err}");
    match &err {
        suppaftp::FtpError::ConnectionError(_) | suppaftp::FtpError::SecureError(_) => {
            TokimoVfsError::ConnectionError(msg)
        }
        _ => {
            let lower = msg.to_lowercase();
            if lower.contains("not found") || lower.contains("no such") || lower.contains("550") {
                TokimoVfsError::NotFound(msg)
            } else if lower.contains("530") || lower.contains("login") || lower.contains("auth") {
                TokimoVfsError::ConnectionError(msg)
            } else {
                TokimoVfsError::Other(msg)
            }
        }
    }
}

/// Parse an FTP LIST response line (Unix-style ls -l or Windows DIR format).
fn parse_list_entry(line: &str, parent_path: &str) -> Option<FileInfo> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Try Unix-style: "drwxr-xr-x  2 user group  4096 Jan  1 12:00 dirname"
    if let Some(info) = parse_unix_list(line, parent_path) {
        return Some(info);
    }

    // Try Windows-style: "01-01-20  12:00PM  <DIR>  dirname"
    parse_windows_list(line, parent_path)
}

fn parse_unix_list(line: &str, parent_path: &str) -> Option<FileInfo> {
    // Minimum fields: perms, links, owner, group, size, month, day, time/year, name
    let parts: Vec<&str> = line.splitn(9, char::is_whitespace).collect();
    let parts: Vec<&str> = parts.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.len() < 8 {
        return None;
    }

    let perms = parts[0];
    let is_dir = perms.starts_with('d');
    let is_link = perms.starts_with('l');

    // Skip . and .. entries
    let name_field = if parts.len() >= 9 {
        // Rejoin remaining parts in case filename has spaces
        let idx = line.match_indices(parts[7]).next().map(|(i, _)| i + parts[7].len())?;
        line[idx..].trim()
    } else {
        parts[7]
    };

    // symlinks show as "name -> target"
    let name = if is_link {
        name_field.split(" -> ").next().unwrap_or(name_field).trim()
    } else {
        name_field
    };

    if name == "." || name == ".." {
        return None;
    }

    let size: u64 = parts[4].parse().unwrap_or(0);

    // Try to parse date: "Jan  1 12:00" or "Jan  1  2020"
    let date_str = format!("{} {} {}", parts[5], parts[6], parts[7]);
    let modified = parse_ftp_date(&date_str);

    let path = format!("{}/{}", parent_path.trim_end_matches('/'), name);

    Some(FileInfo {
        name: name.to_string(),
        path,
        size,
        is_dir: is_dir || is_link,
        modified,
    })
}

fn parse_windows_list(line: &str, parent_path: &str) -> Option<FileInfo> {
    // Format: "01-01-20  12:00PM       <DIR>          dirname"
    // or:     "01-01-20  12:00PM              1234567 filename.txt"
    let parts: Vec<&str> = line.splitn(4, char::is_whitespace).collect();
    let parts: Vec<&str> = parts.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return None;
    }

    let is_dir = parts[2] == "<DIR>";
    let (size, name) = if is_dir {
        (0u64, parts[3].to_string())
    } else {
        let sz: u64 = parts[2].parse().unwrap_or(0);
        (sz, parts[3].to_string())
    };

    if name == "." || name == ".." {
        return None;
    }

    let path = format!("{}/{}", parent_path.trim_end_matches('/'), name);

    Some(FileInfo {
        name,
        path,
        size,
        is_dir,
        modified: None,
    })
}

/// Parse FTP-style dates like "Jan 01 12:00" or "Jan 01  2020".
fn parse_ftp_date(s: &str) -> Option<DateTime<Utc>> {
    // Try "Jan 01 12:00" (current year)
    let now = Utc::now();
    let with_year = format!("{} {}", s, now.format("%Y"));
    if let Ok(dt) = NaiveDateTime::parse_from_str(&with_year, "%b %d %H:%M %Y") {
        return Some(dt.and_utc());
    }
    // Try "Jan 01  2020"
    if let Ok(dt) = NaiveDateTime::parse_from_str(&format!("{s} 00:00"), "%b %d %Y %H:%M") {
        return Some(dt.and_utc());
    }
    None
}

impl FtpDriver {
    fn full_path(&self, rel: &Path) -> String {
        let root = self.params.root.trim_end_matches('/');
        let relative = rel.to_string_lossy().trim_start_matches('/').to_string();
        if relative.is_empty() {
            if root.is_empty() {
                "/".to_string()
            } else {
                root.to_string()
            }
        } else {
            format!("{root}/{relative}")
        }
    }

    async fn do_connect(&self) -> Result<FtpConn> {
        if self.params.use_ftps {
            let mut stream = AsyncNativeTlsFtpStream::connect(&self.params.address)
                .await
                .map_err(|e| ftp_err("connect tls", e))?;
            stream
                .login(&self.params.username, &self.params.password)
                .await
                .map_err(|e| ftp_err("login tls", e))?;
            // Set binary transfer mode
            stream
                .transfer_type(FileType::Binary)
                .await
                .map_err(|e| ftp_err("binary mode", e))?;
            Ok(FtpConn::Tls(stream))
        } else {
            let mut stream = AsyncFtpStream::connect(&self.params.address)
                .await
                .map_err(|e| ftp_err("connect", e))?;
            stream
                .login(&self.params.username, &self.params.password)
                .await
                .map_err(|e| ftp_err("login", e))?;
            stream
                .transfer_type(FileType::Binary)
                .await
                .map_err(|e| ftp_err("binary mode", e))?;
            Ok(FtpConn::Plain(stream))
        }
    }

    /// Ensure we have a working connection (reconnect if needed).
    async fn ensure_connected(&self) -> Result<()> {
        let mut g = self.conn.lock().await;
        if let Some(ref mut conn) = *g {
            // Test connection by cwd
            if conn.cwd(".").await.is_ok() {
                return Ok(());
            }
        }
        // Need to (re)connect
        *g = Some(self.do_connect().await?);
        Ok(())
    }

    /// Get an exclusive lock on the connection, ensuring it's alive.
    async fn with_conn<F, T>(&self, op: F) -> Result<T>
    where
        F: for<'a> FnOnce(
            &'a mut FtpConn,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>,
    {
        self.ensure_connected().await?;
        let mut g = self.conn.lock().await;
        let conn = g
            .as_mut()
            .ok_or_else(|| TokimoVfsError::ConnectionError("ftp 未连接".into()))?;
        op(conn).await
    }
}

// ---- Trait 实现 -----------------------------------------------------------

#[async_trait]
impl Meta for FtpDriver {
    fn driver_name(&self) -> &'static str {
        "ftp"
    }

    async fn init(&self) -> Result<()> {
        self.ensure_connected().await
    }

    async fn drop_driver(&self) -> Result<()> {
        let mut g = self.conn.lock().await;
        if let Some(ref mut conn) = *g {
            let _ = conn.quit().await;
        }
        *g = None;
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let connected = self.conn.lock().await.is_some();
        StorageStatus {
            driver: "ftp".into(),
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
impl Reader for FtpDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let full = self.full_path(path);
        let display = path.to_string_lossy().to_string();
        let display_path = if display.is_empty() || display == "." {
            "/".to_string()
        } else {
            display
        };
        self.with_conn(|conn| {
            let full = full.clone();
            let display_path = display_path.clone();
            Box::pin(async move {
                let lines = conn.list(Some(&full)).await.map_err(|e| ftp_err("list", e))?;
                let entries: Vec<FileInfo> = lines
                    .iter()
                    .filter_map(|line| parse_list_entry(line, &display_path))
                    .collect();
                Ok(entries)
            })
        })
        .await
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let full = self.full_path(path);
        let name = path
            .file_name()
            .map_or_else(|| "/".to_string(), |n| n.to_string_lossy().to_string());
        let display = path.to_string_lossy().to_string();
        self.with_conn(|conn| {
            let full = full.clone();
            let name = name.clone();
            let display = display.clone();
            Box::pin(async move {
                // Try to CWD into it (directory check)
                let is_dir = conn.cwd(&full).await.is_ok();
                Ok(FileInfo {
                    name,
                    path: display,
                    size: 0,
                    is_dir,
                    modified: None,
                })
            })
        })
        .await
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        self.with_conn(|conn| {
            let full = full.clone();
            Box::pin(async move {
                let data = conn.retr_as_bytes(&full).await.map_err(|e| ftp_err("retr", e))?;
                let start = (offset as usize).min(data.len());
                let end = match limit {
                    Some(n) => (start + n as usize).min(data.len()),
                    None => data.len(),
                };
                Ok(data[start..end].to_vec())
            })
        })
        .await
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        match self.read_bytes(path, offset, limit).await {
            Ok(data) => {
                let _ = tx.send(data).await;
            }
            Err(e) => {
                error!("ftp stream_to: {e}");
            }
        }
    }
}

#[async_trait]
impl Mkdir for FtpDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_conn(|conn| {
            let full = full.clone();
            Box::pin(async move { conn.mkdir(&full).await.map_err(|e| ftp_err("mkdir", e)) })
        })
        .await
    }
}

#[async_trait]
impl DeleteFile for FtpDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_conn(|conn| {
            let full = full.clone();
            Box::pin(async move { conn.rm(&full).await.map_err(|e| ftp_err("delete file", e)) })
        })
        .await
    }
}

#[async_trait]
impl DeleteDir for FtpDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let full = self.full_path(path);
        self.with_conn(|conn| {
            let full = full.clone();
            Box::pin(async move { conn.rmdir(&full).await.map_err(|e| ftp_err("delete dir", e)) })
        })
        .await
    }
}

#[async_trait]
impl Rename for FtpDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let from_full = self.full_path(from);
        let to_full = self.full_path(to);
        self.with_conn(|conn| {
            let from_full = from_full.clone();
            let to_full = to_full.clone();
            Box::pin(async move {
                conn.rename(&from_full, &to_full)
                    .await
                    .map_err(|e| ftp_err("rename", e))
            })
        })
        .await
    }
}

#[async_trait]
impl MoveFile for FtpDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let from_full = self.full_path(from);
        let from_name = from
            .file_name()
            .ok_or_else(|| TokimoVfsError::Other(format!("ftp move: 无法确定源文件名: {}", from.display())))?;
        let to_full = format!(
            "{}/{}",
            self.full_path(to_dir).trim_end_matches('/'),
            from_name.to_string_lossy()
        );
        self.with_conn(|conn| {
            let from_full = from_full.clone();
            let to_full = to_full.clone();
            Box::pin(async move { conn.rename(&from_full, &to_full).await.map_err(|e| ftp_err("move", e)) })
        })
        .await
    }
}

#[async_trait]
impl PutFile for FtpDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let full = self.full_path(path);
        self.with_conn(|conn| {
            let full = full.clone();
            let data = data.clone();
            Box::pin(async move {
                let mut reader: &[u8] = &data;
                conn.put_file(&full, &mut reader).await.map_err(|e| ftp_err("put", e))?;
                Ok(())
            })
        })
        .await
    }
}

#[async_trait]
impl PutStream for FtpDriver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let mut buf = Vec::new();
        while let Some(chunk) = rx.recv().await {
            buf.extend_from_slice(&chunk);
        }
        self.put(path, buf).await
    }
}

impl Driver for FtpDriver {
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

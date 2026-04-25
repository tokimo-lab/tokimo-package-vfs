//! `WebDAV` 驱动 — 基于 `reqwest_dav（async，纯` Rust HTTP）。
//!
//! JSON 配置字段：
//!   url         — `WebDAV` 服务器地址，如 "<https://server/remote.php/dav/files/user>"
//!   username    — 用户名
//!   password    — 密码
//!   `root_folder_path` — 远端根目录（可选，默认 "/"）

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest_dav::{Auth, Client, ClientBuilder, Depth, list_cmd::ListEntity};
use tokio::sync::{Mutex, mpsc::Sender};
use tracing::error;

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    CopyFile, DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename,
};
use tokimo_vfs_core::error::{TokimoVfsError, Result};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

pub const CONFIG: DriverConfig = DriverConfig {
    name: "webdav",
    description: "WebDAV（基于 reqwest_dav）",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

// ---- 参数 ----------------------------------------------------------------

#[derive(Clone)]
struct WebDavParams {
    address: String,
    username: String,
    password: String,
    root: String,
}

// ---- 驱动结构 -------------------------------------------------------------

pub struct WebDavDriver {
    params: WebDavParams,
    caps: StorageCapabilities,
    client: Arc<Mutex<Option<Client>>>,
}

// ---- 工厂 ----------------------------------------------------------------

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let address = require_str(params, "url")?.to_string();
    let username = require_str(params, "username")?.to_string();
    let password = require_str(params, "password")?.to_string();
    let root = params["root_folder_path"].as_str().unwrap_or("/").trim().to_string();

    let p = WebDavParams {
        address,
        username,
        password,
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

    Ok(Box::new(WebDavDriver {
        params: p,
        caps,
        client: Arc::new(Mutex::new(None)),
    }))
}

// ---- 辅助函数 -------------------------------------------------------------

fn require_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("webdav 驱动缺少 '{key}' 字段")))
}

fn dav_err(context: &str, err: reqwest_dav::Error) -> TokimoVfsError {
    let msg = format!("webdav {context}: {err}");
    match &err {
        reqwest_dav::Error::Reqwest(re) => {
            if let Some(status) = re.status() {
                match status.as_u16() {
                    404 => TokimoVfsError::NotFound(msg),
                    401 | 403 => TokimoVfsError::ConnectionError(msg),
                    _ => TokimoVfsError::Other(msg),
                }
            } else if re.is_connect() || re.is_timeout() {
                TokimoVfsError::ConnectionError(msg)
            } else {
                TokimoVfsError::Other(msg)
            }
        }
        _ => TokimoVfsError::Other(msg),
    }
}

impl WebDavDriver {
    fn build_client(&self) -> Result<Client> {
        ClientBuilder::new()
            .set_host(self.params.address.clone())
            .set_auth(Auth::Basic(self.params.username.clone(), self.params.password.clone()))
            .build()
            .map_err(|e| TokimoVfsError::InvalidConfig(format!("webdav client build: {e}")))
    }

    async fn ensure_connected(&self) -> Result<()> {
        let mut g = self.client.lock().await;
        if g.is_none() {
            *g = Some(self.build_client()?);
        }
        Ok(())
    }

    async fn get_client(&self) -> Result<Client> {
        self.ensure_connected().await?;
        let g = self.client.lock().await;
        g.clone()
            .ok_or_else(|| TokimoVfsError::ConnectionError("webdav 未连接".into()))
    }

    /// Build full remote path by joining root + relative path.
    fn full_path(&self, rel: &Path) -> String {
        let root = self.params.root.trim_end_matches('/');
        let relative = rel.to_string_lossy().trim_start_matches('/').to_string();
        if relative.is_empty() {
            format!("{root}/")
        } else {
            format!("{root}/{relative}")
        }
    }

    /// Convert a `ListEntity` to `FileInfo`.
    fn entity_to_fileinfo(entity: &ListEntity, parent_path: &str) -> Option<FileInfo> {
        match entity {
            ListEntity::File(f) => {
                let name = extract_name(&f.href);
                if name.is_empty() {
                    return None;
                }
                let path = format!("{}/{}", parent_path.trim_end_matches('/'), name);
                Some(FileInfo {
                    name,
                    path,
                    size: f.content_length as u64,
                    is_dir: false,
                    modified: Some(f.last_modified),
                })
            }
            ListEntity::Folder(f) => {
                let name = extract_name(&f.href);
                if name.is_empty() {
                    return None;
                }
                let path = format!("{}/{}", parent_path.trim_end_matches('/'), name);
                Some(FileInfo {
                    name,
                    path,
                    size: 0,
                    is_dir: true,
                    modified: Some(f.last_modified),
                })
            }
        }
    }
}

/// Extract file/folder name from an href path.
fn extract_name(href: &str) -> String {
    let decoded = urlencoding::decode(href).unwrap_or_else(|_| href.into());
    let trimmed = decoded.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or("").to_string()
}

// ---- Trait 实现 -----------------------------------------------------------

#[async_trait]
impl Meta for WebDavDriver {
    fn driver_name(&self) -> &'static str {
        "webdav"
    }

    async fn init(&self) -> Result<()> {
        let client = self.build_client()?;
        // Verify connectivity with a PROPFIND on root
        let root = self.params.root.trim_end_matches('/');
        let root_path = if root.is_empty() { "/" } else { root };
        client
            .list(root_path, Depth::Number(0))
            .await
            .map_err(|e| dav_err("init", e))?;
        *self.client.lock().await = Some(client);
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        *self.client.lock().await = None;
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let connected = self.client.lock().await.is_some();
        StorageStatus {
            driver: "webdav".into(),
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
impl Reader for WebDavDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        let entities = client
            .list(&full, Depth::Number(1))
            .await
            .map_err(|e| dav_err("list", e))?;
        let display = path.to_string_lossy().to_string();
        let results: Vec<FileInfo> = entities
            .iter()
            .filter_map(|e| Self::entity_to_fileinfo(e, &display))
            .collect();
        Ok(results)
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        let entities = client
            .list(&full, Depth::Number(0))
            .await
            .map_err(|e| dav_err("stat", e))?;
        let display = path.to_string_lossy().to_string();
        entities
            .into_iter()
            .find_map(|e| Self::entity_to_fileinfo(&e, &display))
            .or_else(|| {
                // Depth(0) returns the item itself; use the path name
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                Some(FileInfo {
                    name,
                    path: display,
                    size: 0,
                    is_dir: true,
                    modified: None,
                })
            })
            .ok_or_else(|| TokimoVfsError::NotFound(format!("webdav stat: {full}")))
    }

    async fn link(&self, path: &Path) -> Result<Link> {
        // WebDAV files are accessed via direct URL + Basic auth header
        let full = self.full_path(path);
        let url = format!(
            "{}/{}",
            self.params.address.trim_end_matches('/'),
            full.trim_start_matches('/')
        );
        let mut header = std::collections::HashMap::new();
        // Build basic auth header
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", self.params.username, self.params.password),
        );
        header.insert("Authorization".to_string(), format!("Basic {credentials}"));
        Ok(Link {
            url: Some(url),
            header,
            expiry: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        let response = client.get(&full).await.map_err(|e| dav_err("get", e))?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("webdav read: {e}")))?;
        let data = bytes.to_vec();

        let start = (offset as usize).min(data.len());
        let end = match limit {
            Some(n) => (start + n as usize).min(data.len()),
            None => data.len(),
        };
        Ok(data[start..end].to_vec())
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let client = match self.get_client().await {
            Ok(c) => c,
            Err(e) => {
                error!("webdav stream_to connect: {e}");
                return;
            }
        };
        let full = self.full_path(path);
        let response = match client.get(&full).await {
            Ok(r) => r,
            Err(e) => {
                error!("webdav stream_to get: {e}");
                return;
            }
        };
        let bytes = match response.bytes().await {
            Ok(b) => b,
            Err(e) => {
                error!("webdav stream_to read: {e}");
                return;
            }
        };
        let data = bytes.to_vec();
        let start = (offset as usize).min(data.len());
        let end = match limit {
            Some(n) => (start + n as usize).min(data.len()),
            None => data.len(),
        };
        if start < end {
            let _ = tx.send(data[start..end].to_vec()).await;
        }
    }
}

#[async_trait]
impl Mkdir for WebDavDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        client.mkcol(&full).await.map_err(|e| dav_err("mkdir", e))
    }
}

#[async_trait]
impl DeleteFile for WebDavDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        client.delete(&full).await.map_err(|e| dav_err("delete file", e))
    }
}

#[async_trait]
impl DeleteDir for WebDavDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        client.delete(&full).await.map_err(|e| dav_err("delete dir", e))
    }
}

#[async_trait]
impl Rename for WebDavDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let client = self.get_client().await?;
        let from_full = self.full_path(from);
        let to_full = self.full_path(to);
        client.mv(&from_full, &to_full).await.map_err(|e| dav_err("rename", e))
    }
}

#[async_trait]
impl MoveFile for WebDavDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let from_full = self.full_path(from);
        let from_name = from
            .file_name()
            .ok_or_else(|| TokimoVfsError::Other(format!("webdav move: 无法确定源文件名: {}", from.display())))?;
        let to_full = format!(
            "{}/{}",
            self.full_path(to_dir).trim_end_matches('/'),
            from_name.to_string_lossy()
        );
        let client = self.get_client().await?;
        client.mv(&from_full, &to_full).await.map_err(|e| dav_err("move", e))
    }
}

#[async_trait]
impl CopyFile for WebDavDriver {
    async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        let client = self.get_client().await?;
        let from_full = self.full_path(from);
        let to_full = self.full_path(to);
        client.cp(&from_full, &to_full).await.map_err(|e| dav_err("copy", e))
    }
}

#[async_trait]
impl PutFile for WebDavDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let client = self.get_client().await?;
        let full = self.full_path(path);
        client.put(&full, data).await.map_err(|e| dav_err("put", e))
    }
}

#[async_trait]
impl PutStream for WebDavDriver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let mut buf = Vec::new();
        while let Some(chunk) = rx.recv().await {
            buf.extend_from_slice(&chunk);
        }
        self.put(path, buf).await
    }
}

impl Driver for WebDavDriver {
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

    fn as_copy(&self) -> Option<&dyn CopyFile> {
        Some(self)
    }

    fn as_put(&self) -> Option<&dyn PutFile> {
        Some(self)
    }

    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }
}

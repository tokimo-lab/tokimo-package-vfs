use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{Result, TokimoVfsError};
use crate::model::obj::{FileInfo, Link};
use crate::model::storage::{StorageCapabilities, StorageStatus};

/// Callback injected by `SourceRegistry` so drivers can persist updated
/// credentials (rotated tokens, refreshed cookies) without knowing about the
/// database.  Equivalent to OpenList's `op.MustSaveDriverStorage(d)`.
///
/// The closure receives a JSON patch object (e.g. `{"refresh_token": "…"}`)
/// and is responsible for writing it back to the config store.  It is called
/// fire-and-forget — the driver does not await the result.
pub type ConfigPersister = Arc<dyn Fn(serde_json::Value) + Send + Sync>;

/// 生命周期/状态能力，与 `OpenList` 的 Meta 层类似。
#[async_trait]
pub trait Meta: Send + Sync + 'static {
    fn driver_name(&self) -> &'static str;
    async fn init(&self) -> Result<()>;
    async fn drop_driver(&self) -> Result<()>;
    async fn status(&self) -> StorageStatus;
    fn capabilities(&self) -> StorageCapabilities;

    /// Inject a persistence callback.  Called by `SourceRegistry` before
    /// `init()`.  Drivers that rotate credentials at runtime store this and
    /// call it whenever credentials change (like OpenList's
    /// `op.MustSaveDriverStorage`).
    fn set_config_persister(&self, _persister: ConfigPersister) {}

    /// Return updated config fields that should be persisted after init.
    /// Kept as a simpler fallback for one-shot credential exchanges (e.g.
    /// QR-code login).  Drivers that use `set_config_persister` do not need
    /// to implement this.
    fn resolved_config_patch(&self) -> Option<serde_json::Value> {
        None
    }
}

/// 读能力，与 `OpenList` 的 Reader 层类似。
#[async_trait]
pub trait Reader: Send + Sync + 'static {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>>;
    async fn stat(&self, path: &Path) -> Result<FileInfo>;

    async fn link(&self, _path: &Path) -> Result<Link> {
        Ok(Link::default())
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>>;

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        match self.read_bytes(path, offset, limit).await {
            Ok(data) => {
                tx.send(data).await.ok();
            }
            Err(err) => {
                tracing::error!("stream_to fallback error: {}", err);
            }
        }
    }
}

#[async_trait]
pub trait Mkdir: Send + Sync + 'static {
    async fn mkdir(&self, path: &Path) -> Result<()>;
}

#[async_trait]
pub trait DeleteFile: Send + Sync + 'static {
    async fn delete_file(&self, path: &Path) -> Result<()>;
}

#[async_trait]
pub trait DeleteDir: Send + Sync + 'static {
    async fn delete_dir(&self, path: &Path) -> Result<()>;
}

#[async_trait]
pub trait Rename: Send + Sync + 'static {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()>;
}

#[async_trait]
pub trait MoveFile: Send + Sync + 'static {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()>;
}

#[async_trait]
pub trait CopyFile: Send + Sync + 'static {
    async fn copy(&self, from: &Path, to: &Path) -> Result<()>;
}

#[async_trait]
pub trait PutFile: Send + Sync + 'static {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()>;
}

/// Streaming upload: receives chunks via a channel, avoids buffering the
/// entire file in memory.  Drivers that support multipart/chunked uploads
/// (e.g. Quark, S3) should implement this for large-file transfers.
#[async_trait]
pub trait PutStream: Send + Sync + 'static {
    async fn put_stream(&self, path: &Path, size: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()>;
}

/// Resolve a VFS-relative path to the actual local filesystem path.
/// Only drivers backed by a real local directory (e.g. `local`) return `Some`.
pub trait ResolveLocal: Send + Sync + 'static {
    fn resolve_real_path(&self, path: &Path) -> Option<String>;
}

/// 统一 trait object，同时把可选写能力拆成独立 traits。
pub trait Driver: Meta + Reader {
    fn as_mkdir(&self) -> Option<&dyn Mkdir> {
        None
    }

    fn as_delete_file(&self) -> Option<&dyn DeleteFile> {
        None
    }

    fn as_delete_dir(&self) -> Option<&dyn DeleteDir> {
        None
    }

    fn as_rename(&self) -> Option<&dyn Rename> {
        None
    }

    fn as_move(&self) -> Option<&dyn MoveFile> {
        None
    }

    fn as_copy(&self) -> Option<&dyn CopyFile> {
        None
    }

    fn as_put(&self) -> Option<&dyn PutFile> {
        None
    }

    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        None
    }

    fn as_resolve_local(&self) -> Option<&dyn ResolveLocal> {
        None
    }
}

pub fn unsupported(action: &str, driver_name: &str) -> TokimoVfsError {
    TokimoVfsError::NotImplemented(format!("{driver_name} 不支持 {action}"))
}

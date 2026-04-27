//! 本地文件系统驱动。
//!
//! JSON 配置字段：
//!   root — 本地根目录路径，如 "/mnt/media"

use std::path::Path;

use async_trait::async_trait;
use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    CopyFile, DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename, ResolveLocal,
};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;
use tracing::error;

pub const CONFIG: DriverConfig = DriverConfig {
    name: "local",
    description: "本地文件系统",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let root = params["root_folder_path"]
        .as_str()
        .ok_or_else(|| TokimoVfsError::InvalidConfig("local 驱动缺少 'root_folder_path' 字段".into()))?
        .to_string();
    Ok(Box::new(LocalDriver { root }))
}

struct LocalDriver {
    root: String,
}

impl LocalDriver {
    fn full_path(&self, path: &Path) -> String {
        format!(
            "{}/{}",
            self.root.trim_end_matches('/'),
            path.to_string_lossy().trim_start_matches('/')
        )
    }

    fn move_destination(&self, from: &Path, to_dir: &Path) -> Result<String> {
        let name = from
            .file_name()
            .ok_or_else(|| TokimoVfsError::Other(format!("local move: 无法确定源文件名: {}", from.display())))?;
        Ok(self.full_path(&to_dir.join(name)))
    }
}

#[async_trait]
impl Meta for LocalDriver {
    fn driver_name(&self) -> &'static str {
        "local"
    }

    async fn init(&self) -> Result<()> {
        Ok(())
    }
    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        StorageStatus {
            driver: "local".into(),
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
impl Reader for LocalDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let full = self.full_path(path);
        let mut entries = Vec::new();
        let mut rd = fs::read_dir(&full)
            .await
            .map_err(|e| TokimoVfsError::NotFound(format!("{full}: {e}")))?;

        while let Some(entry) = rd.next_entry().await? {
            let meta = entry.metadata().await.ok();
            let is_dir = meta.as_ref().is_some_and(std::fs::Metadata::is_dir);
            let size = meta.as_ref().map_or(0, std::fs::Metadata::len);
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{}/{}", path.to_string_lossy().trim_end_matches('/'), name);
            entries.push(FileInfo {
                name,
                path: rel,
                size,
                is_dir,
                modified: None,
            });
        }
        Ok(entries)
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let full = self.full_path(path);
        let meta = fs::metadata(&full)
            .await
            .map_err(|e| TokimoVfsError::NotFound(format!("{full}: {e}")))?;
        Ok(FileInfo {
            name: path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
            path: format!("/{}", path.to_string_lossy().trim_start_matches('/')),
            size: meta.len(),
            is_dir: meta.is_dir(),
            modified: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        let mut f = fs::File::open(&full)
            .await
            .map_err(|e| TokimoVfsError::NotFound(format!("{full}: {e}")))?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| TokimoVfsError::Other(format!("seek: {e}")))?;
        let mut buf = match limit {
            Some(n) => Vec::with_capacity(n.min(usize::MAX as u64) as usize),
            None => Vec::new(),
        };
        if let Some(n) = limit {
            let mut limited = f.take(n);
            limited.read_to_end(&mut buf).await?;
        } else {
            f.read_to_end(&mut buf).await?;
        }
        Ok(buf)
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let full = self.full_path(path);
        let mut f = match fs::File::open(&full).await {
            Ok(f) => f,
            Err(e) => {
                error!("stream_to open: {}: {}", full, e);
                return;
            }
        };
        if offset > 0
            && let Err(e) = f.seek(std::io::SeekFrom::Start(offset)).await
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
            match f.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    sent += n as u64;
                    chunk.truncate(n);
                    if tx.send(chunk).await.is_err() {
                        // receiver dropped (tee-task exited or session cancelled)
                        return;
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
impl Mkdir for LocalDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(self.full_path(path)).await.map_err(Into::into)
    }
}

#[async_trait]
impl DeleteFile for LocalDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        fs::remove_file(self.full_path(path)).await.map_err(Into::into)
    }
}

#[async_trait]
impl DeleteDir for LocalDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        fs::remove_dir(self.full_path(path)).await.map_err(Into::into)
    }
}

#[async_trait]
impl Rename for LocalDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        fs::rename(self.full_path(from), self.full_path(to))
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl MoveFile for LocalDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        fs::rename(self.full_path(from), self.move_destination(from, to_dir)?)
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl CopyFile for LocalDriver {
    async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        let from_path = self.full_path(from);
        let to_path = self.full_path(to);
        let metadata = fs::metadata(&from_path).await.map_err(TokimoVfsError::from)?;
        if metadata.is_dir() {
            return Err(TokimoVfsError::NotImplemented("local copy 暂不支持目录递归复制".into()));
        }
        fs::copy(from_path, to_path).await.map(|_| ()).map_err(Into::into)
    }
}

#[async_trait]
impl PutFile for LocalDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        fs::write(self.full_path(path), data).await.map_err(Into::into)
    }
}

#[async_trait]
impl PutStream for LocalDriver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let full = self.full_path(path);
        let full_path = Path::new(&full);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await.ok();
        }
        let mut file = fs::File::create(&full)
            .await
            .map_err(|e| TokimoVfsError::Other(format!("local create {full}: {e}")))?;
        while let Some(chunk) = rx.recv().await {
            file.write_all(&chunk)
                .await
                .map_err(|e| TokimoVfsError::Other(format!("local write {full}: {e}")))?;
        }
        file.flush()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("local flush {full}: {e}")))?;
        Ok(())
    }
}

impl ResolveLocal for LocalDriver {
    fn resolve_real_path(&self, path: &Path) -> Option<String> {
        Some(self.full_path(path))
    }
}

impl Driver for LocalDriver {
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

    fn as_resolve_local(&self) -> Option<&dyn ResolveLocal> {
        Some(self)
    }
}

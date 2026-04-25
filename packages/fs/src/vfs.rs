//! FS 层（Virtual File System）
//!
//! 架构位置：Server → **Vfs** (FS 层) → `StorageManager` (OP 层) → Driver
//!
//! 职责：
//!   1. 路径规范化（保证以 "/" 开头）
//!   2. list/stat 返回的 FileInfo.path 使用虚拟路径（含挂载前缀）
//!      驱动只知道自己根下的相对路径，Vfs 在这里拼上挂载前缀后返回给 Server 层。
//!   3. 扩展点：缓存、访问控制、限速等横切关注点将在此添加，绝不污染 Driver 层。

use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use tokimo_vfs_core::driver::traits::Driver;
use tokimo_vfs_core::error::Result;
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::StorageStatus;
use tokimo_vfs_op::{StorageManager, StorageMount};

pub struct Vfs {
    manager: Arc<StorageManager>,
}

impl Vfs {
    pub fn new(manager: StorageManager) -> Self {
        Self {
            manager: Arc::new(manager),
        }
    }

    // ---- 读操作 ----

    /// Resolve a VFS path to the real local filesystem path.
    /// Returns `None` if the underlying driver is not backed by a local directory.
    pub async fn resolve_real_path(&self, path: &Path) -> Option<String> {
        self.manager.resolve_real_path(path).await
    }

    /// 列目录。
    /// 驱动返回的 `FileInfo.path` 是驱动内部相对路径，
    /// Vfs `用虚拟路径（virt_path` + "/" + name）替换，保证挂载前缀正确。
    pub async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let files = self.manager.list(path).await?;
        let prefix = normalize(path);
        Ok(files
            .into_iter()
            .map(|mut f| {
                f.path = format!("{}/{}", prefix.trim_end_matches('/'), f.name);
                f
            })
            .collect())
    }

    /// stat 单个路径，Vfs 修正 path 字段为虚拟路径。
    pub async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let mut f = self.manager.stat(path).await?;
        f.path = normalize(path);
        Ok(f)
    }

    /// 获取下载 Link（直链 or 代理）。
    pub async fn link(&self, path: &Path) -> Result<Link> {
        self.manager.link(path).await
    }

    /// 随机读字节（用于 HTTP Range 响应）。
    pub async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        self.manager.read_bytes(path, offset, limit).await
    }

    /// 流式传输到 channel（驱动可覆盖实现真正逐块发送）。
    pub async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        self.manager.stream_to(path, offset, limit, tx).await;
    }

    /// Wrap this VFS path into a synchronous [`tokimo_vfs_core::ReadAt`] closure.
    ///
    /// Internally detects the driver type (requires one `.await` for routing):
    /// - **Local driver** → `FileExt::read_at` (zero async overhead, true random-read syscall)
    /// - **Remote driver** → closure that calls `block_on(manager.read_bytes(…))`
    ///
    /// The returned closure is fully synchronous and safe to call from FFmpeg
    /// threads (non-tokio context).
    pub async fn to_read_at(&self, path: impl Into<std::path::PathBuf>) -> tokimo_vfs_core::ReadAt {
        let path: std::path::PathBuf = path.into();

        // Local driver fast path: FileExt::read_at (no async overhead)
        if let Some(local_str) = self.resolve_real_path(&path).await {
            if let Ok(file) = std::fs::File::open(&local_str) {
                let file = Arc::new(file);
                return Arc::new(move |offset: u64, size: usize| {
                    use std::os::unix::fs::FileExt;
                    let mut buf = vec![0u8; size];
                    let n = file.read_at(&mut buf, offset)?;
                    buf.truncate(n);
                    Ok(buf)
                });
            }
            tracing::warn!(
                "VFS local fast-path open failed ({}), falling back to remote read",
                local_str,
            );
        }

        // Remote driver: capture Arc<StorageManager> + handle, block_on inside the closure
        let manager = Arc::clone(&self.manager);
        let handle = tokio::runtime::Handle::current();
        Arc::new(move |offset: u64, size: usize| {
            let manager = manager.clone();
            let path = path.clone();
            handle
                .block_on(manager.read_bytes(&path, offset, Some(size as u64)))
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }

    // ---- 写操作（透传到 OP 层，驱动不支持时返回 NotImplemented）----

    pub async fn mkdir(&self, path: &Path) -> Result<()> {
        self.manager.mkdir(path).await
    }

    pub async fn delete_file(&self, path: &Path) -> Result<()> {
        self.manager.delete_file(path).await
    }

    pub async fn delete_dir(&self, path: &Path) -> Result<()> {
        self.manager.delete_dir(path).await
    }

    /// 重命名/移动。两个路径必须在同一挂载点，否则返回 `NotImplemented`。
    pub async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.manager.rename(from, to).await
    }

    pub async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        self.manager.move_file(from, to_dir).await
    }

    pub async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        self.manager.copy(from, to).await
    }

    pub async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        self.manager.put(path, data).await
    }

    /// Streaming upload (avoids buffering the whole file in memory).
    /// Falls back to `Err(NotImplemented)` if the driver does not support it.
    pub async fn put_stream(&self, path: &Path, size: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        self.manager.put_stream(path, size, rx).await
    }

    /// Check if the driver behind `path` supports streaming upload.
    pub async fn has_put_stream(&self, path: &Path) -> bool {
        self.manager.has_put_stream(path).await
    }

    // ---- 生命周期 ----

    /// 动态挂载一个新驱动并立即初始化它。
    pub async fn mount_driver(
        &self,
        mount_point: impl Into<std::path::PathBuf>,
        driver: Arc<dyn Driver>,
    ) -> Result<()> {
        let mp = mount_point.into();
        driver.init().await?;
        let m = StorageMount::new(mp, Arc::clone(&driver));
        self.manager.mount(m).await;
        Ok(())
    }

    /// 返回所有挂载点路径列表。
    pub async fn mount_points(&self) -> Vec<String> {
        self.manager.mount_points().await
    }

    /// 初始化所有挂载的驱动。返回每个挂载点的初始化结果。
    pub async fn init_all(&self) -> Vec<(String, Result<()>)> {
        self.manager.init_all().await
    }

    pub async fn drop_all(&self) {
        self.manager.drop_all().await;
    }

    /// 所有挂载点的状态列表。
    pub async fn all_status(&self) -> Vec<StorageStatus> {
        self.manager.all_status().await
    }
}

/// 保证路径以 "/" 开头（虚拟路径规范形式）。
fn normalize(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with('/') {
        s.into_owned()
    } else {
        format!("/{s}")
    }
}

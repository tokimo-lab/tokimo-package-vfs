//! OP 层 — 存储操作调度器
//!
//! 架构位置：
//!   HTTP Handler → `StorageManager` (OP 层) → Driver (具体实现)
//!
//! 职责：
//!   1. 挂载点路由：将路径映射到正确的驱动实例
//!   2. 驱动生命周期：init / `drop_driver`
//!   3. 统一错误处理与能力检查
//!
//!   （未来：缓存层、任务调度放在此处扩展）

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::RwLock;

use tokimo_vfs_core::driver::traits::Driver;
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{StorageCapabilities, StorageStatus};

/// 单个存储挂载点。
#[derive(Clone)]
pub struct StorageMount {
    /// 挂载路径，如 `/`、`/aliyun`、`/nas`
    pub mount_point: PathBuf,
    /// 驱动实例
    pub driver: Arc<dyn Driver>,
}

impl StorageMount {
    pub fn new(mount_point: impl Into<PathBuf>, driver: Arc<dyn Driver>) -> Self {
        Self {
            mount_point: mount_point.into(),
            driver,
        }
    }
}

/// 多存储管理器（OP 层核心）。
///
/// 对 HTTP 层暴露与 `Driver` trait 相同的接口，
/// 内部自动根据路径路由到对应驱动。
pub struct StorageManager {
    pub(crate) mounts: RwLock<Vec<StorageMount>>,
}

impl StorageManager {
    pub fn new() -> Self {
        Self {
            mounts: RwLock::new(Vec::new()),
        }
    }

    /// 挂载一个存储，按挂载路径深度降序排列（最长前缀优先匹配）。
    pub async fn mount(&self, m: StorageMount) {
        let mut mounts = self.mounts.write().await;
        mounts.push(m);
        sort_mounts(&mut mounts);
    }

    async fn mounts_snapshot(&self) -> Vec<StorageMount> {
        self.mounts.read().await.clone()
    }

    /// 列出所有已挂载点的挂载路径。
    pub async fn mount_points(&self) -> Vec<String> {
        self.mounts_snapshot()
            .await
            .into_iter()
            .map(|m| m.mount_point.to_string_lossy().into_owned())
            .collect()
    }

    // ---- 内部路由 ----

    async fn resolve(&self, path: &Path) -> Result<(Arc<dyn Driver>, PathBuf)> {
        for m in self.mounts_snapshot().await {
            if let Some(rel) = strip_prefix(path, &m.mount_point) {
                let driver_path = if rel.as_os_str().is_empty() {
                    PathBuf::from("/")
                } else {
                    PathBuf::from("/").join(rel)
                };
                return Ok((Arc::clone(&m.driver), driver_path));
            }
        }
        Err(TokimoVfsError::NotFound(format!(
            "no storage mount for path: {}",
            path.display()
        )))
    }

    async fn primary_mount(&self) -> Result<StorageMount> {
        self.mounts
            .read()
            .await
            .last()
            .cloned()
            .ok_or_else(|| TokimoVfsError::Other("no storage mounted".into()))
    }

    // ---- 生命周期管理 ----

    pub async fn init_all(&self) -> Vec<(String, Result<()>)> {
        let mut results = Vec::new();
        for m in self.mounts_snapshot().await {
            let r = m.driver.init().await;
            results.push((m.mount_point.to_string_lossy().into_owned(), r));
        }
        results
    }

    pub async fn drop_all(&self) {
        for m in self.mounts_snapshot().await {
            let _ = m.driver.drop_driver().await;
        }
    }

    pub async fn all_status(&self) -> Vec<StorageStatus> {
        let mut v = Vec::new();
        for m in self.mounts_snapshot().await {
            v.push(m.driver.status().await);
        }
        v
    }

    /// 返回"主"挂载点（挂载路径最短的那个，通常是 "/"）状态。
    pub async fn primary_status(&self) -> Result<StorageStatus> {
        let primary = self.primary_mount().await?;
        Ok(primary.driver.status().await)
    }

    pub async fn primary_init(&self) -> Result<StorageStatus> {
        let primary = self.primary_mount().await?;
        primary.driver.init().await?;
        Ok(primary.driver.status().await)
    }

    pub async fn primary_drop(&self) -> Result<()> {
        let primary = self.primary_mount().await?;
        primary.driver.drop_driver().await
    }

    pub async fn primary_capabilities(&self) -> Result<StorageCapabilities> {
        let primary = self.primary_mount().await?;
        Ok(primary.driver.capabilities())
    }

    // ---- FS 操作（路由到驱动）----

    /// Resolve a VFS path to the real local filesystem path.
    /// Returns `None` if the driver does not support local resolution.
    pub async fn resolve_real_path(&self, path: &Path) -> Option<String> {
        let (driver, rel) = self.resolve(path).await.ok()?;
        driver.as_resolve_local()?.resolve_real_path(&rel)
    }

    pub async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let (driver, real) = self.resolve(path).await?;
        driver.list(&real).await
    }

    pub async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let (driver, real) = self.resolve(path).await?;
        driver.stat(&real).await
    }

    /// 获取文件下载 Link（直链或代理）。
    pub async fn link(&self, path: &Path) -> Result<Link> {
        let (driver, real) = self.resolve(path).await?;
        driver.link(&real).await
    }

    pub async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let (driver, real) = self.resolve(path).await?;
        driver.read_bytes(&real, offset, limit).await
    }

    pub async fn stream_to(
        &self,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        if let Ok((driver, real)) = self.resolve(path).await {
            driver.stream_to(&real, offset, limit, tx).await;
        }
    }

    pub async fn mkdir(&self, path: &Path) -> Result<()> {
        let (driver, real) = self.resolve(path).await?;
        let mkdir = driver
            .as_mkdir()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 mkdir", driver.driver_name())))?;
        mkdir.mkdir(&real).await
    }

    pub async fn delete_file(&self, path: &Path) -> Result<()> {
        let (driver, real) = self.resolve(path).await?;
        let delete_file = driver
            .as_delete_file()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 delete_file", driver.driver_name())))?;
        delete_file.delete_file(&real).await
    }

    pub async fn delete_dir(&self, path: &Path) -> Result<()> {
        let (driver, real) = self.resolve(path).await?;
        let _ = driver
            .as_delete_dir()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 delete_dir", driver.driver_name())))?;
        delete_dir_recursive(&*driver, real).await
    }

    pub async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let (driver, real_from) = self.resolve(from).await?;
        let (driver2, real_to) = self.resolve(to).await?;
        if !Arc::ptr_eq(&driver, &driver2) {
            return Err(TokimoVfsError::NotImplemented("rename 暂不支持跨 storage".into()));
        }
        let rename = driver
            .as_rename()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 rename", driver.driver_name())))?;
        rename.rename(&real_from, &real_to).await
    }

    pub async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let (driver, real_from) = self.resolve(from).await?;
        let (driver2, real_to_dir) = self.resolve(to_dir).await?;
        if !Arc::ptr_eq(&driver, &driver2) {
            return Err(TokimoVfsError::NotImplemented("move 暂不支持跨 storage".into()));
        }
        let move_file = driver
            .as_move()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 move", driver.driver_name())))?;
        move_file.move_file(&real_from, &real_to_dir).await
    }

    pub async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        let (driver, real_from) = self.resolve(from).await?;
        let (driver2, real_to) = self.resolve(to).await?;
        if !Arc::ptr_eq(&driver, &driver2) {
            return Err(TokimoVfsError::NotImplemented("copy 暂不支持跨 storage".into()));
        }
        let copy = driver
            .as_copy()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 copy", driver.driver_name())))?;
        copy.copy(&real_from, &real_to).await
    }

    pub async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let (driver, real) = self.resolve(path).await?;
        let put = driver
            .as_put()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 put", driver.driver_name())))?;
        put.put(&real, data).await
    }

    /// Streaming upload. Returns `Err(NotImplemented)` if the driver does not
    /// support `PutStream`.
    pub async fn put_stream(&self, path: &Path, size: u64, rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let (driver, real) = self.resolve(path).await?;
        let ps = driver
            .as_put_stream()
            .ok_or_else(|| TokimoVfsError::NotImplemented(format!("{} 不支持 put_stream", driver.driver_name())))?;
        ps.put_stream(&real, size, rx).await
    }

    /// Check if the resolved driver supports streaming upload.
    pub async fn has_put_stream(&self, path: &Path) -> bool {
        match self.resolve(path).await {
            Ok((driver, _)) => driver.as_put_stream().is_some(),
            Err(_) => false,
        }
    }
}

impl Default for StorageManager {
    fn default() -> Self {
        Self::new()
    }
}

fn sort_mounts(mounts: &mut [StorageMount]) {
    mounts.sort_by(|a, b| {
        b.mount_point
            .components()
            .count()
            .cmp(&a.mount_point.components().count())
    });
}

/// Recursively delete a directory: list contents, delete all children, then
/// delete the (now empty) directory itself.  Uses `Box::pin` to support async
/// recursion.
fn delete_dir_recursive<'a>(
    driver: &'a dyn Driver,
    path: PathBuf,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let entries = driver.list(&path).await?;
        for entry in entries {
            let child = PathBuf::from(&entry.path);
            if entry.is_dir {
                delete_dir_recursive(driver, child).await?;
            } else if let Some(df) = driver.as_delete_file() {
                df.delete_file(&child).await?;
            } else {
                return Err(TokimoVfsError::NotImplemented(format!(
                    "{} 不支持 delete_file，无法递归删除目录",
                    driver.driver_name()
                )));
            }
        }
        // unwrap is safe: caller already checked as_delete_dir() is Some
        driver.as_delete_dir().unwrap().delete_dir(&path).await
    })
}

fn strip_prefix<'a>(path: &'a Path, base: &Path) -> Option<&'a Path> {
    if base == Path::new("/") {
        return Some(path.strip_prefix("/").unwrap_or(path));
    }
    path.strip_prefix(base).ok()
}

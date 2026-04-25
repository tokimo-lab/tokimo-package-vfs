// ------- FS 层 -------
pub mod vfs; // Vfs：路径组装、跨切面扩展点（缓存、限速…）

// ------- 内置驱动 -------
pub mod drivers; // local、smb（可按需扩展）

// ------- 常用再导出 -------
pub use tokimo_vfs_core::{
    ConfigPersister, ConnectionState, CopyFile, DeleteDir, DeleteFile, Driver, DriverConfig, DriverFactory,
    DriverRegistry, FileInfo, Link, Meta, Mkdir, MoveFile, TokimoVfsError, PutFile, PutStream, ReadAt, Reader, Rename,
    Result, StorageCapabilities, StorageStatus,
};
pub use tokimo_vfs_op::{StorageManager, StorageMount};
pub use vfs::Vfs;

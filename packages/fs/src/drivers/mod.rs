pub mod aliyundrive;
pub mod baidu_netdisk;
pub mod cloud189;
pub mod ftp;
pub mod local;
pub mod nfs;
pub mod pan115;
pub mod quark;
pub mod s3;
pub mod sftp;
pub mod smb;
pub mod webdav;

use tokimo_vfs_core::error::TokimoVfsError;

/// Map a `reqwest::Error` (typically from `.error_for_status()`) to `TokimoVfsError`,
/// using the HTTP status code for classification.
pub(crate) fn reqwest_err(driver: &str, context: &str, err: reqwest::Error) -> TokimoVfsError {
    if let Some(status) = err.status() {
        match status.as_u16() {
            404 => TokimoVfsError::NotFound(format!("{driver} {context}: {err}")),
            401 | 403 => TokimoVfsError::ConnectionError(format!("{driver} {context}: {err}")),
            _ => TokimoVfsError::Other(format!("{driver} {context}: {err}")),
        }
    } else if err.is_connect() || err.is_timeout() {
        TokimoVfsError::ConnectionError(format!("{driver} {context}: {err}"))
    } else {
        TokimoVfsError::Other(format!("{driver} {context}: {err}"))
    }
}

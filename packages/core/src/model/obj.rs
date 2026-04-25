use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 文件系统中的一个条目（文件或目录）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: Option<DateTime<Utc>>,
}

/// `Driver::link()` 的返回值。
/// - `url` 非空 → 客户端/代理直接请求该 URL
/// - `url` 为空 → 必须经本服务代理转发（`header` 中可附加签名等）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Link {
    /// 下载直链（可选）
    pub url: Option<String>,
    /// 附加到下游请求的头（如 Authorization、Cookie）
    pub header: std::collections::HashMap<String, String>,
    /// 过期时间（None = 永久有效）
    pub expiry: Option<DateTime<Utc>>,
}

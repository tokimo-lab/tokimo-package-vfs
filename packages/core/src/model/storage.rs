use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Connected,
    Error,
}

/// 能力标志 — 驱动通过设置这些字段声明支持哪些操作。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapabilities {
    pub list: bool,
    pub read: bool,
    pub mkdir: bool,
    pub delete_file: bool,
    pub delete_dir: bool,
    pub rename: bool,
    pub write: bool,
    pub symlink: bool,
    pub range_read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatus {
    pub driver: String,
    pub state: ConnectionState,
    pub error: Option<String>,
    pub capabilities: StorageCapabilities,
}

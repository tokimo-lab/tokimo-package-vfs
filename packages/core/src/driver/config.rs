use crate::driver::traits::Driver;
use crate::error::Result;

/// 驱动静态元信息。
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    /// 驱动唯一标识，如 "smb"、"s3"、"local"
    pub name: &'static str,
    /// 人类可读描述
    pub description: &'static str,
}

/// 驱动工厂 — 元信息 + 构造函数。
///
/// `create` 接收 JSON 配置（含驱动专属字段，如 host/share/username）
/// 并返回 `Box<dyn Driver>`。
///
/// 每个驱动在模块底部调用 `inventory::submit!(DriverFactory { ... })` 自注册。
pub struct DriverFactory {
    pub config: DriverConfig,
    pub create: fn(params: &serde_json::Value) -> Result<Box<dyn Driver>>,
}

inventory::collect!(DriverFactory);

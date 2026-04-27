use crate::driver::config::DriverFactory;
use crate::driver::traits::Driver;
use crate::error::{Result, TokimoVfsError};

/// 全局驱动注册表。
///
/// 驱动通过 `inventory::submit!` 自动注册，无需手动调用 `register_all()`。
/// 只要驱动模块被编译进 crate，就会自动出现在注册表中。
#[derive(Default)]
pub struct DriverRegistry;

impl DriverRegistry {
    pub fn new() -> Self {
        Self
    }

    /// 按名称 + JSON 配置创建驱动实例。
    pub fn create(&self, name: &str, params: &serde_json::Value) -> Result<Box<dyn Driver>> {
        inventory::iter::<DriverFactory>()
            .find(|f| f.config.name == name)
            .ok_or_else(|| {
                TokimoVfsError::DriverNotFound(format!("未知驱动 '{}'; 已注册：{:?}", name, self.registered()))
            })
            .and_then(|f| (f.create)(params))
    }

    /// 列出所有已注册的驱动名称。
    pub fn registered(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = inventory::iter::<DriverFactory>().map(|f| f.config.name).collect();
        names.sort_unstable();
        names
    }
}

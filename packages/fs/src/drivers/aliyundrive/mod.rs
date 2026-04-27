mod types;

use std::collections::HashMap;
use std::path::Path;

use super::reqwest_err;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use reqwest::header::{AUTHORIZATION, RANGE, USER_AGENT};
use tokio::sync::{RwLock, mpsc::Sender};
use tracing::error;

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{Driver, Meta, Reader};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};
use types::{
    AliyunEntry, DownloadRequest, DownloadResponse, FileListResponse, TokenResponse, UserResponse, api_error,
    normalize_display_path, to_file_info,
};

const DRIVER_NAME: &str = "aliyundrive";
const TOKEN_URL: &str = "https://auth.alipan.com/v2/account/token";
const USER_URL: &str = "https://api.alipan.com/v2/user/get";
const LIST_URL: &str = "https://api.alipan.com/adrive/v3/file/list";
const DOWNLOAD_URL: &str = "https://api.alipan.com/v2/file/get_download_url";
const DEFAULT_ROOT_FOLDER_ID: &str = "root";
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

pub const CONFIG: DriverConfig = DriverConfig {
    name: DRIVER_NAME,
    description: "Aliyun drive",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

#[derive(Clone)]
struct AliyunParams {
    refresh_token: String,
    root_folder_id: String,
    order_by: String,
    order_direction: String,
    user_agent: String,
}

pub struct AliyunDriveDriver {
    client: reqwest::Client,
    params: AliyunParams,
    caps: StorageCapabilities,
    access_token: RwLock<Option<String>>,
    drive_id: RwLock<Option<String>>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let refresh_token = require_non_empty(params, "refresh_token")?.to_string();
    let root_folder_id =
        optional_non_empty(params, "root_folder_id").unwrap_or_else(|| DEFAULT_ROOT_FOLDER_ID.to_string());
    let order_by = optional_non_empty(params, "order_by").unwrap_or_else(|| "name".to_string());
    let order_direction = optional_non_empty(params, "order_direction").unwrap_or_else(|| "ASC".to_string());
    let user_agent = optional_non_empty(params, "user_agent").unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

    let client = reqwest::Client::builder()
        .build()
        .map_err(|err| TokimoVfsError::ConnectionError(format!("aliyundrive client init failed: {err}")))?;

    let caps = StorageCapabilities {
        list: true,
        read: true,
        mkdir: false,
        delete_file: false,
        delete_dir: false,
        rename: false,
        write: false,
        symlink: false,
        range_read: true,
    };

    Ok(Box::new(AliyunDriveDriver {
        client,
        params: AliyunParams {
            refresh_token,
            root_folder_id,
            order_by,
            order_direction,
            user_agent,
        },
        caps,
        access_token: RwLock::new(None),
        drive_id: RwLock::new(None),
    }))
}

#[async_trait]
impl Meta for AliyunDriveDriver {
    fn driver_name(&self) -> &'static str {
        DRIVER_NAME
    }

    async fn init(&self) -> Result<()> {
        let _ = self.authenticate().await?;
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        match self.authenticate().await {
            Ok(_) => StorageStatus {
                driver: DRIVER_NAME.to_string(),
                state: ConnectionState::Connected,
                error: None,
                capabilities: self.capabilities(),
            },
            Err(err) => StorageStatus {
                driver: DRIVER_NAME.to_string(),
                state: ConnectionState::Error,
                error: Some(err.to_string()),
                capabilities: self.capabilities(),
            },
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        self.caps.clone()
    }
}

#[async_trait]
impl Reader for AliyunDriveDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let folder_id = self.resolve_dir_id(path).await?;
        let entries = self.list_directory(&folder_id).await?;
        Ok(entries.into_iter().map(|entry| to_file_info(path, &entry)).collect())
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        let display_path = normalize_display_path(path);
        if display_path == "/" {
            return Ok(FileInfo {
                name: String::new(),
                path: "/".into(),
                size: 0,
                is_dir: true,
                modified: None,
            });
        }

        let entry = self.resolve_entry(path).await?;
        Ok(FileInfo {
            name: entry.name,
            path: display_path,
            size: if entry.is_dir { 0 } else { entry.size },
            is_dir: entry.is_dir,
            modified: entry.modified,
        })
    }

    async fn link(&self, path: &Path) -> Result<Link> {
        let entry = self.resolve_entry(path).await?;
        if entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "aliyundrive path is a directory: {}",
                path.display()
            )));
        }

        let url = self.fetch_download_url(&entry.id).await?;
        Ok(Link {
            url: Some(url),
            header: HashMap::new(),
            expiry: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let link = self.link(path).await?;
        let url = link
            .url
            .ok_or_else(|| TokimoVfsError::Other("aliyundrive link did not return a URL".into()))?;

        let mut request = self.client.get(url);
        if let Some(range_header) = build_range_header(offset, limit) {
            request = request.header(RANGE, range_header);
        }

        let response = request
            .send()
            .await
            .map_err(|err| reqwest_err("aliyundrive", "read request", err))?;
        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("aliyundrive", "read response", err))?;

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| reqwest_err("aliyundrive", "read body", err))
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let result = async {
            let link = self.link(path).await?;
            let url = link
                .url
                .ok_or_else(|| TokimoVfsError::Other("aliyundrive link did not return a URL".into()))?;

            let mut request = self.client.get(url);
            if let Some(range_header) = build_range_header(offset, limit) {
                request = request.header(RANGE, range_header);
            }

            let response = request
                .send()
                .await
                .map_err(|err| reqwest_err("aliyundrive", "stream request", err))?;
            let response = response
                .error_for_status()
                .map_err(|err| reqwest_err("aliyundrive", "stream response", err))?;

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream
                .try_next()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("aliyundrive stream read failed: {err}")))?
            {
                if tx.send(chunk.to_vec()).await.is_err() {
                    break;
                }
            }
            Ok::<(), TokimoVfsError>(())
        }
        .await;

        if let Err(err) = result {
            error!("aliyundrive stream_to failed: {err}");
        }
    }
}

impl AliyunDriveDriver {
    async fn authenticate(&self) -> Result<(String, String)> {
        let access_token = self.token().await?;
        let drive_id = if let Some(drive_id) = self.drive_id.read().await.clone() {
            drive_id
        } else {
            let drive_id = self.fetch_drive_id(&access_token).await?;
            *self.drive_id.write().await = Some(drive_id.clone());
            drive_id
        };
        Ok((access_token, drive_id))
    }

    async fn token(&self) -> Result<String> {
        if let Some(token) = self.access_token.read().await.clone() {
            return Ok(token);
        }

        let response = self
            .client
            .post(TOKEN_URL)
            .json(&serde_json::json!({
                "refresh_token": self.params.refresh_token,
                "grant_type": "refresh_token",
            }))
            .send()
            .await
            .map_err(|err| TokimoVfsError::ConnectionError(format!("aliyundrive token refresh failed: {err}")))?;
        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("aliyundrive", "token refresh", err))?;
        let data: TokenResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive token decode failed: {err}")))?;
        if data.access_token.is_empty() {
            return Err(api_error(
                "aliyundrive token refresh failed",
                data.message.or(data.msg).or(data.error),
                data.code.as_deref(),
            ));
        }

        *self.access_token.write().await = Some(data.access_token.clone());
        Ok(data.access_token)
    }

    async fn fetch_drive_id(&self, token: &str) -> Result<String> {
        let response = self
            .client
            .post(USER_URL)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(USER_AGENT, &self.params.user_agent)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive user request failed: {err}")))?;
        let response = response
            .error_for_status()
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive user response failed: {err}")))?;
        let data: UserResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive user decode failed: {err}")))?;

        data.drive_id()
            .ok_or_else(|| TokimoVfsError::Other("aliyundrive did not return a drive_id".into()))
    }

    async fn resolve_dir_id(&self, path: &Path) -> Result<String> {
        if normalize_display_path(path) == "/" {
            return Ok(self.params.root_folder_id.clone());
        }
        let entry = self.resolve_entry(path).await?;
        if !entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "aliyundrive path is not a directory: {}",
                path.display()
            )));
        }
        Ok(entry.id)
    }

    async fn resolve_entry(&self, path: &Path) -> Result<AliyunEntry> {
        let mut current_dir_id = self.params.root_folder_id.clone();
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Ok(AliyunEntry {
                id: current_dir_id,
                name: String::new(),
                size: 0,
                is_dir: true,
                modified: None,
            });
        }

        let last_index = segments.len() - 1;
        for (index, segment) in segments.iter().enumerate() {
            let entry = self
                .list_directory(&current_dir_id)
                .await?
                .into_iter()
                .find(|item| item.name == *segment)
                .ok_or_else(|| TokimoVfsError::NotFound(format!("aliyundrive path not found: {}", path.display())))?;

            if index == last_index {
                return Ok(entry);
            }
            if !entry.is_dir {
                return Err(TokimoVfsError::NotFound(format!(
                    "aliyundrive parent is not a directory: {}",
                    path.display()
                )));
            }
            current_dir_id = entry.id;
        }

        Err(TokimoVfsError::NotFound(format!(
            "aliyundrive path not found: {}",
            path.display()
        )))
    }

    async fn list_directory(&self, folder_id: &str) -> Result<Vec<AliyunEntry>> {
        let (access_token, drive_id) = self.authenticate().await?;
        let response = self
            .client
            .post(LIST_URL)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(USER_AGENT, &self.params.user_agent)
            .json(&serde_json::json!({
                "drive_id": drive_id,
                "parent_file_id": folder_id,
                "limit": 200,
                "order_by": self.params.order_by,
                "order_direction": self.params.order_direction,
                "fields": "*",
            }))
            .send()
            .await
            .map_err(|err| reqwest_err("aliyundrive", "list request", err))?;
        let response = response
            .error_for_status()
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive list response failed: {err}")))?;
        let page: FileListResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive list decode failed: {err}")))?;
        if page.code.as_deref().is_some_and(|code| !code.is_empty()) {
            return Err(api_error("aliyundrive list failed", page.message, page.code.as_deref()));
        }
        Ok(page.items.into_iter().map(AliyunEntry::from).collect())
    }

    async fn fetch_download_url(&self, file_id: &str) -> Result<String> {
        let (access_token, drive_id) = self.authenticate().await?;
        let response = self
            .client
            .post(DOWNLOAD_URL)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(USER_AGENT, &self.params.user_agent)
            .json(&DownloadRequest {
                drive_id: &drive_id,
                file_id,
                expire_sec: 14_400,
            })
            .send()
            .await
            .map_err(|err| reqwest_err("aliyundrive", "download request", err))?;
        let response = response
            .error_for_status()
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive download response failed: {err}")))?;
        let data: DownloadResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("aliyundrive download decode failed: {err}")))?;
        if data.url.is_empty() {
            return Err(api_error(
                "aliyundrive download link failed",
                data.message,
                data.code.as_deref(),
            ));
        }
        Ok(data.url)
    }
}

fn require_non_empty<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("aliyundrive driver is missing '{key}'")))
}

fn optional_non_empty(params: &serde_json::Value, key: &str) -> Option<String> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn collect_segments(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn build_range_header(offset: u64, limit: Option<u64>) -> Option<String> {
    if offset == 0 && limit.is_none() {
        return None;
    }
    Some(match limit {
        Some(length) if length > 0 => {
            format!("bytes={offset}-{}", offset.saturating_add(length).saturating_sub(1))
        }
        Some(_) => format!("bytes={offset}-{offset}"),
        None => format!("bytes={offset}-"),
    })
}

impl Driver for AliyunDriveDriver {}

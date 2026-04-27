mod types;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::reqwest_err;
use async_trait::async_trait;
use futures_util::TryStreamExt;
use reqwest::header::{RANGE, USER_AGENT};
use tokio::sync::{RwLock, mpsc::Sender};
use tracing::{error, info};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    ConfigPersister, CopyFile, DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, Reader, Rename,
};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};
use types::{
    BaiduEntry, CreateResponse, DownloadMetaResponse, ListResponse, ManageResponse, TokenResponse, api_error,
    normalize_display_path, to_file_info,
};

const DRIVER_NAME: &str = "baidu_netdisk";
const OFFICIAL_TOKEN_URL: &str = "https://openapi.baidu.com/oauth/2.0/token";
const ONLINE_TOKEN_URL: &str = "https://api.oplist.org/baiduyun/renewapi";
const LIST_URL: &str = "https://pan.baidu.com/rest/2.0/xpan/file";
const DOWNLOAD_META_URL: &str = "https://pan.baidu.com/rest/2.0/xpan/multimedia";
const DEFAULT_ROOT_FOLDER_PATH: &str = "/";
const DEFAULT_USER_AGENT: &str = "pan.baidu.com";

pub const CONFIG: DriverConfig = DriverConfig {
    name: DRIVER_NAME,
    description: "Baidu netdisk",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

#[derive(Clone)]
struct BaiduParams {
    client_id: Option<String>,
    client_secret: Option<String>,
    root_folder_path: String,
    order_by: String,
    order_direction: String,
    user_agent: String,
}

pub struct BaiduNetdiskDriver {
    client: reqwest::Client,
    params: BaiduParams,
    caps: StorageCapabilities,
    access_token: RwLock<Option<String>>,
    /// Expiry instant for the cached access token.  Cleared alongside the
    /// token so we re-fetch before Baidu rejects it.
    access_token_expires_at: RwLock<Option<Instant>>,
    /// Tracks the latest refresh token in memory (Baidu rotates it on every
    /// use).  Stored separately from `params` so the persister can detect
    /// changes.
    current_refresh_token: RwLock<String>,
    /// Injected by `SourceRegistry` before `init()`.  Called fire-and-forget
    /// whenever the refresh token rotates, equivalent to OpenList's
    /// `op.MustSaveDriverStorage`.
    persister: OnceLock<ConfigPersister>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let refresh_token = require_non_empty(params, "refresh_token")?.to_string();
    let root_folder_path =
        optional_non_empty(params, "root_folder_path").unwrap_or_else(|| DEFAULT_ROOT_FOLDER_PATH.to_string());
    let order_by = optional_non_empty(params, "order_by").unwrap_or_else(|| "name".to_string());
    let order_direction = optional_non_empty(params, "order_direction").unwrap_or_else(|| "asc".to_string());
    let user_agent = optional_non_empty(params, "user_agent").unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

    let client = reqwest::Client::builder()
        .build()
        .map_err(|err| TokimoVfsError::ConnectionError(format!("baidu client init failed: {err}")))?;

    let caps = StorageCapabilities {
        list: true,
        read: true,
        mkdir: true,
        delete_file: true,
        delete_dir: true,
        rename: true,
        write: false,
        symlink: false,
        range_read: true,
    };

    Ok(Box::new(BaiduNetdiskDriver {
        client,
        params: BaiduParams {
            client_id: optional_non_empty(params, "client_id"),
            client_secret: optional_non_empty(params, "client_secret"),
            root_folder_path: normalize_root_path(&root_folder_path),
            order_by,
            order_direction,
            user_agent,
        },
        caps,
        access_token: RwLock::new(None),
        access_token_expires_at: RwLock::new(None),
        current_refresh_token: RwLock::new(refresh_token),
        persister: OnceLock::new(),
    }))
}

#[async_trait]
impl Meta for BaiduNetdiskDriver {
    fn driver_name(&self) -> &'static str {
        DRIVER_NAME
    }

    async fn init(&self) -> Result<()> {
        let _ = self.token().await?;
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        match self.token().await {
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

    fn set_config_persister(&self, persister: ConfigPersister) {
        let _ = self.persister.set(persister);
    }
}

#[async_trait]
impl Reader for BaiduNetdiskDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let remote_path = self.remote_path(path);
        let entries = self.list_directory(&remote_path).await?;
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
                "baidu_netdisk path is a directory: {}",
                path.display()
            )));
        }
        let url = self.fetch_download_url(&entry.id).await?;
        let mut headers = HashMap::new();
        headers.insert("User-Agent".into(), self.params.user_agent.clone());
        Ok(Link {
            url: Some(url),
            header: headers,
            expiry: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let link = self.link(path).await?;
        let url = link
            .url
            .ok_or_else(|| TokimoVfsError::Other("baidu link did not return a URL".into()))?;
        let mut request = self.client.get(url).header(USER_AGENT, &self.params.user_agent);
        if let Some(range_header) = build_range_header(offset, limit) {
            request = request.header(RANGE, range_header);
        }
        let response = request
            .send()
            .await
            .map_err(|err| reqwest_err("baidu", "read request", err))?;
        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("baidu", "read response", err))?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| reqwest_err("baidu", "read body", err))
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let result = async {
            let link = self.link(path).await?;
            let url = link
                .url
                .ok_or_else(|| TokimoVfsError::Other("baidu link did not return a URL".into()))?;

            let mut request = self.client.get(url).header(USER_AGENT, &self.params.user_agent);
            if let Some(range_header) = build_range_header(offset, limit) {
                request = request.header(RANGE, range_header);
            }

            let response = request
                .send()
                .await
                .map_err(|err| reqwest_err("baidu", "stream request", err))?;
            let response = response
                .error_for_status()
                .map_err(|err| reqwest_err("baidu", "stream response", err))?;

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream
                .try_next()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("baidu stream read failed: {err}")))?
            {
                if tx.send(chunk.to_vec()).await.is_err() {
                    break;
                }
            }
            Ok::<(), TokimoVfsError>(())
        }
        .await;

        if let Err(err) = result {
            error!("baidu stream_to failed: {err}");
        }
    }
}

impl BaiduNetdiskDriver {
    async fn token(&self) -> Result<String> {
        {
            let token = self.access_token.read().await;
            let expires_at = self.access_token_expires_at.read().await;
            if let (Some(t), Some(exp)) = (token.as_ref(), expires_at.as_ref())
                && Instant::now() + Duration::from_mins(5) < *exp
            {
                return Ok(t.clone());
            }
        }

        let refresh_token = self.current_refresh_token.read().await.clone();

        // Try up to twice (OpenList retries once on empty token).
        let data = self.do_refresh_token(&refresh_token).await?;
        let data = if data.access_token.is_empty() {
            info!("baidu token was empty on first try, retrying once");
            let rt = self.current_refresh_token.read().await.clone();
            self.do_refresh_token(&rt).await?
        } else {
            data
        };

        if data.access_token.is_empty() {
            return Err(TokimoVfsError::ConnectionError(
                data.error_description
                    .or(data.text)
                    .or(data.error)
                    .unwrap_or_else(|| "baidu token refresh returned empty token".to_string()),
            ));
        }

        // Baidu rotates the refresh token on every use — persist the new one
        // immediately (like OpenList's MustSaveDriverStorage).
        if !data.refresh_token.is_empty() && data.refresh_token != refresh_token {
            *self.current_refresh_token.write().await = data.refresh_token.clone();
            if let Some(persister) = self.persister.get() {
                persister(serde_json::json!({ "refresh_token": data.refresh_token }));
            } else {
                tracing::warn!("baidu persister not set — refresh_token rotation will be lost on restart");
            }
        } else if data.refresh_token.is_empty() {
            tracing::warn!("baidu token refresh returned empty refresh_token — rotation not persisted");
        }

        let expires_in = if data.expires_in > 0 {
            data.expires_in as u64
        } else {
            2_592_000 // 30 days default
        };
        *self.access_token.write().await = Some(data.access_token.clone());
        *self.access_token_expires_at.write().await = Some(Instant::now() + Duration::from_secs(expires_in));
        Ok(data.access_token)
    }

    /// Perform the actual HTTP token refresh without any caching logic.
    async fn do_refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let response = if let (Some(client_id), Some(client_secret)) =
            (&self.params.client_id, &self.params.client_secret)
        {
            self.client
                .get(OFFICIAL_TOKEN_URL)
                .query(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                ])
                .send()
                .await
                .map_err(|err| TokimoVfsError::ConnectionError(format!("baidu token refresh failed: {err}")))?
        } else {
            self.client
                .get(ONLINE_TOKEN_URL)
                .query(&[
                    ("refresh_ui", refresh_token),
                    ("server_use", "true"),
                    ("driver_txt", "baiduyun_go"),
                ])
                .send()
                .await
                .map_err(|err| TokimoVfsError::ConnectionError(format!("baidu online token refresh failed: {err}")))?
        };

        // Read the body before checking the status so we can surface the
        // exact Baidu error (e.g. "invalid_grant") rather than just HTTP 400.
        let status = response.status();
        let data: TokenResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("baidu token decode failed: {err}")))?;
        if !status.is_success() && data.access_token.is_empty() {
            let detail = data
                .error_description
                .clone()
                .or_else(|| data.text.clone())
                .or_else(|| data.error.clone());
            let msg = if let Some(desc) = detail {
                format!("baidu token refresh: {status} {desc}")
            } else {
                format!("baidu token refresh: {status}")
            };
            return Err(TokimoVfsError::ConnectionError(msg));
        }
        Ok(data)
    }

    /// Invalidate the cached access token so the next call to `token()` will
    /// exchange a fresh one.  Called when an API response signals the token
    /// has expired (errno -6 / 111).
    async fn invalidate_token(&self) {
        *self.access_token.write().await = None;
        *self.access_token_expires_at.write().await = None;
    }

    fn remote_path(&self, path: &Path) -> String {
        let logical = normalize_display_path(path);
        if logical == "/" {
            return self.params.root_folder_path.clone();
        }
        if self.params.root_folder_path == "/" {
            return logical;
        }
        format!(
            "{}/{}",
            self.params.root_folder_path.trim_end_matches('/'),
            logical.trim_start_matches('/')
        )
    }

    async fn resolve_entry(&self, path: &Path) -> Result<BaiduEntry> {
        let remote_path = self.remote_path(path);
        let parent = parent_remote_path(&remote_path);
        let file_name = Path::new(&remote_path)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .ok_or_else(|| TokimoVfsError::NotFound(format!("baidu path not found: {}", path.display())))?;
        self.list_directory(&parent)
            .await?
            .into_iter()
            .find(|entry| entry.name == file_name)
            .ok_or_else(|| TokimoVfsError::NotFound(format!("baidu path not found: {}", path.display())))
    }

    async fn list_directory(&self, remote_path: &str) -> Result<Vec<BaiduEntry>> {
        let token = self.token().await?;
        let desc = if self.params.order_direction.eq_ignore_ascii_case("desc") {
            "1"
        } else {
            "0"
        };
        let page: ListResponse = self
            .client
            .get(LIST_URL)
            .query(&[
                ("method", "list"),
                ("dir", remote_path),
                ("order", self.params.order_by.as_str()),
                ("desc", desc),
                ("start", "0"),
                ("limit", "200"),
                ("access_token", token.as_str()),
            ])
            .send()
            .await
            .map_err(|err| reqwest_err("baidu", "list request", err))?
            .error_for_status()
            .map_err(|err| reqwest_err("baidu", "list response", err))?
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("baidu list decode failed: {err}")))?;

        // errno -6 / 111 → access token expired; refresh and retry once.
        if matches!(page.errno, -6 | 111) {
            info!("baidu list errno={}, refreshing token and retrying", page.errno);
            self.invalidate_token().await;
            let token = self.token().await?;
            let page: ListResponse = self
                .client
                .get(LIST_URL)
                .query(&[
                    ("method", "list"),
                    ("dir", remote_path),
                    ("order", self.params.order_by.as_str()),
                    ("desc", desc),
                    ("start", "0"),
                    ("limit", "200"),
                    ("access_token", token.as_str()),
                ])
                .send()
                .await
                .map_err(|err| reqwest_err("baidu", "list retry request", err))?
                .error_for_status()
                .map_err(|err| reqwest_err("baidu", "list retry response", err))?
                .json()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("baidu list retry decode failed: {err}")))?;
            if page.errno != 0 {
                return Err(api_error("baidu list failed", None, page.errno));
            }
            return Ok(page.list.into_iter().map(BaiduEntry::from).collect());
        }

        if page.errno != 0 {
            return Err(api_error("baidu list failed", None, page.errno));
        }
        Ok(page.list.into_iter().map(BaiduEntry::from).collect())
    }

    async fn fetch_download_url(&self, fs_id: &str) -> Result<String> {
        let token = self.token().await?;
        let fsids = format!("[{fs_id}]");
        let data: DownloadMetaResponse = self
            .client
            .get(DOWNLOAD_META_URL)
            .query(&[
                ("method", "filemetas"),
                ("fsids", fsids.as_str()),
                ("dlink", "1"),
                ("access_token", token.as_str()),
            ])
            .send()
            .await
            .map_err(|err| reqwest_err("baidu", "download request", err))?
            .error_for_status()
            .map_err(|err| TokimoVfsError::Other(format!("baidu download response failed: {err}")))?
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("baidu download decode failed: {err}")))?;

        // errno -6 / 111 → access token expired; refresh and retry once.
        if matches!(data.errno, -6 | 111) {
            info!("baidu dlink errno={}, refreshing token and retrying", data.errno);
            self.invalidate_token().await;
            let token = self.token().await?;
            let data: DownloadMetaResponse = self
                .client
                .get(DOWNLOAD_META_URL)
                .query(&[
                    ("method", "filemetas"),
                    ("fsids", fsids.as_str()),
                    ("dlink", "1"),
                    ("access_token", token.as_str()),
                ])
                .send()
                .await
                .map_err(|err| reqwest_err("baidu", "download retry request", err))?
                .error_for_status()
                .map_err(|err| TokimoVfsError::Other(format!("baidu download retry response failed: {err}")))?
                .json()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("baidu download retry decode failed: {err}")))?;
            if data.errno != 0 {
                return Err(api_error("baidu download link failed", None, data.errno));
            }
            return data
                .list
                .into_iter()
                .find_map(|item| (!item.dlink.is_empty()).then_some(item.dlink))
                .map(|dlink| format!("{dlink}&access_token={token}"))
                .ok_or_else(|| TokimoVfsError::Other("baidu download payload did not contain a dlink".into()));
        }

        if data.errno != 0 {
            return Err(api_error("baidu download link failed", None, data.errno));
        }
        let dlink = data
            .list
            .into_iter()
            .find_map(|item| (!item.dlink.is_empty()).then_some(item.dlink))
            .ok_or_else(|| TokimoVfsError::Other("baidu download payload did not contain a dlink".into()))?;
        Ok(format!("{dlink}&access_token={token}"))
    }

    /// POST /xpan/file?method=filemanager&opera={opera}
    /// `filelist_json` is a pre-serialized JSON array.
    async fn manage_op(&self, opera: &str, filelist_json: &str) -> Result<()> {
        let token = self.token().await?;
        let resp = self.do_manage(opera, filelist_json, &token).await?;
        if matches!(resp.errno, -6 | 111) {
            info!(
                "baidu manage/{opera} errno={}, refreshing token and retrying",
                resp.errno
            );
            self.invalidate_token().await;
            let token = self.token().await?;
            let resp = self.do_manage(opera, filelist_json, &token).await?;
            return check_manage_resp(&resp, opera);
        }
        check_manage_resp(&resp, opera)
    }

    async fn do_manage(&self, opera: &str, filelist_json: &str, token: &str) -> Result<ManageResponse> {
        self.client
            .post(LIST_URL)
            .query(&[("method", "filemanager"), ("opera", opera), ("access_token", token)])
            .form(&[("async", "0"), ("ondup", "fail"), ("filelist", filelist_json)])
            .send()
            .await
            .map_err(|err| reqwest_err("baidu", opera, err))?
            .error_for_status()
            .map_err(|err| reqwest_err("baidu", opera, err))?
            .json::<ManageResponse>()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("baidu {opera} decode failed: {err}")))
    }

    /// POST /xpan/file?method=create to create a directory.
    async fn api_create_dir(&self, remote_path: &str) -> Result<()> {
        let token = self.token().await?;
        let resp = self.do_create_dir(remote_path, &token).await?;
        if matches!(resp.errno, -6 | 111) {
            info!("baidu mkdir errno={}, refreshing token and retrying", resp.errno);
            self.invalidate_token().await;
            let token = self.token().await?;
            let resp = self.do_create_dir(remote_path, &token).await?;
            if resp.errno != 0 {
                return Err(api_error("baidu mkdir failed", None, resp.errno));
            }
            return Ok(());
        }
        if resp.errno != 0 {
            return Err(api_error("baidu mkdir failed", None, resp.errno));
        }
        Ok(())
    }

    async fn do_create_dir(&self, remote_path: &str, token: &str) -> Result<CreateResponse> {
        self.client
            .post(LIST_URL)
            .query(&[("method", "create"), ("access_token", token)])
            .form(&[("path", remote_path), ("size", "0"), ("isdir", "1"), ("rtype", "3")])
            .send()
            .await
            .map_err(|err| reqwest_err("baidu", "mkdir request", err))?
            .error_for_status()
            .map_err(|err| reqwest_err("baidu", "mkdir response", err))?
            .json::<CreateResponse>()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("baidu mkdir decode failed: {err}")))
    }
}

fn require_non_empty<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("baidu driver is missing '{key}'")))
}

fn optional_non_empty(params: &serde_json::Value, key: &str) -> Option<String> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalize_root_path(path: &str) -> String {
    let path = if path.trim().is_empty() { "/" } else { path.trim() };
    if path.starts_with('/') {
        path.trim_end_matches('/').to_string().if_empty("/")
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() { fallback.to_string() } else { self }
    }
}

fn parent_remote_path(path: &str) -> String {
    let path = PathBuf::from(path);
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let text = parent.to_string_lossy();
    if text.is_empty() {
        "/".to_string()
    } else if text.starts_with('/') {
        text.into_owned()
    } else {
        format!("/{text}")
    }
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

fn check_manage_resp(resp: &ManageResponse, opera: &str) -> Result<()> {
    if resp.errno != 0 {
        return Err(api_error(&format!("baidu {opera} failed"), None, resp.errno));
    }
    for item in &resp.info {
        if item.errno != 0 {
            return Err(api_error(&format!("baidu {opera} item failed"), None, item.errno));
        }
    }
    Ok(())
}

#[async_trait]
impl Mkdir for BaiduNetdiskDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let remote = self.remote_path(path);
        self.api_create_dir(&remote).await
    }
}

#[async_trait]
impl DeleteFile for BaiduNetdiskDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let remote = self.remote_path(path);
        let filelist = serde_json::json!([remote]).to_string();
        self.manage_op("delete", &filelist).await
    }
}

#[async_trait]
impl DeleteDir for BaiduNetdiskDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let remote = self.remote_path(path);
        let filelist = serde_json::json!([remote]).to_string();
        self.manage_op("delete", &filelist).await
    }
}

#[async_trait]
impl Rename for BaiduNetdiskDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let remote_from = self.remote_path(from);
        let new_name = to
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| TokimoVfsError::Other("baidu rename: empty target name".into()))?;

        let from_parent = from.parent().unwrap_or_else(|| Path::new("/"));
        let to_parent = to.parent().unwrap_or_else(|| Path::new("/"));
        let remote_from_parent = self.remote_path(from_parent);
        let remote_to_parent = self.remote_path(to_parent);

        if remote_from_parent == remote_to_parent {
            // Same directory — pure rename.
            let filelist = serde_json::json!([{"path": remote_from, "newname": new_name}]).to_string();
            self.manage_op("rename", &filelist).await
        } else {
            // Different directory — move and rename in one shot.
            let filelist = serde_json::json!([{
                "path": remote_from,
                "dest": remote_to_parent,
                "newname": new_name,
            }])
            .to_string();
            self.manage_op("move", &filelist).await
        }
    }
}

#[async_trait]
impl MoveFile for BaiduNetdiskDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let remote_from = self.remote_path(from);
        let remote_to_dir = self.remote_path(to_dir);
        let file_name = from
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| TokimoVfsError::Other("baidu move: source has no filename".into()))?;
        let filelist = serde_json::json!([{
            "path": remote_from,
            "dest": remote_to_dir,
            "newname": file_name,
        }])
        .to_string();
        self.manage_op("move", &filelist).await
    }
}

#[async_trait]
impl CopyFile for BaiduNetdiskDriver {
    async fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        let remote_from = self.remote_path(from);
        let to_parent = to.parent().unwrap_or_else(|| Path::new("/"));
        let remote_to_dir = self.remote_path(to_parent);
        let new_name = to
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| TokimoVfsError::Other("baidu copy: empty destination name".into()))?;
        let filelist = serde_json::json!([{
            "path": remote_from,
            "dest": remote_to_dir,
            "newname": new_name,
        }])
        .to_string();
        self.manage_op("copy", &filelist).await
    }
}

impl Driver for BaiduNetdiskDriver {
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
}

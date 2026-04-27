mod types;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use super::reqwest_err;

use async_trait::async_trait;
use base64::Engine;
use futures_util::TryStreamExt;
use md5::Md5;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, RANGE, REFERER, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::{Method, RequestBuilder};
use serde::de::DeserializeOwned;
use sha1::Sha1;
use sha1::digest::Digest;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    ConfigPersister, DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutFile, PutStream, Reader, Rename,
};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};
use types::{
    ApiResponse, CreateFolderRequest, CreateFolderResponse, DeleteRequest, DownloadRequest, DownloadResponse,
    MoveRequest, QuarkEntry, RenameRequest, SortResponse, UpAuthRequest, UpAuthResp, UpFinishRequest, UpHashRequest,
    UpHashResp, UpPreRequest, UpPreResp, api_error, normalize_display_path, to_file_info,
};

const DRIVER_NAME: &str = "quark";
const API_BASE: &str = "https://drive.quark.cn/1/clouddrive";
const REFERER_URL: &str = "https://pan.quark.cn";
const DEFAULT_ROOT_FOLDER_ID: &str = "0";
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch";
const ACCEPT_VALUE: &str = "application/json, text/plain, */*";
const PR: &str = "ucpro";
const FR: &str = "pc";

pub const CONFIG: DriverConfig = DriverConfig {
    name: DRIVER_NAME,
    description: "Quark drive",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

#[derive(Clone)]
struct QuarkParams {
    /// Cookie string, protected by `RwLock` for passive refresh (like `OpenList`)
    cookie: Arc<RwLock<String>>,
    root_folder_id: String,
    order_by: String,
    order_direction: String,
    user_agent: String,
}

pub struct QuarkDriver {
    /// Client for API requests
    api_client: reqwest::Client,
    /// Client for download requests (no auto-redirect, handles CDN manually)
    download_client: reqwest::Client,
    params: QuarkParams,
    caps: StorageCapabilities,
    /// Cache for recently created directory IDs (path → fid).
    /// Quark API has eventual consistency — a newly created folder may not
    /// appear in directory listings immediately. This cache bridges the gap.
    dir_cache: RwLock<HashMap<String, String>>,
    /// Injected by `SourceRegistry` before `init()`. Called fire-and-forget
    /// whenever the cookie is refreshed, equivalent to OpenList's
    /// `op.MustSaveDriverStorage`.
    persister: OnceLock<ConfigPersister>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let cookie = require_non_empty(params, "cookie")?.to_string();
    let root_folder_id =
        optional_non_empty(params, "root_folder_id").unwrap_or_else(|| DEFAULT_ROOT_FOLDER_ID.to_string());
    let order_by = optional_non_empty(params, "order_by").unwrap_or_else(|| "file_name".to_string());
    let order_direction = optional_non_empty(params, "order_direction").unwrap_or_else(|| "asc".to_string());
    let user_agent = optional_non_empty(params, "user_agent").unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

    // API client (follows redirects)
    let api_client = reqwest::Client::builder()
        .build()
        .map_err(|err| TokimoVfsError::ConnectionError(format!("quark client init failed: {err}")))?;

    // Download client: no auto-redirect - we handle CDN redirects manually
    // (CDN may reject certain headers like Referer)
    let download_client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .map_err(|err| TokimoVfsError::ConnectionError(format!("quark download client init failed: {err}")))?;

    let caps = StorageCapabilities {
        list: true,
        read: true,
        mkdir: true,
        delete_file: true,
        delete_dir: true,
        rename: true,
        write: true,
        symlink: false,
        range_read: true,
    };

    Ok(Box::new(QuarkDriver {
        api_client,
        download_client,
        params: QuarkParams {
            cookie: Arc::new(RwLock::new(cookie)),
            root_folder_id,
            order_by,
            order_direction,
            user_agent,
        },
        caps,
        dir_cache: RwLock::new(HashMap::new()),
        persister: OnceLock::new(),
    }))
}

#[async_trait]
impl Meta for QuarkDriver {
    fn driver_name(&self) -> &'static str {
        DRIVER_NAME
    }

    async fn init(&self) -> Result<()> {
        self.login_check().await
    }

    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        match self.login_check().await {
            Ok(()) => StorageStatus {
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
impl Reader for QuarkDriver {
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
                "quark path is a directory: {}",
                path.display()
            )));
        }

        let url = self.fetch_download_url(&entry.id).await?;
        let cookie = self.params.cookie.read().await.clone();
        let mut headers = HashMap::new();
        headers.insert("Cookie".into(), cookie);
        headers.insert("Referer".into(), REFERER_URL.to_string());
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
            .ok_or_else(|| TokimoVfsError::Other("quark link did not return a URL".into()))?;
        let range_header = build_range_header(offset, limit);
        let response = self.download_request(&url, range_header).await?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| reqwest_err("quark", "read body", err))
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let result = async {
            let link = self.link(path).await?;
            let url = link
                .url
                .ok_or_else(|| TokimoVfsError::Other("quark link did not return a URL".into()))?;

            let range_header = build_range_header(offset, limit);
            let response = self.download_request(&url, range_header).await?;

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream
                .try_next()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("quark stream read failed: {err}")))?
            {
                if tx.send(chunk.to_vec()).await.is_err() {
                    break;
                }
            }
            Ok::<(), TokimoVfsError>(())
        }
        .await;

        if let Err(err) = result {
            error!("quark stream_to failed: {err}");
        }
    }
}

impl QuarkDriver {
    /// Unified API request method (like `OpenList`'s request function).
    /// Handles common headers, query params, and cookie refresh.
    async fn request<T: DeserializeOwned>(
        &self,
        pathname: &str,
        method: Method,
        callback: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<T> {
        let url = format!("{API_BASE}{pathname}");
        let cookie = self.params.cookie.read().await.clone();

        let request = self
            .api_client
            .request(method, &url)
            .query(&[("pr", PR), ("fr", FR)])
            .header(COOKIE, &cookie)
            .header(ACCEPT, ACCEPT_VALUE)
            .header(REFERER, REFERER_URL)
            .header(USER_AGENT, &self.params.user_agent);

        let request = callback(request);
        let response = request
            .send()
            .await
            .map_err(|err| reqwest_err("quark", "request", err))?;

        // Cookie refresh (like OpenList: check __puus and __pus)
        self.refresh_cookie_from_response(&response).await;

        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("quark", "response", err))?;

        response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("quark response decode failed: {err}")))
    }

    /// Refresh cookie from Set-Cookie response headers (like `OpenList`).
    /// Checks for __puus and __pus cookies and updates them, then persists
    /// immediately via the injected persister (like OpenList's MustSaveDriverStorage).
    async fn refresh_cookie_from_response(&self, response: &reqwest::Response) {
        for c in response.cookies() {
            let name = c.name();
            if name == "__puus" || name == "__pus" {
                let value = c.value();
                let new_cookie = {
                    let mut cookie = self.params.cookie.write().await;
                    *cookie = set_cookie_value(&cookie, name, value);
                    cookie.clone()
                };
                info!("quark cookie refreshed: {}", name);
                if let Some(persister) = self.persister.get() {
                    persister(serde_json::json!({ "cookie": new_cookie }));
                }
            }
        }
    }

    /// Download request for CDN URLs (not using unified request method).
    /// CDN may reject Referer header, so we handle redirects manually.
    async fn download_request(&self, url: &str, range_header: Option<String>) -> Result<reqwest::Response> {
        let mut current_url = url.to_string();
        let max_redirects = 10;
        let cookie = self.params.cookie.read().await.clone();

        for redirect_count in 0..max_redirects {
            // CDN URLs don't need Referer (may cause 403)
            let is_cdn_url = !current_url.contains("drive.quark.cn") && !current_url.contains("pan.quark.cn");

            let mut request = self
                .download_client
                .get(&current_url)
                .header(COOKIE, &cookie)
                .header(USER_AGENT, &self.params.user_agent);

            // Only send Referer to Quark's own servers, not CDN
            if !is_cdn_url {
                request = request.header(REFERER, REFERER_URL);
            }

            if let Some(ref range) = range_header {
                request = request.header(RANGE, range.clone());
            }

            let response = request
                .send()
                .await
                .map_err(|err| reqwest_err("quark", "download request", err))?;

            let status = response.status();

            if status.is_redirection()
                && let Some(location) = response.headers().get("location")
            {
                let location_str = location
                    .to_str()
                    .map_err(|_| TokimoVfsError::Other("invalid redirect location".into()))?;

                current_url = if location_str.starts_with("http://") || location_str.starts_with("https://") {
                    location_str.to_string()
                } else if location_str.starts_with('/') {
                    let parsed = reqwest::Url::parse(&current_url)
                        .map_err(|e| TokimoVfsError::Other(format!("invalid url: {e}")))?;
                    format!(
                        "{}://{}{}",
                        parsed.scheme(),
                        parsed.host_str().unwrap_or(""),
                        location_str
                    )
                } else {
                    let parsed = reqwest::Url::parse(&current_url)
                        .map_err(|e| TokimoVfsError::Other(format!("invalid url: {e}")))?;
                    parsed
                        .join(location_str)
                        .map_err(|e| TokimoVfsError::Other(format!("invalid redirect: {e}")))?
                        .to_string()
                };

                debug!(
                    "quark download redirect {} -> {} (count: {})",
                    url,
                    current_url,
                    redirect_count + 1
                );
                continue;
            }

            // Not a redirect - check for errors
            if status.is_client_error() || status.is_server_error() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "failed to read body".to_string());
                error!("quark download error: {} - {}", status, error_body);
                return Err(TokimoVfsError::ConnectionError(format!(
                    "quark download failed: {status} - {error_body}"
                )));
            }

            return Ok(response);
        }

        Err(TokimoVfsError::Other("quark download: too many redirects".into()))
    }

    async fn login_check(&self) -> Result<()> {
        let data: ApiResponse = self.request("/config", Method::GET, |req| req).await?;
        if data.code == 0 {
            return Ok(());
        }
        Err(api_error(
            "quark cookie is invalid",
            data.message.or(data.msg),
            data.code,
        ))
    }

    async fn resolve_dir_id(&self, path: &Path) -> Result<String> {
        if normalize_display_path(path) == "/" {
            return Ok(self.params.root_folder_id.clone());
        }
        // Check dir_cache first (populated by mkdir) to handle eventual
        // consistency — a just-created folder may not appear in listings yet.
        let cache_key = normalize_display_path(path);
        if let Some(fid) = self.dir_cache.read().await.get(&cache_key) {
            return Ok(fid.clone());
        }
        // First attempt — may fail if the directory was just created and the
        // Quark API listing hasn't caught up yet (eventual consistency).
        match self.resolve_entry(path).await {
            Ok(entry) if entry.is_dir => Ok(entry.id),
            Ok(_) => Err(TokimoVfsError::Other(format!(
                "quark path is not a directory: {}",
                path.display()
            ))),
            Err(_) => {
                // Retry once after a short delay for eventual consistency.
                debug!("quark resolve_dir_id: retrying after delay for {}", path.display());
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                // Re-check cache in case another task populated it.
                if let Some(fid) = self.dir_cache.read().await.get(&cache_key) {
                    return Ok(fid.clone());
                }
                let entry = self.resolve_entry(path).await?;
                if !entry.is_dir {
                    return Err(TokimoVfsError::Other(format!(
                        "quark path is not a directory: {}",
                        path.display()
                    )));
                }
                Ok(entry.id)
            }
        }
    }

    async fn resolve_entry(&self, path: &Path) -> Result<QuarkEntry> {
        let mut current_dir_id = self.params.root_folder_id.clone();
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Ok(QuarkEntry {
                id: current_dir_id,
                name: String::new(),
                size: 0,
                is_dir: true,
                modified: None,
            });
        }

        let last_index = segments.len() - 1;
        let mut built_path = String::new();
        for (index, segment) in segments.iter().enumerate() {
            built_path = if built_path.is_empty() {
                format!("/{segment}")
            } else {
                format!("{built_path}/{segment}")
            };

            // For intermediate (non-last) directory segments, check the
            // dir_cache first to handle Quark API eventual consistency.
            if index < last_index
                && let Some(cached_fid) = self.dir_cache.read().await.get(&built_path)
            {
                current_dir_id = cached_fid.clone();
                continue;
            }

            let entry = self
                .list_directory(&current_dir_id)
                .await?
                .into_iter()
                .find(|item| item.name == *segment)
                .ok_or_else(|| TokimoVfsError::NotFound(format!("quark path not found: {}", path.display())))?;
            if index == last_index {
                return Ok(entry);
            }
            if !entry.is_dir {
                return Err(TokimoVfsError::NotFound(format!(
                    "quark parent is not a directory: {}",
                    path.display()
                )));
            }
            current_dir_id = entry.id;
        }

        Err(TokimoVfsError::NotFound(format!(
            "quark path not found: {}",
            path.display()
        )))
    }

    async fn list_directory(&self, folder_id: &str) -> Result<Vec<QuarkEntry>> {
        let mut all_entries = Vec::new();
        let page_size = 100;
        let mut page = 1;

        loop {
            let sort_value = build_sort_value(&self.params.order_by, &self.params.order_direction);
            let folder_id_owned = folder_id.to_string();
            let page_str = page.to_string();
            let size_str = page_size.to_string();
            let order_by = self.params.order_by.clone();

            let resp: SortResponse = self
                .request("/file/sort", Method::GET, |req| {
                    let mut req = req
                        .query(&[("pdir_fid", &folder_id_owned)])
                        .query(&[("_page", &page_str)])
                        .query(&[("_size", &size_str)])
                        .query(&[("_fetch_total", "1")])
                        .query(&[("fetch_all_file", "1")])
                        .query(&[("fetch_risk_file_name", "1")]);
                    if order_by != "none" {
                        req = req.query(&[("_sort", &sort_value)]);
                    }
                    req
                })
                .await?;

            if resp.code != 0 {
                return Err(api_error("quark list failed", resp.message.or(resp.msg), resp.code));
            }
            let total = resp.total();
            let items = resp.items();
            all_entries.extend(items.into_iter().map(QuarkEntry::from));
            if page * page_size >= total || total == 0 {
                break;
            }
            page += 1;
        }
        Ok(all_entries)
    }

    async fn fetch_download_url(&self, file_id: &str) -> Result<String> {
        let data: DownloadResponse = self
            .request("/file/download", Method::POST, |req| {
                req.json(&DownloadRequest { fids: vec![file_id] })
            })
            .await?;

        if data.code != 0 {
            return Err(api_error(
                "quark download link failed",
                data.message.or(data.msg),
                data.code,
            ));
        }
        data.data
            .into_iter()
            .find_map(|item| (!item.download_url.is_empty()).then_some(item.download_url))
            .ok_or_else(|| TokimoVfsError::Other("quark download payload did not contain a URL".into()))
    }

    /// Create a folder under the given parent folder id.
    /// Returns the new folder's fid if the API provides it.
    async fn api_create_folder(&self, parent_fid: &str, name: &str) -> Result<Option<String>> {
        let data: CreateFolderResponse = self
            .request("/file", Method::POST, |req| {
                req.json(&CreateFolderRequest {
                    dir_init_lock: false,
                    dir_path: "",
                    file_name: name,
                    pdir_fid: parent_fid,
                })
            })
            .await?;

        if data.code != 0 {
            return Err(api_error("quark mkdir failed", data.message.or(data.msg), data.code));
        }
        let fid = data.data.map(|d| d.fid).filter(|fid| !fid.is_empty());
        Ok(fid)
    }

    /// Delete files/folders by their file IDs.
    async fn api_delete(&self, fids: &[&str]) -> Result<()> {
        let data: ApiResponse = self
            .request("/file/delete", Method::POST, |req| {
                req.json(&DeleteRequest {
                    action_type: 1,
                    exclude_fids: vec![],
                    filelist: fids.to_vec(),
                })
            })
            .await?;

        if data.code != 0 {
            return Err(api_error("quark delete failed", data.message.or(data.msg), data.code));
        }
        Ok(())
    }

    /// Rename a file/folder by its file ID.
    async fn api_rename(&self, fid: &str, new_name: &str) -> Result<()> {
        let data: ApiResponse = self
            .request("/file/rename", Method::POST, |req| {
                req.json(&RenameRequest {
                    fid,
                    file_name: new_name,
                })
            })
            .await?;

        if data.code != 0 {
            return Err(api_error("quark rename failed", data.message.or(data.msg), data.code));
        }
        Ok(())
    }

    /// Move files to a target parent folder.
    async fn api_move(&self, fids: &[&str], to_parent_fid: &str) -> Result<()> {
        let data: ApiResponse = self
            .request("/file/move", Method::POST, |req| {
                req.json(&MoveRequest {
                    action_type: 1,
                    exclude_fids: vec![],
                    filelist: fids.to_vec(),
                    to_pdir_fid: to_parent_fid,
                })
            })
            .await?;

        if data.code != 0 {
            return Err(api_error("quark move failed", data.message.or(data.msg), data.code));
        }
        Ok(())
    }

    // ---- Upload helpers ----

    async fn up_pre(&self, file_name: &str, mime_type: &str, size: u64, parent_fid: &str) -> Result<UpPreResp> {
        let now = chrono::Utc::now().timestamp_millis();
        let resp: UpPreResp = self
            .request("/file/upload/pre", Method::POST, |req| {
                req.json(&UpPreRequest {
                    ccp_hash_update: true,
                    dir_name: "",
                    file_name,
                    format_type: mime_type,
                    l_created_at: now,
                    l_updated_at: now,
                    pdir_fid: parent_fid,
                    size,
                })
            })
            .await?;

        if resp.code != 0 {
            return Err(api_error(
                "quark upload pre failed",
                resp.message.or(resp.msg),
                resp.code,
            ));
        }
        Ok(resp)
    }

    async fn up_hash(&self, md5: &str, sha1: &str, task_id: &str) -> Result<bool> {
        let resp: UpHashResp = self
            .request("/file/update/hash", Method::POST, |req| {
                req.json(&UpHashRequest { md5, sha1, task_id })
            })
            .await?;

        if resp.code != 0 {
            return Err(api_error(
                "quark upload hash failed",
                resp.message.or(resp.msg),
                resp.code,
            ));
        }
        Ok(resp.data.is_some_and(|d| d.finish))
    }

    async fn up_auth(&self, pre: &types::UpPreData, auth_meta: String) -> Result<String> {
        let resp: UpAuthResp = self
            .request("/file/upload/auth", Method::POST, |req| {
                req.json(&UpAuthRequest {
                    auth_info: &pre.auth_info,
                    auth_meta,
                    task_id: &pre.task_id,
                })
            })
            .await?;

        if resp.code != 0 {
            return Err(api_error(
                "quark upload auth failed",
                resp.message.or(resp.msg),
                resp.code,
            ));
        }
        resp.data
            .map(|d| d.auth_key)
            .ok_or_else(|| TokimoVfsError::Other("quark upload auth: missing auth_key".into()))
    }

    async fn up_part(
        &self,
        pre: &types::UpPreData,
        mime_type: &str,
        part_number: usize,
        part_data: &[u8],
    ) -> Result<String> {
        let time_str = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth_meta = format!(
            "PUT\n\n{}\n{}\nx-oss-date:{}\nx-oss-user-agent:aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit\n/{}/{}?partNumber={}&uploadId={}",
            mime_type, time_str, time_str, pre.bucket, pre.obj_key, part_number, pre.upload_id,
        );
        let auth_key = self.up_auth(pre, auth_meta).await?;

        // Build OSS upload URL
        let oss_host = if pre.upload_url.starts_with("http://") {
            &pre.upload_url[7..]
        } else if pre.upload_url.starts_with("https://") {
            &pre.upload_url[8..]
        } else {
            &pre.upload_url
        };
        let url = format!("https://{}.{}/{}", pre.bucket, oss_host, pre.obj_key);

        let response = self
            .api_client
            .put(&url)
            .query(&[
                ("partNumber", part_number.to_string()),
                ("uploadId", pre.upload_id.clone()),
            ])
            .header(AUTHORIZATION, &auth_key)
            .header(CONTENT_TYPE, mime_type)
            .header(REFERER, REFERER_URL)
            .header("x-oss-date", &time_str)
            .header(
                "x-oss-user-agent",
                "aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit",
            )
            .body(part_data.to_vec())
            .send()
            .await
            .map_err(|err| reqwest_err("quark", "upload part request", err))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(TokimoVfsError::Other(format!(
                "quark upload part failed: status={status}, body={body}"
            )));
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Ok(etag)
    }

    async fn up_commit(&self, pre: &types::UpPreData, etags: &[String]) -> Result<()> {
        // Build CompleteMultipartUpload XML
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>\n");
        for (i, etag) in etags.iter().enumerate() {
            let _ = write!(
                xml,
                "<Part>\n<PartNumber>{}</PartNumber>\n<ETag>{}</ETag>\n</Part>\n",
                i + 1,
                etag
            );
        }
        xml.push_str("</CompleteMultipartUpload>");

        let content_md5 = {
            let digest = Md5::digest(xml.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(digest)
        };

        let callback_base64 = if let Some(cb) = &pre.callback {
            let cb_json = serde_json::to_string(cb)
                .map_err(|e| TokimoVfsError::Other(format!("quark serialize callback: {e}")))?;
            base64::engine::general_purpose::STANDARD.encode(cb_json.as_bytes())
        } else {
            String::new()
        };

        let time_str = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let auth_meta = format!(
            "POST\n{}\napplication/xml\n{}\nx-oss-callback:{}\nx-oss-date:{}\nx-oss-user-agent:aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit\n/{}/{}?uploadId={}",
            content_md5, time_str, callback_base64, time_str, pre.bucket, pre.obj_key, pre.upload_id,
        );
        let auth_key = self.up_auth(pre, auth_meta).await?;

        let oss_host = if pre.upload_url.starts_with("http://") {
            &pre.upload_url[7..]
        } else if pre.upload_url.starts_with("https://") {
            &pre.upload_url[8..]
        } else {
            &pre.upload_url
        };
        let url = format!("https://{}.{}/{}", pre.bucket, oss_host, pre.obj_key);

        let response = self
            .api_client
            .post(&url)
            .query(&[("uploadId", &pre.upload_id)])
            .header(AUTHORIZATION, &auth_key)
            .header("Content-MD5", &content_md5)
            .header(CONTENT_TYPE, "application/xml")
            .header(REFERER, REFERER_URL)
            .header("x-oss-callback", &callback_base64)
            .header("x-oss-date", &time_str)
            .header(
                "x-oss-user-agent",
                "aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit",
            )
            .body(xml)
            .send()
            .await
            .map_err(|err| reqwest_err("quark", "upload commit request", err))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(TokimoVfsError::Other(format!(
                "quark upload commit failed: status={status}, body={body}"
            )));
        }
        Ok(())
    }

    async fn up_finish(&self, pre: &types::UpPreData) -> Result<()> {
        let resp: ApiResponse = self
            .request("/file/upload/finish", Method::POST, |req| {
                req.json(&UpFinishRequest {
                    obj_key: &pre.obj_key,
                    task_id: &pre.task_id,
                })
            })
            .await?;

        if resp.code != 0 {
            return Err(api_error(
                "quark upload finish failed",
                resp.message.or(resp.msg),
                resp.code,
            ));
        }
        Ok(())
    }
}

fn require_non_empty<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    params[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokimoVfsError::InvalidConfig(format!("quark driver is missing '{key}'")))
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

fn build_sort_value(order_by: &str, order_direction: &str) -> String {
    if order_by == "none" {
        "file_type:asc,file_name:asc".to_string()
    } else {
        format!("file_type:asc,{order_by}:{order_direction}")
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

impl Driver for QuarkDriver {
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

    fn as_put(&self) -> Option<&dyn PutFile> {
        Some(self)
    }

    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }
}

#[async_trait]
impl Mkdir for QuarkDriver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Err(TokimoVfsError::Other("quark mkdir: empty path".into()));
        }
        let folder_name = &segments[segments.len() - 1];
        let parent_path = path.parent().unwrap_or_else(|| Path::new("/"));
        let parent_fid = self.resolve_dir_id(parent_path).await?;
        let fid = self.api_create_folder(&parent_fid, folder_name).await?;

        // Cache the new folder's ID so that subsequent resolve_dir_id calls
        // succeed even if the Quark API listing hasn't caught up yet.
        if let Some(fid) = fid {
            let cache_key = normalize_display_path(path);
            self.dir_cache.write().await.insert(cache_key, fid);
        }
        Ok(())
    }
}

#[async_trait]
impl DeleteFile for QuarkDriver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let entry = self.resolve_entry(path).await?;
        if entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "quark delete_file: path is a directory: {}",
                path.display()
            )));
        }
        self.api_delete(&[&entry.id]).await
    }
}

#[async_trait]
impl DeleteDir for QuarkDriver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let entry = self.resolve_entry(path).await?;
        if !entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "quark delete_dir: path is not a directory: {}",
                path.display()
            )));
        }
        self.api_delete(&[&entry.id]).await
    }
}

#[async_trait]
impl Rename for QuarkDriver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let entry = self.resolve_entry(from).await?;

        let from_parent = from.parent().unwrap_or_else(|| Path::new("/"));
        let to_parent = to.parent().unwrap_or_else(|| Path::new("/"));

        let to_segments = collect_segments(to);
        let new_name = to_segments
            .last()
            .ok_or_else(|| TokimoVfsError::Other("quark rename: empty target path".into()))?;

        // If parent directories differ, we need a move + rename
        let from_parent_norm = normalize_display_path(from_parent);
        let to_parent_norm = normalize_display_path(to_parent);

        if from_parent_norm == to_parent_norm {
            // Same directory — just rename
            self.api_rename(&entry.id, new_name).await
        } else {
            // Different directory — move first, then rename if name changed
            let to_parent_fid = self.resolve_dir_id(to_parent).await?;
            self.api_move(&[&entry.id], &to_parent_fid).await?;

            let from_segments = collect_segments(from);
            let old_name = from_segments.last().map_or("", std::string::String::as_str);
            if old_name != new_name {
                self.api_rename(&entry.id, new_name).await?;
            }
            Ok(())
        }
    }
}

#[async_trait]
impl MoveFile for QuarkDriver {
    async fn move_file(&self, from: &Path, to_dir: &Path) -> Result<()> {
        let entry = self.resolve_entry(from).await?;
        let to_dir_fid = self.resolve_dir_id(to_dir).await?;
        self.api_move(&[&entry.id], &to_dir_fid).await
    }
}

#[async_trait]
impl PutFile for QuarkDriver {
    async fn put(&self, path: &Path, data: Vec<u8>) -> Result<()> {
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Err(TokimoVfsError::Other("quark put: empty path".into()));
        }
        let file_name = &segments[segments.len() - 1];
        let parent_path = path.parent().unwrap_or_else(|| Path::new("/"));
        let parent_fid = self.resolve_dir_id(parent_path).await?;

        // Delete existing file first to avoid creating a duplicate
        if let Ok(entry) = self.resolve_entry(path).await
            && !entry.is_dir
        {
            self.api_delete(&[&entry.id]).await?;
        }

        // Compute MD5 and SHA1 hashes
        let md5_hex = format!("{:x}", Md5::digest(&data));
        let sha1_hex = format!("{:x}", Sha1::digest(&data));
        let mime_type = mime_guess::from_path(path).first_or_octet_stream().to_string();

        // Step 1: pre-upload
        let pre = self
            .up_pre(file_name, &mime_type, data.len() as u64, &parent_fid)
            .await?;
        let pre_data = pre
            .data
            .ok_or_else(|| TokimoVfsError::Other("quark upload pre: missing data in response".into()))?;

        if pre_data.finish {
            debug!("quark upload: instant upload (秒传) for {}", file_name);
            return Ok(());
        }

        // Step 2: hash check (秒传)
        let hash_finish = self.up_hash(&md5_hex, &sha1_hex, &pre_data.task_id).await?;
        if hash_finish {
            debug!("quark upload: hash match (秒传) for {}", file_name);
            return Ok(());
        }

        // Step 3: multipart upload
        let part_size = pre
            .metadata
            .as_ref()
            .map(|m| m.part_size)
            .filter(|&s| s > 0)
            .unwrap_or(4 * 1024 * 1024); // default 4MB

        let total = data.len();
        let mut part_number = 1;
        let mut etags: Vec<String> = Vec::new();
        let mut offset = 0usize;

        while offset < total {
            let end = (offset + part_size).min(total);
            let part_data = &data[offset..end];

            let etag = self.up_part(&pre_data, &mime_type, part_number, part_data).await?;
            if etag == "finish" {
                return Ok(());
            }
            etags.push(etag);
            part_number += 1;
            offset = end;
        }

        // Step 4: commit (complete multipart upload)
        self.up_commit(&pre_data, &etags).await?;

        // Step 5: finish
        self.up_finish(&pre_data).await
    }
}

#[async_trait]
impl PutStream for QuarkDriver {
    async fn put_stream(&self, path: &Path, size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Err(TokimoVfsError::Other("quark put_stream: empty path".into()));
        }
        let file_name = &segments[segments.len() - 1];
        let parent_path = path.parent().unwrap_or_else(|| Path::new("/"));
        let parent_fid = self.resolve_dir_id(parent_path).await?;

        // Delete existing file first to avoid creating a duplicate
        if let Ok(entry) = self.resolve_entry(path).await
            && !entry.is_dir
        {
            self.api_delete(&[&entry.id]).await?;
        }

        let mime_type = mime_guess::from_path(path).first_or_octet_stream().to_string();

        // Step 1: pre-upload
        let pre = self.up_pre(file_name, &mime_type, size, &parent_fid).await?;
        let pre_data = pre
            .data
            .ok_or_else(|| TokimoVfsError::Other("quark upload pre: missing data in response".into()))?;

        if pre_data.finish {
            debug!("quark put_stream: instant upload (秒传) for {}", file_name);
            return Ok(());
        }

        // Step 2: stream parts — buffer up to `part_size`, upload each part
        //         immediately. Max memory = 1 part (~4 MB), not the whole file.
        //         Compute MD5/SHA1 incrementally for up_hash call.
        let part_size = pre
            .metadata
            .as_ref()
            .map(|m| m.part_size)
            .filter(|&s| s > 0)
            .unwrap_or(4 * 1024 * 1024);

        let mut part_buf = Vec::with_capacity(part_size);
        let mut part_number = 1usize;
        let mut etags: Vec<String> = Vec::new();
        let mut md5_hasher = Md5::new();
        let mut sha1_hasher = Sha1::new();

        while let Some(chunk) = rx.recv().await {
            md5_hasher.update(&chunk);
            sha1_hasher.update(&chunk);
            part_buf.extend_from_slice(&chunk);

            while part_buf.len() >= part_size {
                let tail = part_buf.split_off(part_size);
                let part_data = std::mem::replace(&mut part_buf, tail);

                let etag = self.up_part(&pre_data, &mime_type, part_number, &part_data).await?;
                if etag == "finish" {
                    return Ok(());
                }
                etags.push(etag);
                part_number += 1;
            }
        }

        // Flush remaining bytes as the last part
        if !part_buf.is_empty() {
            let etag = self.up_part(&pre_data, &mime_type, part_number, &part_buf).await?;
            if etag != "finish" {
                etags.push(etag);
            }
        }

        // Step 3: update hash (required by Quark before finish)
        let md5_hex = format!("{:x}", md5_hasher.finalize());
        let sha1_hex = format!("{:x}", sha1_hasher.finalize());
        let hash_finish = self.up_hash(&md5_hex, &sha1_hex, &pre_data.task_id).await?;
        if hash_finish {
            debug!("quark put_stream: hash match (秒传) for {}", file_name);
            return Ok(());
        }

        // Step 4: commit + finish
        self.up_commit(&pre_data, &etags).await?;
        self.up_finish(&pre_data).await
    }
}

/// Set or update a cookie value in a cookie string (like `OpenList`'s cookie.SetStr).
fn set_cookie_value(cookie_str: &str, name: &str, value: &str) -> String {
    let mut cookies: Vec<(&str, &str)> = Vec::new();
    let mut found = false;

    for part in cookie_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim();
            if k == name {
                cookies.push((k, value));
                found = true;
            } else {
                cookies.push((k, v.trim()));
            }
        }
    }

    if !found {
        cookies.push((name, value));
    }

    cookies
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

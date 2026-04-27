//! 115 网盘驱动（首版只读）。
//!
//! JSON 配置字段：
//!   cookie         — 115 登录 Cookie（可选）
//!   `qrcode_token`   — 115 扫码授权后的 UID（可选，和 cookie 二选一即可）
//!   `qrcode_source`  — 扫码登录来源，默认 "qandroid"（避免与浏览器 web 会话互踢）
//!   `root_folder_id` — 根目录 ID，可选，默认 "0"
//!   `page_size`      — 列表分页大小，可选，默认 1000，最大 1150

mod crypto;
mod types;
mod utils;

use std::collections::HashMap;
use std::path::Path;

use super::reqwest_err;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use reqwest::header::{COOKIE, HeaderMap, HeaderValue, LOCATION, RANGE, REFERER, SET_COOKIE, USER_AGENT};
use tokio::sync::{RwLock, mpsc::Sender};
use tracing::{debug, error};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{Driver, Meta, Reader};
use tokimo_vfs_core::error::{Result, TokimoVfsError};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};
use types::{
    DownloadInfo, DownloadRequestPayload, DownloadResponse, FileListResponse, LoginCheckResponse, Pan115Entry,
    QrLoginResponse, api_error, normalize_display_path, to_file_info,
};
use utils::{build_range_header, collect_segments, optional_non_empty, validate_cookie};

const DRIVER_NAME: &str = "115cloud";
const LIST_API_URL: &str = "https://webapi.115.com/files";
const LOGIN_CHECK_URL: &str = "https://passportapi.115.com/app/1.0/web/1.0/check/sso";
const DOWNLOAD_URL_API: &str = "https://proapi.115.com/app/chrome/downurl";
const QR_LOGIN_API_PREFIX: &str = "https://passportapi.115.com/app/1.0";
const DEFAULT_PAGE_SIZE: u32 = 1000;
const MAX_PAGE_SIZE: u32 = 1150;
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 115Browser/27.0.5.7";
const DEFAULT_QRCODE_SOURCE: &str = "qandroid";
const REFERER_URL: &str = "https://115.com/";

pub const CONFIG: DriverConfig = DriverConfig {
    name: DRIVER_NAME,
    description: "115 cloud storage",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

#[derive(Clone)]
struct Pan115Params {
    cookie: Option<String>,
    qrcode_token: Option<String>,
    qrcode_source: String,
    root_folder_id: String,
    page_size: u32,
    user_agent: String,
}

pub struct Pan115Driver {
    /// Client for API calls that don't need CDN cookie handling (list, login, etc.)
    client: reqwest::Client,
    params: Pan115Params,
    caps: StorageCapabilities,
    auth_cookie: RwLock<Option<String>>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let cookie = optional_non_empty(params, "cookie");
    let qrcode_token = optional_non_empty(params, "qrcode_token");
    let qrcode_source =
        optional_non_empty(params, "qrcode_source").unwrap_or_else(|| DEFAULT_QRCODE_SOURCE.to_string());

    if cookie.is_none() && qrcode_token.is_none() {
        return Err(TokimoVfsError::InvalidConfig(
            "pan115 driver requires either 'cookie' or 'qrcode_token'".into(),
        ));
    }
    if let Some(cookie) = cookie.as_deref() {
        validate_cookie(cookie)?;
    }

    let root_folder_id = optional_non_empty(params, "root_folder_id").unwrap_or_else(|| "0".to_string());
    let page_size = params["page_size"]
        .as_u64()
        .unwrap_or(u64::from(DEFAULT_PAGE_SIZE))
        .clamp(1, u64::from(MAX_PAGE_SIZE)) as u32;

    let user_agent = optional_non_empty(params, "user_agent").unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());

    let client = reqwest::Client::builder()
        .build()
        .map_err(|err| TokimoVfsError::ConnectionError(format!("pan115 client init failed: {err}")))?;

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

    Ok(Box::new(Pan115Driver {
        client,
        params: Pan115Params {
            cookie,
            qrcode_token,
            qrcode_source,
            root_folder_id,
            page_size,
            user_agent,
        },
        caps,
        auth_cookie: RwLock::new(None),
    }))
}

#[async_trait]
impl Meta for Pan115Driver {
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

    fn resolved_config_patch(&self) -> Option<serde_json::Value> {
        let cookie = self.auth_cookie.try_read().ok()?.clone()?;
        Some(serde_json::json!({ "cookie": cookie }))
    }
}

#[async_trait]
impl Reader for Pan115Driver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let dir_id = self.resolve_dir_id(path).await?;
        let entries = self.list_directory(&dir_id).await?;
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
                "pan115 path is a directory: {}",
                path.display()
            )));
        }

        let pick_code = entry
            .pick_code
            .ok_or_else(|| TokimoVfsError::Other(format!("pan115 file is missing pick_code: {}", path.display())))?;
        let (url, cdn_cookie) = self.fetch_download_url_with_cookie(&pick_code).await?;

        let mut headers = HashMap::new();
        if let Some(ck) = cdn_cookie {
            headers.insert("Cookie".into(), ck);
        }
        headers.insert("User-Agent".into(), self.params.user_agent.clone());
        headers.insert("Referer".into(), REFERER_URL.to_string());

        Ok(Link {
            url: Some(url),
            header: headers,
            expiry: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let entry = self.resolve_entry(path).await?;
        if entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "pan115 path is a directory: {}",
                path.display()
            )));
        }
        let pick_code = entry
            .pick_code
            .ok_or_else(|| TokimoVfsError::Other(format!("pan115 file is missing pick_code: {}", path.display())))?;

        let (url, cdn_cookie) = self.fetch_download_url_with_cookie(&pick_code).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.params.user_agent)
                .map_err(|err| TokimoVfsError::Other(format!("pan115 invalid user agent: {err}")))?,
        );
        headers.insert(REFERER, HeaderValue::from_static(REFERER_URL));
        if let Some(range_header) = build_range_header(offset, limit) {
            headers.insert(RANGE, HeaderValue::from_str(&range_header).unwrap());
        }
        if let Some(ref ck) = cdn_cookie {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(ck)
                    .map_err(|err| TokimoVfsError::Other(format!("pan115 invalid cdn cookie: {err}")))?,
            );
        }

        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|err| reqwest_err("pan115", "read request", err))?;
        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("pan115", "read response", err))?;

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|err| reqwest_err("pan115", "read body", err))
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let result = async {
            let entry = self.resolve_entry(path).await?;
            if entry.is_dir {
                return Err(TokimoVfsError::Other(format!(
                    "pan115 path is a directory: {}",
                    path.display()
                )));
            }
            let pick_code = entry.pick_code.ok_or_else(|| {
                TokimoVfsError::Other(format!("pan115 file is missing pick_code: {}", path.display()))
            })?;

            let (url, cdn_cookie) = self.fetch_download_url_with_cookie(&pick_code).await?;

            let mut headers = HeaderMap::new();
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&self.params.user_agent)
                    .map_err(|err| TokimoVfsError::Other(format!("pan115 invalid user agent: {err}")))?,
            );
            headers.insert(REFERER, HeaderValue::from_static(REFERER_URL));
            if let Some(range_header) = build_range_header(offset, limit) {
                headers.insert(RANGE, HeaderValue::from_str(&range_header).unwrap());
            }
            if let Some(ref ck) = cdn_cookie {
                headers.insert(
                    COOKIE,
                    HeaderValue::from_str(ck)
                        .map_err(|err| TokimoVfsError::Other(format!("pan115 invalid cdn cookie: {err}")))?,
                );
            }

            let response = self
                .client
                .get(&url)
                .headers(headers)
                .send()
                .await
                .map_err(|err| reqwest_err("pan115", "stream request", err))?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(TokimoVfsError::ConnectionError(format!(
                    "pan115 CDN error: status={status} body={body}"
                )));
            }

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream
                .try_next()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("pan115 stream read failed: {err}")))?
            {
                if tx.send(chunk.to_vec()).await.is_err() {
                    break;
                }
            }

            Ok::<(), TokimoVfsError>(())
        }
        .await;

        if let Err(err) = result {
            error!("pan115 stream_to failed: {err}");
        }
    }
}

impl Pan115Driver {
    /// Fetch the CDN download URL AND the CDN auth cookie.
    ///
    /// The 115 API sets a cross-domain `Set-Cookie: …; domain=.115cdn.net` on the
    /// download response. reqwest's Jar rejects it (RFC 6265 cross-domain check),
    /// so we extract it manually from the response headers.
    /// Always uses the Chrome download API which provides the CDN auth cookie.
    async fn fetch_download_url_with_cookie(&self, pick_code: &str) -> Result<(String, Option<String>)> {
        self.fetch_download_url_chrome_with_cookie(pick_code).await
    }

    /// Collect cookies from a response: CDN cookies into `cdn_cookies`,
    /// all other cookies into `accumulated` (for forwarding on next hop).
    fn collect_cookies(headers: &HeaderMap, cdn_cookies: &mut Vec<String>, accumulated: &mut String) {
        for value in headers.get_all(SET_COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            let nv = match s.split(';').next() {
                Some(nv) if !nv.trim().is_empty() => nv.trim().to_string(),
                _ => continue,
            };
            debug!("pan115: Set-Cookie = {s}");
            if s.contains("115cdn.net") {
                cdn_cookies.push(nv);
            } else {
                let name = nv.split('=').next().unwrap_or("");
                if !name.is_empty() && !accumulated.contains(name) {
                    accumulated.push_str("; ");
                    accumulated.push_str(&nv);
                }
            }
        }
    }

    async fn authenticate(&self) -> Result<String> {
        if let Some(cookie) = self.auth_cookie.read().await.clone() {
            return Ok(cookie);
        }

        if let Some(cookie) = self.params.cookie.as_ref() {
            self.login_check(cookie).await?;
            *self.auth_cookie.write().await = Some(cookie.clone());
            return Ok(cookie.clone());
        }

        let qrcode_token = self
            .params
            .qrcode_token
            .as_deref()
            .ok_or_else(|| TokimoVfsError::InvalidConfig("pan115 missing qrcode_token".into()))?;
        let cookie = self.login_with_qrcode(qrcode_token).await?;
        self.login_check(&cookie).await?;
        *self.auth_cookie.write().await = Some(cookie.clone());
        Ok(cookie)
    }

    async fn cookie(&self) -> Result<String> {
        if let Some(cookie) = self.auth_cookie.read().await.clone() {
            return Ok(cookie);
        }

        self.authenticate().await
    }

    async fn login_check(&self, cookie: &str) -> Result<()> {
        let response = self
            .client
            .get(LOGIN_CHECK_URL)
            .query(&[("_", chrono::Utc::now().timestamp_millis().to_string())])
            .header(COOKIE, cookie)
            .header(USER_AGENT, &self.params.user_agent)
            .send()
            .await
            .map_err(|err| TokimoVfsError::ConnectionError(format!("pan115 login check failed: {err}")))?;

        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("pan115", "login check", err))?;
        let data: LoginCheckResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("pan115 login check decode failed: {err}")))?;

        if data.state == 0 {
            return Ok(());
        }

        Err(TokimoVfsError::ConnectionError(
            data.message.unwrap_or_else(|| "pan115 auth is invalid".to_string()),
        ))
    }

    async fn login_with_qrcode(&self, qrcode_token: &str) -> Result<String> {
        let response = self
            .client
            .post(format!(
                "{}/{}/1.0/login/qrcode",
                QR_LOGIN_API_PREFIX, self.params.qrcode_source
            ))
            .header(USER_AGENT, &self.params.user_agent)
            .form(&[("account", qrcode_token), ("app", self.params.qrcode_source.as_str())])
            .send()
            .await
            .map_err(|err| TokimoVfsError::ConnectionError(format!("pan115 qrcode login failed: {err}")))?;

        let response = response
            .error_for_status()
            .map_err(|err| reqwest_err("pan115", "qrcode login", err))?;
        let data: QrLoginResponse = response
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("pan115 qrcode login decode failed: {err}")))?;

        if data.state != 1 {
            return Err(TokimoVfsError::ConnectionError(
                data.message
                    .unwrap_or_else(|| "pan115 qrcode login was not approved".to_string()),
            ));
        }

        data.data
            .cookie
            .to_cookie()
            .ok_or_else(|| TokimoVfsError::ConnectionError("pan115 qrcode login did not return a cookie".into()))
    }

    async fn resolve_dir_id(&self, path: &Path) -> Result<String> {
        if normalize_display_path(path) == "/" {
            return Ok(self.params.root_folder_id.clone());
        }

        let entry = self.resolve_entry(path).await?;
        if !entry.is_dir {
            return Err(TokimoVfsError::Other(format!(
                "pan115 path is not a directory: {}",
                path.display()
            )));
        }
        Ok(entry.id)
    }

    async fn resolve_entry(&self, path: &Path) -> Result<Pan115Entry> {
        let mut current_dir_id = self.params.root_folder_id.clone();
        let segments = collect_segments(path);
        if segments.is_empty() {
            return Ok(Pan115Entry {
                id: current_dir_id,
                name: String::new(),
                size: 0,
                is_dir: true,
                pick_code: None,
                modified: None,
            });
        }

        let last_index = segments.len() - 1;
        for (index, segment) in segments.iter().enumerate() {
            let entries = self.list_directory(&current_dir_id).await?;
            let entry = entries
                .into_iter()
                .find(|item| item.name == *segment)
                .ok_or_else(|| TokimoVfsError::NotFound(format!("pan115 path not found: {}", path.display())))?;

            if index == last_index {
                return Ok(entry);
            }
            if !entry.is_dir {
                return Err(TokimoVfsError::NotFound(format!(
                    "pan115 parent is not a directory: {}",
                    path.display()
                )));
            }
            current_dir_id = entry.id;
        }

        Err(TokimoVfsError::NotFound(format!(
            "pan115 path not found: {}",
            path.display()
        )))
    }

    async fn list_directory(&self, dir_id: &str) -> Result<Vec<Pan115Entry>> {
        let cookie = self.cookie().await?;
        let mut entries = Vec::new();
        let mut offset = 0_u32;

        loop {
            let response = self
                .client
                .get(LIST_API_URL)
                .query(&[
                    ("aid", "1".to_string()),
                    ("cid", dir_id.to_string()),
                    ("offset", offset.to_string()),
                    ("limit", self.params.page_size.to_string()),
                    ("show_dir", "1".to_string()),
                    ("format", "json".to_string()),
                    ("record_open_time", "1".to_string()),
                ])
                .header(COOKIE, &cookie)
                .header(USER_AGENT, &self.params.user_agent)
                .send()
                .await
                .map_err(|err| reqwest_err("pan115", "list request", err))?;

            let response = response
                .error_for_status()
                .map_err(|err| reqwest_err("pan115", "list response", err))?;
            let page: FileListResponse = response
                .json()
                .await
                .map_err(|err| TokimoVfsError::Other(format!("pan115 list decode failed: {err}")))?;

            if !page.state {
                return Err(api_error(
                    "pan115 list failed",
                    page.message,
                    page.errno.or(page.err_no),
                ));
            }

            let page_count = page.count.unwrap_or(page.data.len() as u32);
            let page_offset = page.offset.unwrap_or(offset);
            let page_len = page.data.len() as u32;
            entries.extend(page.data.into_iter().map(Pan115Entry::from));

            if page_len == 0 || page_offset.saturating_add(page_len) >= page_count {
                break;
            }
            offset = page_offset.saturating_add(page_len);
        }

        Ok(entries)
    }

    async fn fetch_download_url_chrome_with_cookie(&self, pick_code: &str) -> Result<(String, Option<String>)> {
        let cookie = self.cookie().await?;
        let payload = serde_json::to_vec(&DownloadRequestPayload { pickcode: pick_code })
            .map_err(|err| TokimoVfsError::Other(format!("pan115 download payload failed: {err}")))?;

        let key = crypto::generate_key();
        let encrypted_payload = crypto::encode_payload(&payload, &key);

        // Use a no-redirect client to capture cross-domain Set-Cookie from every hop.
        // The 115 API sets `Set-Cookie: …; domain=.115cdn.net` on a redirect intermediate
        // which reqwest's cookie jar rejects (RFC 6265 cross-domain check).
        let no_redir = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| TokimoVfsError::ConnectionError(format!("pan115 no-redirect client: {err}")))?;

        let mut cdn_cookies = Vec::<String>::new();
        let mut accumulated_cookies = cookie.clone();

        // Step 1: Send the initial POST
        let first_resp = no_redir
            .post(format!("{DOWNLOAD_URL_API}?t={}", chrono::Utc::now().timestamp()))
            .header(COOKIE, &accumulated_cookies)
            .header(USER_AGENT, &self.params.user_agent)
            .header(REFERER, REFERER_URL)
            .form(&[("data", &encrypted_payload)])
            .send()
            .await
            .map_err(|err| reqwest_err("pan115", "download request", err))?;

        Self::collect_cookies(first_resp.headers(), &mut cdn_cookies, &mut accumulated_cookies);

        // Step 2: Follow redirects manually
        let mut resp = first_resp;
        while resp.status().is_redirection() {
            let loc = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if loc.is_empty() {
                break;
            }
            resp = no_redir
                .get(&loc)
                .header(COOKIE, &accumulated_cookies)
                .header(USER_AGENT, &self.params.user_agent)
                .header(REFERER, REFERER_URL)
                .send()
                .await
                .map_err(|err| reqwest_err("pan115", "download redirect", err))?;

            Self::collect_cookies(resp.headers(), &mut cdn_cookies, &mut accumulated_cookies);
        }

        let resp = resp
            .error_for_status()
            .map_err(|err| reqwest_err("pan115", "download response", err))?;

        let cdn_cookie = if cdn_cookies.is_empty() {
            None
        } else {
            Some(cdn_cookies.join("; "))
        };

        let result: DownloadResponse = resp
            .json()
            .await
            .map_err(|err| TokimoVfsError::Other(format!("pan115 download decode failed: {err}")))?;

        if !result.state {
            return Err(api_error(
                "pan115 download link failed",
                result.message,
                result.errno.or(result.err_no),
            ));
        }

        let encoded = result
            .data
            .ok_or_else(|| TokimoVfsError::Other("pan115 download response is missing data".into()))?;
        let decoded = crypto::decode_payload(&encoded, &key)?;
        let all_links: HashMap<String, DownloadInfo> = serde_json::from_slice(&decoded)
            .map_err(|err| TokimoVfsError::Other(format!("pan115 download payload decode failed: {err}")))?;

        let dl_url = all_links
            .into_values()
            .find_map(|item| (!item.url.url.is_empty()).then_some(item.url.url))
            .ok_or_else(|| TokimoVfsError::Other("pan115 download payload did not contain a URL".into()))?;

        debug!("pan115: download url={dl_url}, cdn_cookie={cdn_cookie:?}");
        Ok((dl_url, cdn_cookie))
    }
}

impl Driver for Pan115Driver {}

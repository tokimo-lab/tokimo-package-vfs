mod types;

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use futures_util::TryStreamExt;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Sha1;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{
    CopyFile, DeleteDir, DeleteFile, Driver, Meta, Mkdir, MoveFile, PutStream, Reader, Rename,
};
use tokimo_vfs_core::error::{TokimoVfsError, Result};
use tokimo_vfs_core::model::obj::{FileInfo, Link};
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

use types::{
    AppConf, BatchTaskResp, Cloud189File, Cloud189Folder, DownResp, EncryptConf, FilesResp, RsaKeyResp, UploadUrlsResp,
};

const DRIVER_NAME: &str = "189cloud";
const WEB_URL: &str = "https://cloud.189.cn";
const AUTH_URL: &str = "https://open.e.189.cn";
const UPLOAD_URL: &str = "https://upload.cloud.189.cn";
const DEFAULT_ROOT_ID: &str = "-11";
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 9; SM-G9750) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Mobile Safari/537.36";
// Part size for multipart upload: 10 MiB
const PART_SIZE: usize = 10 * 1024 * 1024;

pub const CONFIG: DriverConfig = DriverConfig {
    name: DRIVER_NAME,
    description: "Tianyi Cloud (189.cn / 天翼云盘)",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

struct RsaCache {
    pub_key_pem: String,
    pk_id: String,
    expires_at: Instant,
}

struct Credentials {
    username: String,
    password: String,
}

pub struct Cloud189Driver {
    credentials: Credentials,
    root_folder_id: String,
    order_by: String,
    order_direction: String,
    /// reqwest client with cookie store; replaced on re-login
    client: Mutex<reqwest::Client>,
    caps: StorageCapabilities,
    /// Cached RSA key for upload request signing
    rsa_cache: RwLock<Option<RsaCache>>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let username = require_str(params, "username")?.to_string();
    let password = require_str(params, "password")?.to_string();
    let root_folder_id = optional_str(params, "root_folder_id").unwrap_or_else(|| DEFAULT_ROOT_ID.to_string());
    let order_by = optional_str(params, "order_by").unwrap_or_else(|| "lastOpTime".to_string());
    let order_direction = optional_str(params, "order_direction").unwrap_or_else(|| "true".to_string());

    let client = build_client()?;

    Ok(Box::new(Cloud189Driver {
        credentials: Credentials { username, password },
        root_folder_id,
        order_by,
        order_direction,
        client: Mutex::new(client),
        caps: StorageCapabilities {
            list: true,
            read: true,
            mkdir: true,
            delete_file: true,
            delete_dir: true,
            rename: true,
            write: true,
            symlink: false,
            range_read: true,
        },
        rsa_cache: RwLock::new(None),
    }))
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn require_str<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    match params.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(TokimoVfsError::Other(format!(
            "cloud189: required config key '{key}' missing or empty"
        ))),
    }
}

fn optional_str(params: &serde_json::Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(DEFAULT_USER_AGENT)
        .timeout(Duration::from_mins(1))
        .build()
        .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189: client build failed: {e}")))
}

fn random_no_cache() -> String {
    let n = OsRng.next_u64() % 100_000_000_000_000_000;
    format!("0.{n:017}")
}

fn random_hex_string(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(&buf)
}

/// Wrap a raw base64 RSA key into a proper PEM string (64-char line breaks required by Rust PEM parser).
fn make_public_key_pem(raw_b64: &str) -> String {
    let wrapped = raw_b64
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----")
}

/// RSA PKCS1v15 encrypt → lowercase hex string.
/// Equivalent to OpenList's `RsaEncode(data, key, hex=true)`.
fn rsa_encode_hex(data: &[u8], pub_key_pem: &str) -> Result<String> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_key_pem)
        .map_err(|e| TokimoVfsError::Other(format!("cloud189: RSA key parse: {e}")))?;
    let ct = pub_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .map_err(|e| TokimoVfsError::Other(format!("cloud189: RSA encrypt: {e}")))?;
    Ok(hex::encode(&ct))
}

/// RSA PKCS1v15 encrypt → base64 string (used for upload signing).
fn rsa_encode_b64(data: &[u8], pub_key_pem: &str) -> Result<String> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_key_pem)
        .map_err(|e| TokimoVfsError::Other(format!("cloud189: RSA key parse: {e}")))?;
    let ct = pub_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .map_err(|e| TokimoVfsError::Other(format!("cloud189: RSA encrypt: {e}")))?;
    Ok(B64.encode(&ct))
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - data.len() % block_size;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(padding as u8, padding));
    out
}

/// AES-128-ECB encrypt with PKCS7 padding, return hex-encoded ciphertext.
/// Equivalent to OpenList's `hex.EncodeToString(AesEncrypt(data, key))`.
fn aes_ecb_hex(data: &[u8], key: &[u8; 16]) -> String {
    let mut padded = pkcs7_pad(data, 16);
    let cipher = Aes128::new_from_slice(key).expect("key is always 16 bytes");
    for chunk in padded.chunks_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    hex::encode(&padded)
}

/// HMAC-SHA1, return hex-encoded MAC.
fn hmac_sha1_hex(key: &[u8], data: &[u8]) -> String {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = <HmacSha1 as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Encode form parameters sorted alphabetically (matches OpenList's `qs()`).
fn encode_form_sorted(params: &HashMap<&str, &str>) -> String {
    let mut keys: Vec<&&str> = params.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| format!("{}={}", k, params[*k]))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_cn_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|ndt| ndt.and_utc() - chrono::Duration::hours(8))
}

fn folder_to_info(f: &Cloud189Folder, parent: &Path) -> FileInfo {
    FileInfo {
        name: f.name.clone(),
        path: parent.join(&f.name).to_string_lossy().to_string(),
        is_dir: true,
        size: 0,
        modified: parse_cn_time(&f.last_op_time),
    }
}

fn file_to_info(f: &Cloud189File, parent: &Path) -> FileInfo {
    FileInfo {
        name: f.name.clone(),
        path: parent.join(&f.name).to_string_lossy().to_string(),
        is_dir: false,
        size: f.size as u64,
        modified: parse_cn_time(&f.last_op_time),
    }
}

// ─── Core driver logic ────────────────────────────────────────────────────────

impl Cloud189Driver {
    /// Full 4-step login: get redirect params → app config → encrypt config →
    /// submit login. Equivalent to OpenList's `Cloud189.newLogin()`.
    async fn do_login(&self) -> Result<()> {
        let new_client = build_client()?;

        // Step 1: GET login redirect page to extract lt/reqId/appId
        let login_url = format!(
            "{WEB_URL}/api/portal/loginUrl.action?redirectURL={}",
            urlencoding::encode("https://cloud.189.cn/main.action")
        );
        let res = new_client
            .get(&login_url)
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 login step1: {e}")))?;

        if res.url().as_str().contains("web/main") {
            *self.client.lock().await = new_client;
            return Ok(());
        }

        let redirect_url = res.url().clone();
        let qp: HashMap<_, _> = redirect_url.query_pairs().into_owned().collect();
        let lt = qp.get("lt").cloned().unwrap_or_default();
        let req_id = qp.get("reqId").cloned().unwrap_or_default();
        let app_id = qp.get("appId").cloned().unwrap_or_default();
        let referer = redirect_url.to_string();

        // Step 2: GET app configuration
        let app_conf: AppConf = new_client
            .post(format!("{AUTH_URL}/api/logbox/oauth2/appConf.do"))
            .header("lt", &lt)
            .header("reqid", &req_id)
            .header("referer", &referer)
            .header("origin", AUTH_URL)
            .form(&[("version", "2.0"), ("appKey", app_id.as_str())])
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 appConf: {e}")))?
            .json()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 appConf parse: {e}")))?;

        if app_conf.result != "0" {
            return Err(TokimoVfsError::ConnectionError(format!(
                "cloud189 appConf error: {}",
                app_conf.msg
            )));
        }

        // Step 3: GET RSA key
        let enc_conf: EncryptConf = new_client
            .post(format!("{AUTH_URL}/api/logbox/config/encryptConf.do"))
            .header("lt", &lt)
            .header("reqid", &req_id)
            .header("referer", &referer)
            .header("origin", AUTH_URL)
            .form(&[("appId", app_id.as_str())])
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 encryptConf: {e}")))?
            .json()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 encryptConf parse: {e}")))?;

        if enc_conf.result != 0 {
            return Err(TokimoVfsError::ConnectionError("cloud189: encryptConf failed".to_string()));
        }

        let pre = &enc_conf.data.pre;
        let pub_key_pem = make_public_key_pem(&enc_conf.data.pub_key);
        let enc_user = format!(
            "{pre}{}",
            rsa_encode_hex(self.credentials.username.as_bytes(), &pub_key_pem)?
        );
        let enc_pass = format!(
            "{pre}{}",
            rsa_encode_hex(self.credentials.password.as_bytes(), &pub_key_pem)?
        );

        // Step 4: Submit login
        let client_type = app_conf.data.client_type.to_string();
        let login_data = [
            ("version", "v2.0"),
            ("apToken", ""),
            ("appKey", app_id.as_str()),
            ("accountType", app_conf.data.account_type.as_str()),
            ("userName", enc_user.as_str()),
            ("epd", enc_pass.as_str()),
            ("captchaType", ""),
            ("validateCode", ""),
            ("smsValidateCode", ""),
            ("captchaToken", ""),
            ("returnUrl", app_conf.data.return_url.as_str()),
            ("mailSuffix", app_conf.data.mail_suffix.as_str()),
            ("dynamicCheck", "FALSE"),
            ("clientType", client_type.as_str()),
            ("cb_SaveName", "3"),
            ("isOauth2", if app_conf.data.is_oauth2 { "true" } else { "false" }),
            ("state", ""),
            ("paramId", app_conf.data.param_id.as_str()),
        ];

        let body: serde_json::Value = new_client
            .post(format!("{AUTH_URL}/api/logbox/oauth2/loginSubmit.do"))
            .header("lt", &lt)
            .header("reqid", &req_id)
            .header("referer", &referer)
            .header("origin", AUTH_URL)
            .form(&login_data)
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 loginSubmit: {e}")))?
            .json()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 loginSubmit parse: {e}")))?;

        if body.get("result").and_then(serde_json::Value::as_i64).unwrap_or(-1) != 0 {
            let msg = body.get("msg").and_then(|v| v.as_str()).unwrap_or("unknown");
            let detail = if msg.contains("设备ID不存在") || msg.contains("二次设备校验") {
                format!("{msg} — 请前往 https://e.dlife.cn/index.do 登录天翼账号，在「账号安全」中关闭「设备锁」后重试")
            } else {
                msg.to_string()
            };
            return Err(TokimoVfsError::ConnectionError(format!("cloud189 login failed: {detail}")));
        }

        // Step 5: Follow toUrl to exchange the login ticket for a cloud.189.cn session cookie.
        // loginSubmit.do runs on open.e.189.cn; the toUrl redirects to cloud.189.cn which sets
        // the actual session cookie (cookieUserSession). Without this step, all API calls fail
        // with InvalidSessionKey because the two domains don't share cookies.
        if let Some(to_url) = body.get("toUrl").and_then(|v| v.as_str())
            && !to_url.is_empty()
        {
            new_client
                .get(to_url)
                .header("Referer", AUTH_URL)
                .send()
                .await
                .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 toUrl follow: {e}")))?;
        }

        *self.client.lock().await = new_client;
        info!("cloud189: logged in as {}", self.credentials.username);
        Ok(())
    }

    /// Execute an API request. On `InvalidSessionKey`, re-login and retry once.
    async fn api(
        &self,
        method: reqwest::Method,
        url: &str,
        configure: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<bytes::Bytes> {
        let body = self.raw_api(method.clone(), url, &configure).await?;

        // Check for session expiry inline
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
            let expired = json
                .get("errorCode")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == "InvalidSessionKey");
            if expired {
                warn!("cloud189: session expired, re-logging in");
                self.do_login().await?;
                return self.raw_api(method, url, &configure).await;
            }
        }

        Ok(body)
    }

    async fn raw_api(
        &self,
        method: reqwest::Method,
        url: &str,
        configure: &impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<bytes::Bytes> {
        let client = self.client.lock().await;
        let rb = client
            .request(method, url)
            .header("Accept", "application/json;charset=UTF-8")
            .header("Referer", WEB_URL)
            .query(&[("noCache", random_no_cache())]);
        let rb = configure(rb);
        let resp = rb
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "(unreadable)".to_string());
            return Err(TokimoVfsError::Other(format!("cloud189: HTTP {status} — {body}")));
        }
        resp.bytes()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189: read body: {e}")))
    }

    async fn get_files(&self, folder_id: &str, dir_path: &Path) -> Result<Vec<FileInfo>> {
        let mut result = Vec::new();
        let mut page_num = 1usize;
        loop {
            let page_str = page_num.to_string();
            let fid = folder_id.to_string();
            let order_by = self.order_by.clone();
            let order_dir = self.order_direction.clone();
            let body = self
                .api(
                    reqwest::Method::GET,
                    &format!("{WEB_URL}/api/open/file/listFiles.action"),
                    |req| {
                        req.query(&[
                            ("pageSize", "60"),
                            ("pageNum", &page_str),
                            ("mediaType", "0"),
                            ("folderId", &fid),
                            ("iconOption", "5"),
                            ("orderBy", &order_by),
                            ("descending", &order_dir),
                        ])
                    },
                )
                .await?;

            let resp: FilesResp =
                serde_json::from_slice(&body).map_err(|e| TokimoVfsError::Other(format!("cloud189 list parse: {e}")))?;

            if resp.res_code != 0 {
                return Err(TokimoVfsError::Other(format!("cloud189 list: {}", resp.res_message)));
            }
            if resp.file_list_ao.count == 0 {
                break;
            }
            for folder in &resp.file_list_ao.folder_list {
                result.push(folder_to_info(folder, dir_path));
            }
            for file in &resp.file_list_ao.file_list {
                result.push(file_to_info(file, dir_path));
            }
            page_num += 1;
        }
        Ok(result)
    }

    /// Walk the path tree to get the numeric ID and whether it's a folder.
    async fn resolve_id(&self, path: &Path) -> Result<(String, bool)> {
        let segs: Vec<&str> = path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();

        if segs.is_empty() {
            return Ok((self.root_folder_id.clone(), true));
        }

        let mut current_id = self.root_folder_id.clone();
        let total = segs.len();
        for (i, seg) in segs.iter().enumerate() {
            let cid = current_id.clone();
            let body = self
                .api(
                    reqwest::Method::GET,
                    &format!("{WEB_URL}/api/open/file/listFiles.action"),
                    |req| {
                        req.query(&[
                            ("pageSize", "100"),
                            ("pageNum", "1"),
                            ("mediaType", "0"),
                            ("folderId", &cid),
                            ("iconOption", "0"),
                        ])
                    },
                )
                .await?;

            let resp: FilesResp = serde_json::from_slice(&body)
                .map_err(|e| TokimoVfsError::Other(format!("cloud189 resolve parse: {e}")))?;

            let is_last = i == total - 1;
            if let Some(folder) = resp.file_list_ao.folder_list.iter().find(|f| f.name == *seg) {
                current_id = folder.id.to_string();
                if is_last {
                    return Ok((current_id, true));
                }
                continue;
            }
            if is_last && let Some(file) = resp.file_list_ao.file_list.iter().find(|f| f.name == *seg) {
                return Ok((file.id.to_string(), false));
            }
            return Err(TokimoVfsError::NotFound(format!("cloud189: '{seg}' not found")));
        }
        Ok((current_id, true))
    }

    async fn get_download_url(&self, file_id: &str) -> Result<String> {
        let fid = file_id.to_string();
        let body = self
            .api(
                reqwest::Method::GET,
                &format!("{WEB_URL}/api/portal/getFileInfo.action"),
                |req| req.query(&[("fileId", &fid)]),
            )
            .await?;

        let resp: DownResp = serde_json::from_slice(&body)
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 getFileInfo parse: {e}")))?;

        let raw = if resp.download_url.is_empty() {
            resp.file_download_url
        } else {
            resp.download_url
        };

        if raw.is_empty() {
            return Err(TokimoVfsError::Other("cloud189: no download URL in response".to_string()));
        }

        let url = if raw.starts_with("//") {
            format!("https:{raw}")
        } else {
            raw.replace("http://", "https://")
        };

        // Follow CDN redirect without consuming the body
        let client = self.client.lock().await;
        let resp = client
            .get(&url)
            .header("User-Agent", DEFAULT_USER_AGENT)
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 dl redirect: {e}")))?;

        if resp.status().is_redirection()
            && let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok())
        {
            return Ok(loc.replace("http://", "https://"));
        }
        Ok(url)
    }

    /// Get or refresh the upload RSA key cache.
    async fn get_res_key(&self) -> Result<(String, String)> {
        {
            let c = self.rsa_cache.read().await;
            if let Some(cache) = &*c
                && cache.expires_at > Instant::now()
            {
                return Ok((cache.pub_key_pem.clone(), cache.pk_id.clone()));
            }
        }

        let body = self
            .api(
                reqwest::Method::GET,
                &format!("{WEB_URL}/api/security/generateRsaKey.action"),
                |req| req,
            )
            .await?;

        let key: RsaKeyResp =
            serde_json::from_slice(&body).map_err(|e| TokimoVfsError::Other(format!("cloud189 getRsaKey parse: {e}")))?;

        let pub_key_pem = make_public_key_pem(&key.pub_key);

        // expire is a ms epoch; calculate duration from now
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let ttl_ms = (key.expire as u64).saturating_sub(now_ms);
        let expires_at = Instant::now() + Duration::from_millis(ttl_ms.max(60_000));

        *self.rsa_cache.write().await = Some(RsaCache {
            pub_key_pem: pub_key_pem.clone(),
            pk_id: key.pk_id.clone(),
            expires_at,
        });

        Ok((pub_key_pem, key.pk_id))
    }

    /// Get session key for upload signing.
    async fn get_session_key(&self) -> Result<String> {
        let body = self
            .api(
                reqwest::Method::GET,
                &format!("{WEB_URL}/v2/getUserBriefInfo.action"),
                |req| req,
            )
            .await?;

        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 getUserBriefInfo parse: {e}")))?;

        json.get("sessionKey")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .ok_or_else(|| TokimoVfsError::Other("cloud189: no sessionKey in response".to_string()))
    }

    /// Execute a signed upload API request.
    /// Equivalent to OpenList's `Cloud189.uploadRequest()`.
    async fn upload_request(
        &self,
        uri: &str,
        form: &HashMap<&str, &str>,
        session_key: &str,
    ) -> Result<serde_json::Value> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();

        // Generate random AES key (16–32 bytes), take first 16 bytes for encryption
        let aes_key_hex = random_hex_string(16); // 32 hex chars = 16 bytes
        let aes_key: [u8; 16] = {
            let bytes = hex::decode(&aes_key_hex).expect("valid hex");
            bytes.try_into().expect("exactly 16 bytes")
        };
        // Use raw aes_key_hex as the "l" string for HMAC
        let l = aes_key_hex.as_bytes();

        // Encode form params (sorted alphabetically) and AES-encrypt
        let form_sorted = encode_form_sorted(form);
        let encrypted_params = aes_ecb_hex(form_sorted.as_bytes(), &aes_key);

        // HMAC-SHA1 signature
        let sign_data =
            format!("SessionKey={session_key}&Operate=GET&RequestURI={uri}&Date={timestamp}&params={encrypted_params}");
        let signature = hmac_sha1_hex(l, sign_data.as_bytes());

        // RSA-encrypt the AES key for the EncryptionText header
        let (pub_key_pem, pk_id) = self.get_res_key().await?;
        let encryption_text = rsa_encode_b64(&aes_key, &pub_key_pem)?;

        let x_request_id = random_hex_string(16);

        let client = self.client.lock().await;
        let url = format!("{UPLOAD_URL}{uri}?params={encrypted_params}");
        let resp = client
            .get(&url)
            .header("Accept", "application/json;charset=UTF-8")
            .header("SessionKey", session_key)
            .header("Signature", signature)
            .header("X-Request-Date", &timestamp)
            .header("X-Request-ID", x_request_id)
            .header("EncryptionText", encryption_text)
            .header("PkId", pk_id)
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 uploadRequest: {e}")))?;

        if !resp.status().is_success() {
            return Err(TokimoVfsError::Other(format!(
                "cloud189 uploadRequest HTTP {}",
                resp.status()
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 uploadRequest parse: {e}")))?;

        if json.get("code").and_then(|v| v.as_str()).unwrap_or("") != "SUCCESS" {
            return Err(TokimoVfsError::Other(format!(
                "cloud189 uploadRequest failed: {}",
                json.get("msg").and_then(|v| v.as_str()).unwrap_or("unknown")
            )));
        }

        Ok(json)
    }

    /// Create a batch task (MOVE / COPY / DELETE).
    async fn batch_task(
        &self,
        task_type: &str,
        target_folder_id: &str,
        file_id: &str,
        file_name: &str,
        is_folder: bool,
    ) -> Result<()> {
        let is_folder_val = if is_folder { "1" } else { "0" };
        let task_infos = serde_json::json!([{
            "fileId": file_id,
            "fileName": file_name,
            "isFolder": is_folder_val,
        }])
        .to_string();

        let task_type_owned = task_type.to_string();
        let target_owned = target_folder_id.to_string();
        let task_infos_owned = task_infos.clone();

        let body = self
            .api(
                reqwest::Method::POST,
                &format!("{WEB_URL}/api/open/batch/createBatchTask.action"),
                |req| {
                    req.form(&[
                        ("type", task_type_owned.as_str()),
                        ("targetFolderId", target_owned.as_str()),
                        ("taskInfos", task_infos_owned.as_str()),
                    ])
                },
            )
            .await?;

        let resp: BatchTaskResp =
            serde_json::from_slice(&body).map_err(|e| TokimoVfsError::Other(format!("cloud189 batchTask parse: {e}")))?;

        if resp.res_code != 0 {
            return Err(TokimoVfsError::Other(format!(
                "cloud189 batchTask failed (task_id={})",
                resp.task_id
            )));
        }

        Ok(())
    }

    /// Upload file data using 189's multipart upload API.
    async fn do_upload(&self, parent_folder_id: &str, file_name: &str, data: &[u8]) -> Result<()> {
        let session_key = self.get_session_key().await?;
        let file_size = data.len();
        let part_count = file_size.div_ceil(PART_SIZE).max(1);
        let enc_name = urlencoding::encode(file_name).to_string();

        // Init multipart upload
        let mut form: HashMap<&str, &str> = HashMap::new();
        let parent_str = parent_folder_id.to_string();
        let size_str = file_size.to_string();
        let count_str = PART_SIZE.to_string();
        form.insert("parentFolderId", &parent_str);
        form.insert("fileName", &enc_name);
        form.insert("fileSize", &size_str);
        form.insert("sliceSize", &count_str);
        form.insert("lazyCheck", "1");

        let init_resp = self
            .upload_request("/person/initMultiUpload", &form, &session_key)
            .await?;

        let upload_file_id = init_resp
            .get("data")
            .and_then(|d| d.get("uploadFileId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if upload_file_id.is_empty() {
            return Err(TokimoVfsError::Other(
                "cloud189: no uploadFileId in initMultiUpload response".to_string(),
            ));
        }

        let mut all_md5s = Vec::new();
        let mut total_md5 = <md5::Md5 as md5::Digest>::new();

        for (part_idx, chunk) in data.chunks(PART_SIZE).enumerate() {
            use md5::Digest;
            let part_num = part_idx + 1;
            let chunk_md5_bytes = md5::Md5::digest(chunk);
            let chunk_md5_hex = hex::encode(chunk_md5_bytes);
            let chunk_md5_b64 = B64.encode(chunk_md5_bytes);
            all_md5s.push(chunk_md5_hex.to_uppercase());
            total_md5.update(chunk);

            let part_info = format!("{part_num}-{chunk_md5_b64}");
            let mut url_form: HashMap<&str, &str> = HashMap::new();
            url_form.insert("partInfo", &part_info);
            url_form.insert("uploadFileId", &upload_file_id);

            let url_resp = self
                .upload_request("/person/getMultiUploadUrls", &url_form, &session_key)
                .await?;

            let urls: UploadUrlsResp = serde_json::from_value(url_resp)
                .map_err(|e| TokimoVfsError::Other(format!("cloud189 uploadUrls parse: {e}")))?;

            let part_key = format!("partNumber_{part_num}");
            let part_data = urls
                .upload_urls
                .get(&part_key)
                .ok_or_else(|| TokimoVfsError::Other(format!("cloud189: no upload URL for part {part_num}")))?;

            // Parse headers from URL-encoded string: "key=value&key2=value2"
            let headers_str = urlencoding::decode(&part_data.request_header)
                .unwrap_or_default()
                .to_string();

            let client = self.client.lock().await;
            let mut req = client.put(&part_data.request_url).body(chunk.to_vec());
            for pair in headers_str.split('&') {
                if let Some(eq) = pair.find('=') {
                    req = req.header(&pair[..eq], &pair[eq + 1..]);
                }
            }
            req.send()
                .await
                .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 part upload: {e}")))?;
        }

        use md5::Digest;
        let file_md5 = hex::encode(total_md5.finalize());
        let slice_md5 = if part_count > 1 {
            let joined = all_md5s.join("\n");
            hex::encode(md5::Md5::digest(joined.as_bytes()))
        } else {
            file_md5.clone()
        };

        let mut commit_form: HashMap<&str, &str> = HashMap::new();
        commit_form.insert("uploadFileId", &upload_file_id);
        commit_form.insert("fileMd5", &file_md5);
        commit_form.insert("sliceMd5", &slice_md5);
        commit_form.insert("lazyCheck", "1");
        commit_form.insert("opertype", "3");

        self.upload_request("/person/commitMultiUploadFile", &commit_form, &session_key)
            .await?;

        Ok(())
    }
}

// ─── Meta ─────────────────────────────────────────────────────────────────────

#[async_trait]
impl Meta for Cloud189Driver {
    fn driver_name(&self) -> &'static str {
        DRIVER_NAME
    }

    async fn init(&self) -> Result<()> {
        self.do_login().await
    }

    async fn drop_driver(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        StorageStatus {
            driver: DRIVER_NAME.to_string(),
            state: ConnectionState::Connected,
            error: None,
            capabilities: self.capabilities(),
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        self.caps.clone()
    }
}

// ─── Reader ───────────────────────────────────────────────────────────────────

#[async_trait]
impl Reader for Cloud189Driver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        let (folder_id, _is_dir) = self.resolve_id(path).await?;
        self.get_files(&folder_id, path).await
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        // Stat a file/folder by resolving its parent, then finding it in the listing
        let parent = path.parent().unwrap_or(Path::new(""));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TokimoVfsError::Other("cloud189 stat: invalid path".to_string()))?;

        if parent == Path::new("") && name.is_empty() {
            // root
            return Ok(FileInfo {
                name: "/".to_string(),
                path: path.to_string_lossy().to_string(),
                is_dir: true,
                size: 0,
                modified: None,
            });
        }

        let entries = self.list(parent).await?;
        entries
            .into_iter()
            .find(|e| e.name == name)
            .ok_or_else(|| TokimoVfsError::NotFound(format!("cloud189 stat: '{name}' not found")))
    }

    async fn link(&self, path: &Path) -> Result<Link> {
        let (file_id, is_dir) = self.resolve_id(path).await?;
        if is_dir {
            return Err(TokimoVfsError::Other(
                "cloud189: cannot get link for directory".to_string(),
            ));
        }
        let url = self.get_download_url(&file_id).await?;
        Ok(Link {
            url: Some(url),
            header: HashMap::default(),
            expiry: None,
        })
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        let (file_id, is_dir) = self.resolve_id(path).await?;
        if is_dir {
            return Err(TokimoVfsError::Other(
                "cloud189: cannot read bytes of directory".to_string(),
            ));
        }
        let url = self.get_download_url(&file_id).await?;

        let client = self.client.lock().await;
        let mut req = client.get(&url).header("User-Agent", DEFAULT_USER_AGENT);

        let end = limit.map(|l| offset + l - 1);
        let range_hdr = match (offset, end) {
            (0, None) => None,
            (s, None) => Some(format!("bytes={s}-")),
            (s, Some(e)) => Some(format!("bytes={s}-{e}")),
        };
        if let Some(r) = range_hdr {
            req = req.header("Range", r);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("cloud189 read_bytes: {e}")))?;

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TokimoVfsError::Other(format!("cloud189 read_bytes body: {e}")))?;

        Ok(bytes.to_vec())
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let (file_id, is_dir) = match self.resolve_id(path).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("cloud189 stream_to resolve: {e}");
                return;
            }
        };
        if is_dir {
            return;
        }
        let url = match self.get_download_url(&file_id).await {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("cloud189 stream_to link: {e}");
                return;
            }
        };

        let client = self.client.lock().await;
        let mut req = client.get(&url).header("User-Agent", DEFAULT_USER_AGENT);

        let end = limit.map(|l| offset + l - 1);
        let range_hdr = match (offset, end) {
            (0, None) => None,
            (s, None) => Some(format!("bytes={s}-")),
            (s, Some(e)) => Some(format!("bytes={s}-{e}")),
        };
        if let Some(r) = range_hdr {
            req = req.header("Range", r);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("cloud189 stream_to fetch: {e}");
                return;
            }
        };

        let mut stream = resp.bytes_stream();
        while let Ok(Some(chunk)) = stream.try_next().await {
            if tx.send(chunk.to_vec()).await.is_err() {
                break;
            }
        }
    }
}

// ─── Write capabilities ───────────────────────────────────────────────────────

#[async_trait]
impl Mkdir for Cloud189Driver {
    async fn mkdir(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TokimoVfsError::Other("cloud189 mkdir: invalid path".to_string()))?
            .to_string();

        let (parent_id, _) = self.resolve_id(parent).await?;
        let pid = parent_id.clone();
        let dname = dir_name.clone();

        self.api(
            reqwest::Method::POST,
            &format!("{WEB_URL}/api/open/file/createFolder.action"),
            |req| req.form(&[("parentFolderId", pid.as_str()), ("folderName", dname.as_str())]),
        )
        .await?;

        Ok(())
    }
}

#[async_trait]
impl DeleteFile for Cloud189Driver {
    async fn delete_file(&self, path: &Path) -> Result<()> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let (file_id, _) = self.resolve_id(path).await?;
        self.batch_task("DELETE", "", &file_id, &name, false).await
    }
}

#[async_trait]
impl DeleteDir for Cloud189Driver {
    async fn delete_dir(&self, path: &Path) -> Result<()> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let (folder_id, _) = self.resolve_id(path).await?;
        self.batch_task("DELETE", "", &folder_id, &name, true).await
    }
}

#[async_trait]
impl Rename for Cloud189Driver {
    async fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let new_name = to
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TokimoVfsError::Other("cloud189 rename: invalid target path".to_string()))?
            .to_string();

        let (id, is_dir) = self.resolve_id(from).await?;
        let id_owned = id.clone();
        let new_name_owned = new_name.clone();

        if is_dir {
            self.api(
                reqwest::Method::POST,
                &format!("{WEB_URL}/api/open/file/renameFolder.action"),
                |req| {
                    req.form(&[
                        ("folderId", id_owned.as_str()),
                        ("destFolderName", new_name_owned.as_str()),
                    ])
                },
            )
            .await?;
        } else {
            self.api(
                reqwest::Method::POST,
                &format!("{WEB_URL}/api/open/file/renameFile.action"),
                |req| req.form(&[("fileId", id_owned.as_str()), ("destFileName", new_name_owned.as_str())]),
            )
            .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl MoveFile for Cloud189Driver {
    async fn move_file(&self, src: &Path, dst_dir: &Path) -> Result<()> {
        let name = src.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let (src_id, is_dir) = self.resolve_id(src).await?;
        let (dst_id, _) = self.resolve_id(dst_dir).await?;
        self.batch_task("MOVE", &dst_id, &src_id, &name, is_dir).await
    }
}

#[async_trait]
impl CopyFile for Cloud189Driver {
    async fn copy(&self, src: &Path, dst_dir: &Path) -> Result<()> {
        let name = src.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let (src_id, is_dir) = self.resolve_id(src).await?;
        let (dst_id, _) = self.resolve_id(dst_dir).await?;
        self.batch_task("COPY", &dst_id, &src_id, &name, is_dir).await
    }
}

#[async_trait]
impl PutStream for Cloud189Driver {
    async fn put_stream(&self, path: &Path, _size: u64, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TokimoVfsError::Other("cloud189 put: invalid path".to_string()))?
            .to_string();

        let (parent_id, _) = self.resolve_id(parent).await?;

        // Buffer the stream in memory (189 upload needs total file size upfront)
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            buf.extend_from_slice(&chunk);
        }

        self.do_upload(&parent_id, &file_name, &buf).await
    }
}

// ─── Driver dispatch ──────────────────────────────────────────────────────────

impl Driver for Cloud189Driver {
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
    fn as_put_stream(&self) -> Option<&dyn PutStream> {
        Some(self)
    }
}

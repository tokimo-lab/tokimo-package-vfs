#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct AppConf {
    #[serde(default)]
    pub data: AppConfData,
    #[serde(default)]
    pub msg: String,
    #[serde(default)]
    pub result: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct AppConfData {
    #[serde(rename = "accountType", default)]
    pub account_type: String,
    #[serde(rename = "appKey", default)]
    pub app_key: String,
    #[serde(rename = "clientType", default)]
    pub client_type: i32,
    #[serde(rename = "isOauth2", default)]
    pub is_oauth2: bool,
    #[serde(rename = "mailSuffix", default)]
    pub mail_suffix: String,
    #[serde(rename = "paramId", default)]
    pub param_id: String,
    #[serde(rename = "returnUrl", default)]
    pub return_url: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptConf {
    pub result: i32,
    pub data: EncryptConfData,
}

#[derive(Debug, Deserialize)]
pub struct EncryptConfData {
    pub pre: String,
    #[serde(rename = "pubKey")]
    pub pub_key: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Cloud189FileIcon {
    #[serde(rename = "smallUrl", default)]
    pub small_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Cloud189File {
    pub id: i64,
    #[serde(rename = "lastOpTime", default)]
    pub last_op_time: String,
    pub name: String,
    pub size: i64,
    #[serde(default)]
    pub icon: Cloud189FileIcon,
}

#[derive(Debug, Deserialize)]
pub struct Cloud189Folder {
    pub id: i64,
    #[serde(rename = "lastOpTime", default)]
    pub last_op_time: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct FileListAO {
    #[serde(default)]
    pub count: i32,
    #[serde(rename = "fileList", default)]
    pub file_list: Vec<Cloud189File>,
    #[serde(rename = "folderList", default)]
    pub folder_list: Vec<Cloud189Folder>,
}

#[derive(Debug, Deserialize)]
pub struct FilesResp {
    #[serde(rename = "res_code", default)]
    pub res_code: i32,
    #[serde(rename = "res_message", default)]
    pub res_message: String,
    #[serde(rename = "fileListAO", default)]
    pub file_list_ao: FileListAO,
}

#[derive(Debug, Deserialize, Default)]
pub struct DownResp {
    #[serde(rename = "res_code", default)]
    pub res_code: i32,
    #[serde(rename = "downloadUrl", default)]
    pub download_url: String,
    #[serde(rename = "fileDownloadUrl", default)]
    pub file_download_url: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct UploadUrlPart {
    #[serde(rename = "requestURL", default)]
    pub request_url: String,
    #[serde(rename = "requestHeader", default)]
    pub request_header: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct UploadUrlsResp {
    #[serde(default)]
    pub code: String,
    #[serde(rename = "uploadUrls", default)]
    pub upload_urls: std::collections::HashMap<String, UploadUrlPart>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RsaKeyResp {
    /// Expiry timestamp in milliseconds
    #[serde(default)]
    pub expire: i64,
    #[serde(rename = "pkId", default)]
    pub pk_id: String,
    #[serde(rename = "pubKey", default)]
    pub pub_key: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct BatchTaskResp {
    #[serde(rename = "taskId", default)]
    pub task_id: String,
    #[serde(rename = "res_code", default)]
    pub res_code: i32,
}

//! NFS 驱动 — 支持 `NFSv3（nfs3_client）和` `NFSv4（nfs4_client），纯` Rust 用户态实现。
//! 无需 OS mount，无需 root 权限；`version` 可省略，默认自动探测协议版本。
//!
//! JSON 配置字段：
//!   host         — NFS 服务器地址，如 "127.0.0.1"
//!   `export_path`  — 服务器导出路径，如 "/srv/media"
//!   version      — 可选："3" 或 "4"；省略时优先尝试 NFSv4.1，失败后回退 `NFSv3`
//!   insecure     — 允许非特权源端口（默认 false）；若 exports 未配置 insecure，v3/v4 都需要特权源端口
//!   uid          — `NFSv3` `专用：AUTH_UNIX` uid（默认 0）
//!   gid          — `NFSv3` `专用：AUTH_UNIX` gid（默认 0）

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use nfs3_client::nfs3_types::nfs3::{
    GETATTR3args, LOOKUP3args, Nfs3Option, Nfs3Result, READ3args, READDIRPLUS3args, diropargs3, fattr3, filename3,
    ftype3, nfs_fh3, nfsstat3, nfstime3,
};
use nfs3_client::nfs3_types::rpc::{auth_unix, opaque_auth};
use nfs3_client::nfs3_types::xdr_codec::Opaque;
use nfs3_client::tokio::TokioConnector;
use nfs3_client::{Nfs3Connection, Nfs3ConnectionBuilder};
use nfs4::FileAttributeId;
use nfs4_client::Client as Nfs4Client;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc::Sender;
use tracing::{error, warn};

use tokimo_vfs_core::driver::config::{DriverConfig, DriverFactory};
use tokimo_vfs_core::driver::traits::{Driver, Meta, Reader};
use tokimo_vfs_core::error::{TokimoVfsError, Result};
use tokimo_vfs_core::model::obj::FileInfo;
use tokimo_vfs_core::model::storage::{ConnectionState, StorageCapabilities, StorageStatus};

// NFSv3 具体连接类型
type NfsConn = Nfs3Connection<nfs3_client::tokio::TokioIo<tokio::net::TcpStream>>;

pub const CONFIG: DriverConfig = DriverConfig {
    name: "nfs",
    description: "NFS（NFSv3/NFSv4 纯 Rust 客户端，无需 OS mount）",
};

inventory::submit!(DriverFactory {
    config: CONFIG,
    create: factory,
});

// ---- 配置结构 ---------------------------------------------------------------

#[derive(Clone, Copy)]
enum ResolvedNfsVersion {
    V3 { privileged_port: bool, uid: u32, gid: u32 },
    V4 { privileged_port: bool },
}

enum NfsVersion {
    Auto {
        preferred: ResolvedNfsVersion,
        fallback: ResolvedNfsVersion,
    },
    Fixed(ResolvedNfsVersion),
}

pub struct NfsDriver {
    host: String,
    export_path: String,
    version: NfsVersion,
    resolved: Arc<Mutex<Option<ResolvedNfsVersion>>>,
    connected: Arc<AtomicBool>,
}

pub fn factory(params: &serde_json::Value) -> Result<Box<dyn Driver>> {
    let host = params["host"]
        .as_str()
        .ok_or_else(|| TokimoVfsError::InvalidConfig("nfs 驱动缺少 'host' 字段".into()))?
        .to_string();
    let export_path = params["export_path"]
        .as_str()
        .ok_or_else(|| TokimoVfsError::InvalidConfig("nfs 驱动缺少 'export_path' 字段".into()))?
        .to_string();

    let insecure = params["insecure"].as_bool().unwrap_or(false);
    let v4 = ResolvedNfsVersion::V4 {
        privileged_port: !insecure,
    };
    let v3 = ResolvedNfsVersion::V3 {
        privileged_port: !insecure,
        uid: params["uid"].as_u64().unwrap_or(0) as u32,
        gid: params["gid"].as_u64().unwrap_or(0) as u32,
    };
    let version = match params["version"].as_str() {
        None | Some("auto") => NfsVersion::Auto {
            preferred: v4,
            fallback: v3,
        },
        Some("4") => NfsVersion::Fixed(v4),
        Some("3") => NfsVersion::Fixed(v3),
        Some(other) => {
            return Err(TokimoVfsError::InvalidConfig(format!(
                "nfs 驱动的 'version' 只能是 '3'、'4' 或省略，收到 '{other}'"
            )));
        }
    };

    Ok(Box::new(NfsDriver {
        host,
        export_path,
        version,
        resolved: Arc::new(Mutex::new(None)),
        connected: Arc::new(AtomicBool::new(false)),
    }))
}

// ---- 共用工具 ---------------------------------------------------------------

/// Classify `NFSv3` status codes into `TokimoVfsError`.
fn classify_nfs3_status(status: nfsstat3, context: &str) -> TokimoVfsError {
    match status {
        nfsstat3::NFS3ERR_NOENT => TokimoVfsError::NotFound(format!("nfs {context}: {status:?}")),
        nfsstat3::NFS3ERR_STALE | nfsstat3::NFS3ERR_BADHANDLE | nfsstat3::NFS3ERR_IO => {
            TokimoVfsError::ConnectionError(format!("nfs {context}: {status:?}"))
        }
        _ => TokimoVfsError::Other(format!("nfs {context}: {status:?}")),
    }
}

/// Map `nfs3_client::error::Error` to `TokimoVfsError`.
fn nfs3_err(context: &str, err: nfs3_client::error::Error) -> TokimoVfsError {
    match &err {
        nfs3_client::error::Error::NfsError(status) => classify_nfs3_status(*status, context),
        nfs3_client::error::Error::Io(_)
        | nfs3_client::error::Error::Rpc(_)
        | nfs3_client::error::Error::Portmap(_) => TokimoVfsError::ConnectionError(format!("nfs {context}: {err}")),
        _ => TokimoVfsError::Other(format!("nfs {context}: {err}")),
    }
}

/// Map `nfs4_client::Error` to `TokimoVfsError`.
fn nfs4_err(context: &str, err: nfs4_client::Error) -> TokimoVfsError {
    match &err {
        nfs4_client::Error::Io(_) | nfs4_client::Error::SunRpc(_) => {
            TokimoVfsError::ConnectionError(format!("nfs4 {context}: {err:?}"))
        }
        nfs4_client::Error::Protocol(status_err) => match status_err {
            nfs4::StatusError::NoEnt => TokimoVfsError::NotFound(format!("nfs4 {context}: {err:?}")),
            nfs4::StatusError::Stale | nfs4::StatusError::FhExpired => {
                TokimoVfsError::ConnectionError(format!("nfs4 {context}: {err:?}"))
            }
            _ => TokimoVfsError::Other(format!("nfs4 {context}: {err:?}")),
        },
        _ => TokimoVfsError::Other(format!("nfs4 {context}: {err:?}")),
    }
}

/// 将 `export_path` + driver path 拼合成 NFS4 完整服务器路径
fn nfs4_full_path(export_path: &str, path: &Path) -> PathBuf {
    let rel = path.to_string_lossy();
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        PathBuf::from(export_path)
    } else {
        Path::new(export_path).join(rel)
    }
}

// ---- NFSv3 工具 ------------------------------------------------------------

fn time_to_datetime(t: nfstime3) -> DateTime<Utc> {
    let st = UNIX_EPOCH + Duration::new(u64::from(t.seconds), t.nseconds);
    DateTime::<Utc>::from(st)
}

fn fattr_to_fileinfo(name: &str, path_str: &str, attr: &fattr3) -> FileInfo {
    FileInfo {
        name: name.to_string(),
        path: path_str.to_string(),
        size: attr.size,
        is_dir: matches!(attr.type_, ftype3::NF3DIR),
        modified: Some(time_to_datetime(attr.mtime)),
    }
}

impl NfsDriver {
    fn cached_version(&self) -> Option<ResolvedNfsVersion> {
        *self.resolved.lock().unwrap()
    }

    fn set_cached_version(&self, version: ResolvedNfsVersion) {
        *self.resolved.lock().unwrap() = Some(version);
    }

    async fn probe_version(&self, version: ResolvedNfsVersion) -> Result<()> {
        match version {
            ResolvedNfsVersion::V3 {
                privileged_port,
                uid,
                gid,
            } => {
                let conn = self.connect_v3(privileged_port, uid, gid).await?;
                conn.unmount().await.ok();
                Ok(())
            }
            ResolvedNfsVersion::V4 { privileged_port } => {
                let host = self.host.clone();
                let export_path = self.export_path.clone();
                tokio::task::spawn_blocking(move || {
                    let mut c = connect_nfs4(&host, privileged_port)?;
                    c.look_up(Path::new(&export_path))?;
                    Ok::<_, nfs4_client::Error>(())
                })
                .await
                .map_err(|e| TokimoVfsError::ConnectionError(format!("nfs spawn: {e}")))?
                .map_err(|e| TokimoVfsError::ConnectionError(format!("NFS4 连接失败: {e:?}")))
            }
        }
    }

    async fn active_version(&self) -> Result<ResolvedNfsVersion> {
        if let Some(version) = self.cached_version() {
            return Ok(version);
        }

        let version = match self.version {
            NfsVersion::Fixed(version) => {
                self.probe_version(version).await?;
                version
            }
            NfsVersion::Auto { preferred, fallback } => match self.probe_version(preferred).await {
                Ok(()) => preferred,
                Err(primary_err) => {
                    warn!("NFS 自动探测：优先协议失败，尝试回退: {}", primary_err);
                    self.probe_version(fallback).await.map_err(|fallback_err| {
                        TokimoVfsError::ConnectionError(format!(
                            "NFS 自动探测失败: primary={primary_err}, fallback={fallback_err}"
                        ))
                    })?;
                    fallback
                }
            },
        };

        self.set_cached_version(version);
        Ok(version)
    }

    /// 建立新的 `NFSv3` 连接（每次操作独立连接，支持并发）
    async fn connect_v3(&self, privileged_port: bool, uid: u32, gid: u32) -> Result<NfsConn> {
        let cred = opaque_auth::auth_unix(&auth_unix {
            stamp: 0,
            machinename: Opaque::new(std::borrow::Cow::Borrowed(b"")),
            uid,
            gid,
            gids: vec![],
        });
        Nfs3ConnectionBuilder::new(TokioConnector, self.host.clone(), self.export_path.clone())
            .connect_from_privileged_port(privileged_port)
            .credential(cred)
            .mount()
            .await
            .map_err(|e| TokimoVfsError::ConnectionError(format!("NFS mount 失败: {e}")))
    }
}

/// `NFSv3` 路径走查：从根 fh 逐级 lookup，返回目标 fh
async fn resolve_path_v3(conn: &mut NfsConn, path: &Path) -> Result<nfs_fh3> {
    let path_str = path.to_string_lossy();
    let components: Vec<&str> = path_str
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    let mut current_fh = conn.root_nfs_fh3();
    for comp in components {
        let res = conn
            .lookup(&LOOKUP3args {
                what: diropargs3 {
                    dir: current_fh,
                    name: filename3::from(comp.as_bytes()),
                },
            })
            .await
            .map_err(|e| nfs3_err("lookup", e))?;
        match res {
            Nfs3Result::Ok(ok) => current_fh = ok.object,
            Nfs3Result::Err((s, _)) => return Err(classify_nfs3_status(s, &format!("lookup '{comp}'"))),
        }
    }
    Ok(current_fh)
}

// ---- NFSv4 工具 ------------------------------------------------------------

fn connect_tcp(host: &str, port: u16, privileged_port: bool) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = None;

    for addr in addrs {
        if privileged_port {
            let mut fallback_to_unprivileged = false;
            for local_port in 300..1024 {
                let socket = Socket::new(
                    if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
                    Type::STREAM,
                    Some(Protocol::TCP),
                )?;
                let local_addr = match addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_port),
                };
                if let Err(e) = socket.bind(&local_addr.into()) {
                    last_err = Some(e);
                    if matches!(
                        last_err.as_ref().map(io::Error::kind),
                        Some(io::ErrorKind::PermissionDenied)
                    ) {
                        fallback_to_unprivileged = true;
                        break;
                    }
                    continue;
                }
                match socket.connect(&addr.into()) {
                    Ok(()) => return Ok(socket.into()),
                    Err(e) => last_err = Some(e),
                }
            }
            if fallback_to_unprivileged {
                warn!(
                    "NFS privileged source port unavailable for {}, retrying with unprivileged port",
                    addr
                );
            }
            if fallback_to_unprivileged {
                match TcpStream::connect(addr) {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_err = Some(e),
                }
            }
        } else {
            match TcpStream::connect(addr) {
                Ok(stream) => return Ok(stream),
                Err(e) => last_err = Some(e),
            }
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no usable TCP address")))
}

/// 建立 `NFSv4` blocking 连接（用于 `spawn_blocking` 内）
fn connect_nfs4(host: &str, privileged_port: bool) -> std::result::Result<Nfs4Client<TcpStream>, nfs4_client::Error> {
    let stream = connect_tcp(host, nfs4_client::NFS_PORT, privileged_port).map_err(nfs4_client::Error::Io)?;
    Nfs4Client::new(stream)
}

fn nfs4_time_to_datetime(t: &nfs4::Time) -> Option<DateTime<Utc>> {
    if t.seconds < 0 {
        return None;
    }
    let dur = Duration::new(t.seconds as u64, t.nseconds);
    Some(DateTime::<Utc>::from(UNIX_EPOCH + dur))
}

fn nfs4_attrs_to_fileinfo(name: &str, path_str: &str, attrs: &nfs4::FileAttributes) -> FileInfo {
    let size = attrs.get_as::<u64>(FileAttributeId::Size).copied().unwrap_or(0);
    let is_dir = attrs
        .get_as::<nfs4::FileType>(FileAttributeId::Type)
        .is_some_and(|t| matches!(t, nfs4::FileType::Directory));
    let modified = attrs
        .get_as::<nfs4::Time>(FileAttributeId::TimeModify)
        .and_then(nfs4_time_to_datetime);
    FileInfo {
        name: name.to_string(),
        path: path_str.to_string(),
        size,
        is_dir,
        modified,
    }
}

// ---- Driver 实现 -----------------------------------------------------------

#[async_trait]
impl Meta for NfsDriver {
    fn driver_name(&self) -> &'static str {
        "nfs"
    }

    async fn init(&self) -> Result<()> {
        self.active_version().await?;
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn drop_driver(&self) -> Result<()> {
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn status(&self) -> StorageStatus {
        let ok = self.connected.load(Ordering::SeqCst);
        StorageStatus {
            driver: "nfs".into(),
            state: if ok {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            },
            error: None,
            capabilities: self.capabilities(),
        }
    }

    fn capabilities(&self) -> StorageCapabilities {
        StorageCapabilities {
            list: true,
            read: true,
            mkdir: false,
            delete_file: false,
            delete_dir: false,
            rename: false,
            write: false,
            symlink: false,
            range_read: true,
        }
    }
}

#[async_trait]
impl Reader for NfsDriver {
    async fn list(&self, path: &Path) -> Result<Vec<FileInfo>> {
        match self.active_version().await? {
            ResolvedNfsVersion::V3 {
                privileged_port,
                uid,
                gid,
            } => self.list_v3(path, privileged_port, uid, gid).await,
            ResolvedNfsVersion::V4 { privileged_port } => self.list_v4(path, privileged_port).await,
        }
    }

    async fn stat(&self, path: &Path) -> Result<FileInfo> {
        match self.active_version().await? {
            ResolvedNfsVersion::V3 {
                privileged_port,
                uid,
                gid,
            } => self.stat_v3(path, privileged_port, uid, gid).await,
            ResolvedNfsVersion::V4 { privileged_port } => self.stat_v4(path, privileged_port).await,
        }
    }

    async fn read_bytes(&self, path: &Path, offset: u64, limit: Option<u64>) -> Result<Vec<u8>> {
        match self.active_version().await? {
            ResolvedNfsVersion::V3 {
                privileged_port,
                uid,
                gid,
            } => self.read_bytes_v3(path, offset, limit, privileged_port, uid, gid).await,
            ResolvedNfsVersion::V4 { privileged_port } => {
                self.read_bytes_v4(path, offset, limit, privileged_port).await
            }
        }
    }

    async fn stream_to(&self, path: &Path, offset: u64, limit: Option<u64>, tx: Sender<Vec<u8>>) {
        let version = match self.active_version().await {
            Ok(version) => version,
            Err(e) => {
                error!("stream_to nfs init: {}", e);
                return;
            }
        };
        match version {
            ResolvedNfsVersion::V3 {
                privileged_port,
                uid,
                gid,
            } => {
                self.stream_to_v3(path, offset, limit, tx, privileged_port, uid, gid)
                    .await;
            }
            ResolvedNfsVersion::V4 { privileged_port } => {
                self.stream_to_v4(path, offset, limit, tx, privileged_port).await;
            }
        }
    }
}

// ---- NFSv3 方法实现 ---------------------------------------------------------

impl NfsDriver {
    async fn list_v3(&self, path: &Path, privileged_port: bool, uid: u32, gid: u32) -> Result<Vec<FileInfo>> {
        let mut conn = self.connect_v3(privileged_port, uid, gid).await?;
        let dir_fh = resolve_path_v3(&mut conn, path).await?;
        let path_prefix = path.to_string_lossy().trim_end_matches('/').to_string();

        let mut entries: Vec<FileInfo> = Vec::new();
        let mut cookie = 0u64;
        let mut cookieverf = nfs3_client::nfs3_types::nfs3::cookieverf3::default();

        loop {
            let res = conn
                .readdirplus(&READDIRPLUS3args {
                    dir: dir_fh.clone(),
                    cookie,
                    cookieverf,
                    dircount: 4096,
                    maxcount: 65536,
                })
                .await
                .map_err(|e| nfs3_err("readdirplus", e))?;

            match res {
                Nfs3Result::Ok(ok) => {
                    cookieverf = ok.cookieverf;
                    let eof = ok.reply.eof;

                    for entry in ok.reply.entries.0 {
                        let name = String::from_utf8_lossy(entry.name.as_ref()).into_owned();
                        if name == "." || name == ".." {
                            continue;
                        }
                        cookie = entry.cookie;
                        let rel_path = format!("{path_prefix}/{name}");
                        if let Nfs3Option::Some(ref attr) = entry.name_attributes {
                            entries.push(fattr_to_fileinfo(&name, &rel_path, attr));
                        } else {
                            entries.push(FileInfo {
                                name,
                                path: rel_path,
                                size: 0,
                                is_dir: false,
                                modified: None,
                            });
                        }
                    }

                    if eof {
                        break;
                    }
                }
                Nfs3Result::Err((s, _)) => {
                    conn.unmount().await.ok();
                    return Err(classify_nfs3_status(s, "readdirplus"));
                }
            }
        }

        conn.unmount().await.ok();
        Ok(entries)
    }

    async fn stat_v3(&self, path: &Path, privileged_port: bool, uid: u32, gid: u32) -> Result<FileInfo> {
        let mut conn = self.connect_v3(privileged_port, uid, gid).await?;
        let fh = resolve_path_v3(&mut conn, path).await?;

        let res = conn
            .getattr(&GETATTR3args { object: fh })
            .await
            .map_err(|e| nfs3_err("getattr", e))?;

        conn.unmount().await.ok();

        match res {
            Nfs3Result::Ok(ok) => {
                let attr = ok.obj_attributes;
                let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
                let path_str = format!("/{}", path.to_string_lossy().trim_start_matches('/'));
                Ok(fattr_to_fileinfo(&name, &path_str, &attr))
            }
            Nfs3Result::Err((s, _)) => Err(classify_nfs3_status(s, "getattr")),
        }
    }

    async fn read_bytes_v3(
        &self,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
        privileged_port: bool,
        uid: u32,
        gid: u32,
    ) -> Result<Vec<u8>> {
        let mut conn = self.connect_v3(privileged_port, uid, gid).await?;
        let fh = resolve_path_v3(&mut conn, path).await?;
        const CHUNK: u32 = 256 * 1024;

        let mut buf = Vec::new();
        let mut pos = offset;
        let mut remain = limit;

        loop {
            let to_read = match remain {
                Some(0) => break,
                Some(r) => r.min(u64::from(CHUNK)) as u32,
                None => CHUNK,
            };

            let res = conn
                .read(&READ3args {
                    file: fh.clone(),
                    offset: pos,
                    count: to_read,
                })
                .await
                .map_err(|e| nfs3_err("read", e))?;

            match res {
                Nfs3Result::Ok(ok) => {
                    let data = ok.data.0.as_ref();
                    buf.extend_from_slice(data);
                    pos += data.len() as u64;
                    if let Some(ref mut r) = remain {
                        *r = r.saturating_sub(data.len() as u64);
                    }
                    if ok.eof || data.is_empty() {
                        break;
                    }
                }
                Nfs3Result::Err((s, _)) => {
                    conn.unmount().await.ok();
                    return Err(classify_nfs3_status(s, "read"));
                }
            }
        }

        conn.unmount().await.ok();
        Ok(buf)
    }

    #[allow(clippy::too_many_arguments)]
    async fn stream_to_v3(
        &self,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
        tx: Sender<Vec<u8>>,
        privileged_port: bool,
        uid: u32,
        gid: u32,
    ) {
        let mut conn = match self.connect_v3(privileged_port, uid, gid).await {
            Ok(c) => c,
            Err(e) => {
                error!("stream_to_v3 connect: {}", e);
                return;
            }
        };
        let fh = match resolve_path_v3(&mut conn, path).await {
            Ok(fh) => fh,
            Err(e) => {
                error!("stream_to_v3 resolve: {}", e);
                conn.unmount().await.ok();
                return;
            }
        };

        const CHUNK: u32 = 256 * 1024;
        let mut pos = offset;
        let mut remain = limit;

        loop {
            let to_read = match remain {
                Some(0) => break,
                Some(r) => r.min(u64::from(CHUNK)) as u32,
                None => CHUNK,
            };

            let res = conn
                .read(&READ3args {
                    file: fh.clone(),
                    offset: pos,
                    count: to_read,
                })
                .await;

            match res {
                Ok(Nfs3Result::Ok(ok)) => {
                    let data = ok.data.0.into_owned();
                    let n = data.len() as u64;
                    if n == 0 {
                        break;
                    }
                    let eof = ok.eof;
                    pos += n;
                    if let Some(ref mut r) = remain {
                        *r = r.saturating_sub(n);
                    }
                    if tx.send(data).await.is_err() {
                        break;
                    }
                    if eof {
                        break;
                    }
                }
                Ok(Nfs3Result::Err((s, _))) => {
                    error!("stream_to_v3 read: {:?}", s);
                    break;
                }
                Err(e) => {
                    error!("stream_to_v3 rpc: {}", e);
                    break;
                }
            }
        }

        conn.unmount().await.ok();
    }
}

// ---- NFSv4 方法实现 ---------------------------------------------------------

impl NfsDriver {
    async fn list_v4(&self, path: &Path, privileged_port: bool) -> Result<Vec<FileInfo>> {
        let host = self.host.clone();
        let full_path = nfs4_full_path(&self.export_path, path);
        let path_prefix = path.to_string_lossy().trim_end_matches('/').to_string();

        let entries = tokio::task::spawn_blocking(move || {
            let mut c = connect_nfs4(&host, privileged_port).map_err(|e| nfs4_err("connect", e))?;
            let fh = c.look_up(&full_path).map_err(|e| nfs4_err("lookup", e))?;
            let attrs = [
                FileAttributeId::Size,
                FileAttributeId::Type,
                FileAttributeId::TimeModify,
            ]
            .into_iter()
            .collect();
            c.read_dir(fh, attrs).map_err(|e| nfs4_err("readdir", e))
        })
        .await
        .map_err(|e| TokimoVfsError::ConnectionError(format!("nfs4 spawn: {e}")))??;

        Ok(entries
            .into_iter()
            .filter(|e| e.name != "." && e.name != "..")
            .map(|e| {
                let rel_path = format!("{}/{}", path_prefix, e.name);
                nfs4_attrs_to_fileinfo(&e.name, &rel_path, &e.attrs)
            })
            .collect())
    }

    async fn stat_v4(&self, path: &Path, privileged_port: bool) -> Result<FileInfo> {
        let host = self.host.clone();
        let full_path = nfs4_full_path(&self.export_path, path);
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let path_str = format!("/{}", path.to_string_lossy().trim_start_matches('/'));

        let attr_res = tokio::task::spawn_blocking(move || {
            let mut c = connect_nfs4(&host, privileged_port).map_err(|e| nfs4_err("connect", e))?;
            let fh = c.look_up(&full_path).map_err(|e| nfs4_err("lookup", e))?;
            c.get_attr(fh).map_err(|e| nfs4_err("getattr", e))
        })
        .await
        .map_err(|e| TokimoVfsError::ConnectionError(format!("nfs4 spawn: {e}")))??;

        Ok(nfs4_attrs_to_fileinfo(&name, &path_str, &attr_res.object_attributes))
    }

    async fn read_bytes_v4(
        &self,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
        privileged_port: bool,
    ) -> Result<Vec<u8>> {
        let host = self.host.clone();
        let full_path = nfs4_full_path(&self.export_path, path);

        tokio::task::spawn_blocking(move || {
            let mut c = connect_nfs4(&host, privileged_port).map_err(|e| nfs4_err("connect", e))?;
            let fh = c.look_up(&full_path).map_err(|e| nfs4_err("lookup", e))?;
            const CHUNK: u32 = 256 * 1024;
            let mut buf = Vec::new();
            let mut pos = offset;
            let mut remain = limit;

            loop {
                let to_read = match remain {
                    Some(0) => break,
                    Some(r) => r.min(u64::from(CHUNK)) as u32,
                    None => CHUNK,
                };
                let res = c.read(fh.clone(), pos, to_read).map_err(|e| nfs4_err("read", e))?;
                let n = res.data.len() as u64;
                if n == 0 {
                    break;
                }
                pos += n;
                if let Some(ref mut r) = remain {
                    *r = r.saturating_sub(n);
                }
                buf.extend_from_slice(&res.data);
                if res.eof {
                    break;
                }
            }
            Ok(buf)
        })
        .await
        .map_err(|e| TokimoVfsError::ConnectionError(format!("nfs4 spawn: {e}")))?
    }

    async fn stream_to_v4(
        &self,
        path: &Path,
        offset: u64,
        limit: Option<u64>,
        tx: Sender<Vec<u8>>,
        privileged_port: bool,
    ) {
        let host = self.host.clone();
        let full_path = nfs4_full_path(&self.export_path, path);

        // 使用 tokio mpsc 桥接 blocking 线程与 async 发送端
        let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

        let _join = tokio::task::spawn_blocking(move || {
            let mut c = match connect_nfs4(&host, privileged_port) {
                Ok(c) => c,
                Err(e) => {
                    error!("stream_to_v4 connect: {:?}", e);
                    return;
                }
            };
            let fh = match c.look_up(&full_path) {
                Ok(fh) => fh,
                Err(e) => {
                    error!("stream_to_v4 lookup: {:?}", e);
                    return;
                }
            };

            const CHUNK: u32 = 256 * 1024;
            let mut pos = offset;
            let mut remain = limit;

            loop {
                let to_read = match remain {
                    Some(0) => break,
                    Some(r) => r.min(u64::from(CHUNK)) as u32,
                    None => CHUNK,
                };
                match c.read(fh.clone(), pos, to_read) {
                    Ok(res) => {
                        let n = res.data.len() as u64;
                        if n == 0 {
                            break;
                        }
                        pos += n;
                        if let Some(ref mut r) = remain {
                            *r = r.saturating_sub(n);
                        }
                        let eof = res.eof;
                        if raw_tx.blocking_send(res.data).is_err() {
                            break;
                        }
                        if eof {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("stream_to_v4 read: {:?}", e);
                        break;
                    }
                }
            }
        });

        while let Some(chunk) = raw_rx.recv().await {
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
    }
}

impl Driver for NfsDriver {}

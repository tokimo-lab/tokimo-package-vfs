# tokimo-package-vfs

Unified async virtual filesystem (VFS) layer for [Tokimo](https://github.com/tokimo-lab/tokimo).

A single `Driver` trait fronts local disk, network shares, cloud object storage,
and a handful of consumer cloud drives, plus a stream-oriented op layer for
media-friendly large-file workflows (range reads, parallel chunk download,
byte-range copy, walking, watching).

## Workspace crates

| Crate | Purpose |
| --- | --- |
| [`tokimo-vfs-core`](./packages/core) | `Driver` / `FileMeta` / `FileChange` traits, errors, capability flags |
| [`tokimo-vfs`](./packages/fs) | All driver implementations (see matrix below) |
| [`tokimo-vfs-op`](./packages/op) | High-level op layer — range reads, parallel copy, walker, file-watch helpers |
| [`tokimo-vfs-smb`](./packages/smb) | Vendored fork of [smb-rs](https://github.com/avivg/smb-rs) with a handwritten NTLMv2 implementation in place of `sspi` |

## Supported storage backends

The `Driver` trait splits I/O capability by intent. Listing and reading are
mandatory; everything else is opt-in via `Driver::as_<capability>()` downcasts.
The matrix below records what each driver actually wires up today.

Legend: ✅ = implemented · ⚪ = not supported (or upstream API does not expose it)

### Local & network filesystems

| Backend | Driver name | List | Read | Mkdir | Delete file | Delete dir | Rename | Move | Copy | Put | Put stream | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Local disk | `local` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Native paths, `resolve_local` short-circuits to OS file ops |
| SFTP | `sftp` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ | ✅ | OpenSSH-compatible, via `russh` |
| FTP | `ftp` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ | ✅ | Plain FTP / FTPS |
| SMB / CIFS | `smb` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ | ✅ | SMB2/3 with handwritten NTLMv2 (see below) |
| NFS | `nfs` | ✅ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | NFSv3 read-only (mount-style enumeration) |
| WebDAV | `webdav` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Basic / Digest auth |

### Object storage

| Backend | Driver name | List | Read | Delete file | Put | Put stream | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| S3-compatible | `s3` | ✅ | ✅ | ✅ | ✅ | ✅ | AWS S3 / MinIO / R2 / OSS-S3 / B2-S3 — anything speaking the S3 wire |

### Consumer cloud drives

| Backend | Driver name | List | Read | Mkdir | Delete file | Delete dir | Rename | Move | Copy | Put | Put stream | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 阿里云盘 (Aliyun Drive) | `aliyundrive` | ✅ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | Read-only (refresh-token auth, share & STS modes) |
| 百度网盘 (Baidu Netdisk) | `baidu_netdisk` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ⚪ | OAuth via 百度开放平台 |
| 天翼云盘 (189 Cloud) | `189cloud` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ | Username + password login |
| 115 网盘 (115 Cloud) | `115cloud` | ✅ | ✅ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | Cookie auth, read-only |
| 夸克网盘 (Quark) | `quark` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚪ | ✅ | ✅ | Cookie auth |

If a driver row shows `⚪` for write operations, calling the corresponding
helper on the `Driver` trait returns `Err(unsupported(...))` rather than
silently failing — callers can probe support upfront via
`driver.as_put().is_some()` etc.

## Op layer (`tokimo-vfs-op`)

Built on top of any `Driver`:

- `read_range` / `read_chunked` — stream byte ranges as `mpsc::Receiver<Vec<u8>>`
- `parallel_copy` — multi-connection chunked copy for fast remote-to-local transfer
- `walk` — async tree walker with prune callbacks (used by media library scanners)
- `file_watch` — best-effort change notification (polling fallback for drivers that lack native events)

These wrappers are how Tokimo's media services treat all backends uniformly,
including doing 10-stream parallel pulls from S3 / SMB / SFTP for thumbnails.

## SMB — why the custom fork

Upstream `smb-rs` depends on `sspi` (and transitively the entire `picky-*`
ASN.1 stack) to drive NTLM / Kerberos / SPNEGO authentication. Tokimo only
needs raw NTLMv2 over the wire — no SPNEGO wrapper, no Kerberos, no DER
parsing. Carrying ~50k lines of cryptographic glue for one HMAC-MD5 chain was
not a tradeoff we wanted.

`packages/smb/src/ntlm/` ships a from-scratch NTLMv2 client (~500 LoC) that:

- Computes `NTOWFv2` / `NtProofStr` / `LMv2Response` / `SessionBaseKey` per [MS-NLMP] §3.3.2
- Generates Type 1, parses Type 2, builds Type 3 NTLMSSP messages directly inside SMB2 SessionSetup
- Encrypts a random `ExportedSessionKey` with `RC4(KeyExchangeKey)` (RFC 6229) for key exchange
- Is verified against the official [MS-NLMP] §4.2.4 test vectors (`NTOWFv2`, `NtProofStr`, `SessionBaseKey`, `LMv2Response`)

After the rewrite the crate's only crypto dependencies are `md4`, `md-5`,
`hmac`, and `rand`. All `sspi` and `picky-*` crates are gone.

## Building & testing

```bash
cargo build --workspace
cargo test  --workspace
```

The NTLMv2 unit tests live under `packages/smb/src/ntlm/{crypto,messages}.rs`
and cover both RFC primitives (MD4, MD5, HMAC-MD5, RC4) and the [MS-NLMP]
authentication chain end-to-end:

```bash
cargo test -p tokimo-vfs-smb --lib ntlm::
```

A SMB smoke-test binary lives at `packages/fs/src/bin/smb_test.rs`:

```bash
SMB_HOST=10.0.0.10 SMB_SHARE=media SMB_USER=william SMB_PASS='secret' \
  cargo run --release --bin smb_test -p tokimo-vfs
```

## License

MIT. Individual vendored components retain upstream attribution where required
(see `packages/smb` for the `smb-rs` MIT notice).

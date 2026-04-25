# tokimo-package-vfs

Unified async virtual filesystem layer for [Tokimo](https://github.com/tokimo-lab/tokimo) — a single `Driver` trait that fronts Local, SFTP, FTP, SMB, S3, NFS, WebDAV, and more, plus a [stream-oriented op layer](./packages/op) for media-friendly large-file operations (range reads, parallel chunks, byte-range copies).

## Crates

| Crate | Description |
| --- | --- |
| [`tokimo-vfs-core`](./packages/core) | `Driver` / `FileMeta` / `FileChange` traits and shared types |
| [`tokimo-vfs`](./packages/fs) | Driver implementations (Local, SFTP, FTP, SMB, S3, NFS, WebDAV, …) |
| [`tokimo-vfs-op`](./packages/op) | High-level op layer — range reads, parallel copy, walker, file-watch helpers |
| [`tokimo-vfs-smb`](./packages/smb) | Vendored fork of [smb-rs](https://github.com/avivg/smb-rs) with a handwritten NTLMv2 implementation in place of `sspi` |

## SMB — Why a custom fork

The upstream `smb-rs` crate depends on `sspi` (and transitively the entire `picky-*` ASN.1 stack) for NTLM/Kerberos/SPNEGO authentication. For Tokimo we only need pure NTLMv2 over the wire — no SPNEGO wrapper, no Kerberos. Carrying ~50k lines of cryptographic glue for one HMAC-MD5 chain was not a tradeoff we wanted.

`packages/smb/src/ntlm/` contains a from-scratch NTLMv2 client (~500 LoC) that:

- Computes `NTOWFv2` / `NtProofStr` / `LMv2Response` / `SessionBaseKey` per [MS-NLMP] §3.3.2
- Generates Type 1 / parses Type 2 / builds Type 3 NTLMSSP messages directly over the SMB2 SessionSetup wire
- Encrypts the random `ExportedSessionKey` with `RC4(KeyExchangeKey)` (RFC 6229)
- Is verified against the official [MS-NLMP] §4.2.4 test vectors (NTOWFv2, NtProofStr, SessionBaseKey, LMv2)

After this rewrite the crate compiles with only `md4`, `md-5`, `hmac`, and `rand` for crypto — all `sspi` and `picky-*` dependencies are gone.

## Building

```bash
cargo build --workspace
cargo test  --workspace
```

A SMB smoke-test binary lives at `packages/fs/src/bin/smb_test.rs`:

```bash
SMB_HOST=10.0.0.10 SMB_SHARE=media SMB_USER=william SMB_PASS='secret' \
  cargo run --release --bin smb_test -p tokimo-vfs
```

## License

MIT — see individual crates for upstream attribution where applicable (smb-rs is MIT licensed).

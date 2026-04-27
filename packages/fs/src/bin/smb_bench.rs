//! SMB read-throughput diagnostic tool.
//!
//! Tests two access patterns back-to-back and reports MB/s:
//!   1. small-window  — many small `read_bytes` calls (simulates current AVIO path)
//!   2. large-window  — one `read_bytes` per large chunk (reduces open/close overhead)
//!
//! Usage:
//!   cargo run -p tokimo-vfs --bin `smb_bench` -- \
//!     --host 192.168.1.10 --share media --username user --password pass \
//!     --path "/movie/foo.mkv" --read-mb 128

#![allow(clippy::print_stdout)]

use std::time::Instant;

use clap::Parser;
use std::path::Path;
use tokimo_vfs::Reader;
use tokimo_vfs::drivers::smb::factory as smb_factory;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(about = "SMB sequential read benchmark")]
struct Args {
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "")]
    share: String,
    #[arg(long, default_value = "")]
    username: String,
    #[arg(long, default_value = "")]
    password: String,
    #[arg(long, default_value = "")]
    domain: String,
    #[arg(long, default_value = "")]
    root: String,
    /// Remote path relative to root (e.g. /movie/foo.mkv)
    #[arg(long)]
    path: String,
    /// Total MB to read per test
    #[arg(long, default_value = "128")]
    read_mb: u64,
    /// Chunk size for small-window test (KB)
    #[arg(long, default_value = "4096")]
    small_chunk_kb: u64,
    /// Chunk size for large-window test (KB)
    #[arg(long, default_value = "32768")]
    large_chunk_kb: u64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    let params = serde_json::json!({
        "host":     args.host,
        "share":    args.share,
        "username": args.username,
        "password": args.password,
        "domain":   args.domain,
        "root":     args.root,
    });
    let driver = smb_factory(&params)?;

    let path = Path::new(&args.path);
    let total_bytes = args.read_mb * 1024 * 1024;

    // ── warm-up: single 1 MB read to establish connection ──────────────────
    println!("Warming up (1 MB read)…");
    let _ = driver.read_bytes(path, 0, Some(1024 * 1024)).await?;
    println!("Connected.\n");

    // ── helper ──────────────────────────────────────────────────────────────
    async fn run_test(
        driver: &dyn Reader,
        path: &Path,
        total_bytes: u64,
        chunk_bytes: u64,
        label: &str,
    ) -> Result<(), BoxError> {
        let chunks = total_bytes.div_ceil(chunk_bytes);
        println!("── {label} ──");
        println!(
            "  chunk={} KB  chunks={}  total={} MB",
            chunk_bytes / 1024,
            chunks,
            total_bytes / 1024 / 1024
        );

        let t_start = Instant::now();
        let mut offset = 0u64;
        let mut bytes_received = 0u64;
        let mut open_close_overhead_ms = 0u64;

        for i in 0..chunks {
            let limit = chunk_bytes.min(total_bytes - offset);
            let t0 = Instant::now();
            let data = driver.read_bytes(path, offset, Some(limit)).await?;
            let elapsed_ms = t0.elapsed().as_millis() as u64;

            if data.is_empty() {
                println!("  chunk {i}: EOF at offset {}MB", offset / 1024 / 1024);
                break;
            }

            // Estimate open/close overhead: time − (bytes / max_theoretical_bandwidth)
            // We assume ~300 MB/s max for 2.5 Gbps.
            let transfer_ms = (data.len() as u64 * 1000) / (300 * 1024 * 1024);
            let overhead_ms = elapsed_ms.saturating_sub(transfer_ms);
            open_close_overhead_ms += overhead_ms;

            if i < 5 || i % 20 == 0 {
                println!(
                    "  chunk {i:3}: offset={}MB  got={}KB  time={}ms  (est. overhead={}ms)",
                    offset / 1024 / 1024,
                    data.len() / 1024,
                    elapsed_ms,
                    overhead_ms,
                );
            }

            bytes_received += data.len() as u64;
            offset += data.len() as u64;
        }

        let total_ms = t_start.elapsed().as_millis() as u64;
        let mb_per_sec = if total_ms > 0 {
            (bytes_received * 1000) / (1024 * 1024 * total_ms)
        } else {
            0
        };

        println!();
        println!("  RESULT: {bytes_received}B in {total_ms}ms  →  {mb_per_sec} MB/s");
        println!(
            "  Estimated open/close overhead: {open_close_overhead_ms}ms total  \
                  ({} ms/chunk avg)",
            open_close_overhead_ms / chunks.max(1)
        );
        println!();

        Ok(())
    }

    let small_chunk = args.small_chunk_kb * 1024;
    let large_chunk = args.large_chunk_kb * 1024;

    run_test(
        driver.as_ref(),
        path,
        total_bytes,
        small_chunk,
        &format!(
            "small-window ({} KB/chunk — current AVIO behavior)",
            args.small_chunk_kb
        ),
    )
    .await?;

    // Re-create driver to get a fresh connection (avoids connection rotation skewing results)
    let driver2 = smb_factory(&params)?;
    let _ = driver2.read_bytes(path, 0, Some(1024 * 1024)).await?;

    run_test(
        driver2.as_ref(),
        path,
        total_bytes,
        large_chunk,
        &format!(
            "large-window ({} KB/chunk — fewer open/close cycles)",
            args.large_chunk_kb
        ),
    )
    .await?;

    Ok(())
}

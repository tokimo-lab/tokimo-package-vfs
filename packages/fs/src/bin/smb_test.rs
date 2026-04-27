#![allow(clippy::print_stdout)]

use std::path::Path;

use tokimo_vfs::drivers::smb::factory as smb_factory;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let host = std::env::var("SMB_HOST").unwrap_or_else(|_| "10.0.0.10".into());
    let share = std::env::var("SMB_SHARE").unwrap_or_else(|_| "media".into());
    let username = std::env::var("SMB_USER").unwrap_or_else(|_| "william".into());
    let password = std::env::var("SMB_PASS").unwrap_or_else(|_| "@#hujiayu22".into());

    let params = serde_json::json!({
        "host": host,
        "share": share,
        "username": username,
        "password": password,
        "domain": "",
        "root": "",
    });

    println!("Connecting to smb://{username}@{host}/{share} ...");
    let driver = smb_factory(&params)?;

    let entries = driver.list(Path::new("/")).await?;
    println!("✅ connected. {} entries:", entries.len());
    for e in entries.iter().take(20) {
        println!(
            "  {} {} {} bytes",
            if e.is_dir { "DIR " } else { "FILE" },
            e.name,
            e.size
        );
    }
    Ok(())
}

// src/main.rs
use clap::{ArgAction, Parser};
use env_logger::Builder;
#[cfg(all(feature = "fuse", unix))]
use fuser::MountOption;
#[cfg(all(feature = "fuse", unix))]
use log::warn;
use log::{error, info, LevelFilter};
#[cfg(all(feature = "fuse", unix))]
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
#[cfg(all(feature = "fuse", unix))]
use std::process::Command;

mod block_device;
mod jpeg_disk;
mod mirage_fs;
mod mp3_disk;
mod mp4_disk;
mod png_disk;
mod raid_device;
mod url_media;
mod web_assets;
mod webdav_server;
mod webp_disk;

use block_device::BlockDevice;
use jpeg_disk::JpegDisk;
use mirage_fs::MirageFS;
use mp3_disk::Mp3Disk;
use mp4_disk::Mp4Disk;
use png_disk::PngDisk;
use raid_device::Raid0Device;
use url_media::{is_url, open_media_url};
use webp_disk::WebPDisk;

#[derive(Parser)]
#[command(name = "MirageFS")]
#[command(author = "Seuriin (Github: SSL-ACTX)")]
#[command(version = "1.6.0")]
#[command(
    about = "High-Stealth Steganographic Filesystem",
    long_about = "MirageFS mounts an encrypted filesystem inside standard image/video files."
)]
struct Cli {
    #[arg(value_name = "MOUNT_POINT")]
    mount_point: Option<PathBuf>,
    #[arg(value_name = "MEDIA_FILES", num_args = 1..)]
    image_files: Vec<String>,
    #[arg(short, long)]
    format: bool,
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
    #[arg(
        short,
        long,
        help = "Serve via WebDAV instead of mounting (No FUSE required)"
    )]
    webdav: bool,
    #[arg(long, default_value = "8080", help = "Port for WebDAV server")]
    port: u16,
    #[arg(long, help = "Mount as read-only (also implied for URL media)")]
    read_only: bool,
    #[arg(long, help = "Username for WebDAV (default: admin)")]
    user: Option<String>,
    #[arg(long, help = "Password for WebDAV (default: carrier password)")]
    pass: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Upload carrier files to a cloud provider
    #[cfg(feature = "cloud")]
    Upload {
        #[arg(short, long, default_value = "temp-sh")]
        provider: String,
        #[arg(short, long, help = "Existing Bin ID (for Filebin)")]
        bin_id: Option<String>,
        #[arg(value_name = "FILES", required = true)]
        files: Vec<String>,
    },
}

fn print_banner() {
    println!(
        r#"
    ██▄  ▄██ ▄▄ ▄▄▄▄   ▄▄▄   ▄▄▄▄ ▄▄▄▄▄ ██████ ▄█████
    ██ ▀▀ ██ ██ ██▄█▄ ██▀██ ██ ▄▄ ██▄▄  ██▄▄   ▀▀▀▄▄▄
    ██    ██ ██ ██ ██ ██▀██ ▀███▀ ██▄▄▄ ██     █████▀

    v1.6.0 | By Seuriin (SSL-ACTX)
    "#
    );
}

fn init_logger(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };

    Builder::new()
        .format(|buf, record| {
            let style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "[{} {}] {}",
                buf.timestamp_seconds(),
                style.value(record.level()),
                record.args()
            )
        })
        .filter(None, level)
        .init();
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize Logging
    if std::env::var("RUST_LOG").is_err() {
        let v = if cli.verbose == 0 { 1 } else { cli.verbose };
        init_logger(v);
    } else {
        env_logger::init();
    }

    print_banner();

    // Handle Subcommands
    if let Some(command) = cli.command {
        match command {
            #[cfg(feature = "cloud")]
            Commands::Upload { provider, bin_id, files } => {
                return upload_to_cloud(provider, bin_id, files);
            }
        }
    }

    // --- Pre-Flight Checks ---
    if cli.image_files.is_empty() {
        anyhow::bail!("No media files provided. Use --help for usage.");
    }
    let _target_mount_point = cli.mount_point.ok_or_else(|| anyhow::anyhow!("Mount point is required for mount/webdav mode."))?;

    // Expand directories into files
    let mut expanded_files = Vec::new();
    for source in cli.image_files {
        if is_url(&source) {
            expanded_files.push(source);
            continue;
        }

        let path = PathBuf::from(&source);
        if path.is_dir() {
            info!("Expanding directory: {:?}", path);
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_file() {
                    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                        let ext = ext.to_lowercase();
                        if ["png", "jpg", "jpeg", "webp", "mp4", "m4v", "mov", "mp3"].contains(&ext.as_str()) {
                            expanded_files.push(p.to_string_lossy().to_string());
                        }
                    }
                }
            }
        } else if path.exists() {
            expanded_files.push(source);
        } else {
            anyhow::bail!("Media file not found: {:?}", path);
        }
    }

    // Verify Media Files Exist (Local Paths Only)
    for source in &expanded_files {
        if !is_url(source) {
            let path = PathBuf::from(source);
            if !path.exists() {
                anyhow::bail!("Media file not found: {:?}", path);
            }
        }
    }

    if expanded_files.is_empty() {
        anyhow::bail!("No valid media files provided.");
    }

    // Prepare Mount Point (Only for FUSE mode)
    #[cfg(all(feature = "fuse", unix))]
    if !cli.webdav {
        if !_target_mount_point.exists() {
            info!("Creating mount point at {:?}", _target_mount_point);
            fs::create_dir_all(&_target_mount_point)?;
        }
        if !_target_mount_point.is_dir() {
            anyhow::bail!("Mount point must be a directory: {:?}", _target_mount_point);
        }
    }


    // --- Password Interaction ---
    print!("[-] Enter Password: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;

    if cli.format {
        print!("[!] Confirm Password (FORMATTING): ");
        io::stdout().flush()?;
        let confirm = rpassword::read_password()?;
        if password != confirm {
            anyhow::bail!("[!] Passwords do not match!");
        }
    }

    // --- Initialize Storage Layer ---
    let mut disks: Vec<Box<dyn BlockDevice>> = Vec::new();
    let mut read_only = cli.read_only;
    info!(
        "Initializing storage array with {} carrier(s)...",
        expanded_files.len()
    );

    for source in expanded_files {
        if is_url(&source) {
            if cli.format {
                anyhow::bail!(
                    "Formatting is not supported for media URLs (read-only mode). Remove --format."
                );
            }
            info!("Loading remote carrier: {}", source);
            let disk = open_media_url(&source, &password)?;
            disks.push(disk);
            read_only = true;
            continue;
        }

        let path = PathBuf::from(&source);
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        info!("Loading carrier: {:?}", path);

        if read_only && cli.format {
            anyhow::bail!("--read-only cannot be used with --format.");
        }

        let disk: Box<dyn BlockDevice> = match extension.as_str() {
            "png" => Box::new(PngDisk::new(path, &password, cli.format)?),
            "jpg" | "jpeg" => Box::new(JpegDisk::new(path, &password, cli.format)?),
            "webp" => Box::new(WebPDisk::new(path, &password, cli.format)?),
            "mp4" | "m4v" | "mov" => Box::new(Mp4Disk::new(path, &password, cli.format)?),
            "mp3" => Box::new(Mp3Disk::new(path, &password, cli.format)?),
            _ => anyhow::bail!("Unsupported file extension: .{}", extension),
        };

        disks.push(disk);
    }

    // Initialize RAID Controller
    let raid_controller = Raid0Device::new(disks, cli.format)?;

    // Initialize Filesystem
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(unix)]
    let gid = unsafe { libc::getgid() };
    #[cfg(windows)]
    let (uid, gid) = (0, 0);

    let fs = match MirageFS::new(Box::new(raid_controller), cli.format, uid, gid, read_only) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Filesystem Init Error: {}", e);
            anyhow::bail!("Failed to initialize MirageFS.");
        }
    };

    // --- Launch Mode Selection ---

    if cli.webdav {
        let web_user = cli.user.unwrap_or_else(|| "admin".to_string());
        let web_pass = cli.pass.unwrap_or_else(|| password.clone());
        return run_webdav(fs, cli.port, web_user, web_pass);
    }

    #[cfg(all(feature = "fuse", unix))]
    {
        run_fuse(fs, _target_mount_point, read_only)
    }

    #[cfg(not(all(feature = "fuse", unix)))]
    {
        info!("MirageFS compiled without FUSE support. Defaulting to WebDAV.");
        let web_user = cli.user.unwrap_or_else(|| "admin".to_string());
        let web_pass = cli.pass.unwrap_or_else(|| password.clone());
        run_webdav(fs, cli.port, web_user, web_pass)
    }
}

#[cfg(feature = "cloud")]
fn upload_to_cloud(provider_name: String, mut bin_id: Option<String>, files: Vec<String>) -> anyhow::Result<()> {
    info!("Initializing Cloud Uploader ({})", provider_name);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use srapi_rs::{TempShProvider, TmpfilesProvider, JumpshareProvider, FilebinProvider, FileProvider, UploadedFile, ProviderError};
        use async_trait::async_trait;

        #[async_trait]
        trait SimpleUploadProvider {
            async fn upload_bytes(&self, filename: &str, bytes: Vec<u8>) -> Result<UploadedFile, ProviderError>;
        }

        #[async_trait]
        impl SimpleUploadProvider for TempShProvider {
            async fn upload_bytes(&self, filename: &str, bytes: Vec<u8>) -> Result<UploadedFile, ProviderError> {
                TempShProvider::upload_bytes(self, filename, bytes).await
            }
        }

        #[async_trait]
        impl SimpleUploadProvider for TmpfilesProvider {
            async fn upload_bytes(&self, filename: &str, bytes: Vec<u8>) -> Result<UploadedFile, ProviderError> {
                TmpfilesProvider::upload_bytes(self, filename, bytes).await
            }
        }

        #[async_trait]
        impl SimpleUploadProvider for JumpshareProvider {
            async fn upload_bytes(&self, filename: &str, bytes: Vec<u8>) -> Result<UploadedFile, ProviderError> {
                JumpshareProvider::upload_bytes(self, filename, bytes).await
            }
        }

        // Filebin wrapper to fit SimpleUploadProvider
        struct FilebinSimple {
            inner: FilebinProvider,
            active_bin: tokio::sync::Mutex<Option<String>>,
        }

        #[async_trait]
        impl SimpleUploadProvider for FilebinSimple {
            async fn upload_bytes(&self, filename: &str, bytes: Vec<u8>) -> Result<UploadedFile, ProviderError> {
                let mut bin_lock = self.active_bin.lock().await;
                let bid = if let Some(ref id) = *bin_lock {
                    id.clone()
                } else {
                    let id = self.inner.create_bin().await?;
                    info!("Created new Filebin: {}", id);
                    *bin_lock = Some(id.clone());
                    id
                };

                let len = bytes.len() as u64;
                let body = reqwest::Body::from(bytes);
                self.inner.upload_file(&bid, filename, body, len).await.map(|m| UploadedFile {
                    url: format!("https://filebin.net/{}/{}", bid, m.filename),
                    filename: m.filename,
                    size: m.size,
                    content_type: m.content_type,
                    expires_at: None,
                })
            }
        }

        let provider: Box<dyn SimpleUploadProvider> = match provider_name.as_str() {
            "temp-sh" => Box::new(TempShProvider::new()),
            "tmpfiles" => Box::new(TmpfilesProvider::new()),
            "jumpshare" => Box::new(JumpshareProvider::new()),
            "filebin" => Box::new(FilebinSimple { 
                inner: FilebinProvider::new(), 
                active_bin: tokio::sync::Mutex::new(bin_id.take()) 
            }),
            _ => {
                error!("Unsupported provider: {}", provider_name);
                return;
            }
        };
        for file_arg in files {
            let path = PathBuf::from(&file_arg);
            let mut to_upload = Vec::new();

            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() { to_upload.push(p); }
                    }
                }
            } else {
                to_upload.push(path);
            }

            for p in to_upload {
                info!("Uploading {:?}...", p);
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                let bytes = match tokio::fs::read(&p).await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Read failed {}: {}", name, e);
                        continue;
                    }
                };

                match provider.upload_bytes(&name, bytes).await {
                    Ok(res) => info!("[SUCCESS] {} -> {}", name, res.url),
                    Err(e) => error!("[FAILED] {}: {}", name, e),
                }
            }
        }
    });

    Ok(())
}

// --- Mode Implementations ---

fn run_webdav(fs: MirageFS, port: u16, user: String, pass: String) -> anyhow::Result<()> {
    info!("Starting WebDAV Mode (FUSE Disabled)...");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        webdav_server::start_webdav_server(fs, port, user, pass).await;
    });

    Ok(())
}

#[cfg(all(feature = "fuse", unix))]
fn run_fuse(fs: MirageFS, mount_point: PathBuf, read_only: bool) -> anyhow::Result<()> {
    let mut options = vec![
        MountOption::FSName("mirage".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
        MountOption::DefaultPermissions,
    ];

    if read_only {
        options.push(MountOption::RO);
    } else {
        options.push(MountOption::RW);
    }

    info!("Mounting at {:?}", mount_point);
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    info!("Owner: UID={}, GID={}", uid, gid);
    info!("Press Ctrl+C to unmount.");

    let mount_path = mount_point.clone();

    // Signal Handler for Clean Unmount
    ctrlc::set_handler(move || {
        info!("\n[!] Received Ctrl+C. Force unmounting...");
        let status = Command::new("fusermount")
            .arg("-u")
            .arg("-z")
            .arg(&mount_path)
            .status();

        if status.is_err() || !status.unwrap().success() {
            // Fallback for non-FUSE systems or weird states
            let _ = Command::new("umount").arg(&mount_path).status();
        }
    })
    .ok();

    match fuser::mount2(fs, mount_point, &options) {
        Ok(_) => {
            info!("Unmounted successfully.");
            Ok(())
        }
        Err(e) => {
            error!("FUSE Mount Failed: {}", e);
            warn!("If FUSE is not installed, try running with --webdav");
            Err(anyhow::anyhow!("FUSE mount failed"))
        }
    }
}

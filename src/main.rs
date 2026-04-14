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
mod mp4_disk;
mod png_disk;
mod raid_device;
mod url_media;
mod webdav_server;
mod webp_disk;

use block_device::BlockDevice;
use jpeg_disk::JpegDisk;
use mirage_fs::MirageFS;
use mp4_disk::Mp4Disk;
use png_disk::PngDisk;
use raid_device::Raid0Device;
use url_media::{is_url, open_media_url};
use webp_disk::WebPDisk;

#[derive(Parser)]
#[command(name = "MirageFS")]
#[command(author = "Seuriin (Github: SSL-ACTX)")]
#[command(version = "1.5.0")]
#[command(
    about = "High-Stealth Steganographic Filesystem",
    long_about = "MirageFS mounts an encrypted filesystem inside standard image/video files."
)]
struct Cli {
    #[arg(value_name = "MOUNT_POINT")]
    mount_point: PathBuf,
    #[arg(value_name = "MEDIA_FILES", required = true, num_args = 1..)]
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
}

fn print_banner() {
    println!(
        r#"
    ██▄  ▄██ ▄▄ ▄▄▄▄   ▄▄▄   ▄▄▄▄ ▄▄▄▄▄ ██████ ▄█████
    ██ ▀▀ ██ ██ ██▄█▄ ██▀██ ██ ▄▄ ██▄▄  ██▄▄   ▀▀▀▄▄▄
    ██    ██ ██ ██ ██ ██▀██ ▀███▀ ██▄▄▄ ██     █████▀

    v1.5.0 | By Seuriin (SSL-ACTX)
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

    // --- Pre-Flight Checks ---

    // Verify Media Files Exist (Local Paths Only)
    for source in &cli.image_files {
        if !is_url(source) {
            let path = PathBuf::from(source);
            if !path.exists() {
                anyhow::bail!("Media file not found: {:?}", path);
            }
        }
    }

    // Prepare Mount Point (Only for FUSE mode)
    #[cfg(all(feature = "fuse", unix))]
    if !cli.webdav {
        if !cli.mount_point.exists() {
            info!("Creating mount point at {:?}", cli.mount_point);
            fs::create_dir_all(&cli.mount_point)?;
        }
        if !cli.mount_point.is_dir() {
            anyhow::bail!("Mount point must be a directory: {:?}", cli.mount_point);
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
        cli.image_files.len()
    );

    for source in cli.image_files {
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
        run_fuse(fs, cli.mount_point, read_only)
    }

    #[cfg(not(all(feature = "fuse", unix)))]
    {
        info!("MirageFS compiled without FUSE support. Defaulting to WebDAV.");
        let web_user = cli.user.unwrap_or_else(|| "admin".to_string());
        let web_pass = cli.pass.unwrap_or_else(|| password.clone());
        run_webdav(fs, cli.port, web_user, web_pass)
    }
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

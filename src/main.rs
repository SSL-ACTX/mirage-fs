// src/main.rs
use clap::{Parser, ArgAction};
use log::{info, error, LevelFilter};
use std::path::PathBuf;
use std::io::{self, Write};
use env_logger::Builder;
#[cfg(feature = "fuse")]
use fuser::MountOption;
#[cfg(feature = "fuse")]
use std::fs;

mod block_device;
mod raid_device;
mod mirage_fs;
mod png_disk;
mod jpeg_disk;
mod webp_disk;
mod mp4_disk;
mod webdav_server;

use block_device::BlockDevice;
use raid_device::Raid0Device;
use mirage_fs::MirageFS;
use png_disk::PngDisk;
use jpeg_disk::JpegDisk;
use webp_disk::WebPDisk;
use mp4_disk::Mp4Disk;

#[derive(Parser)]
#[command(name = "MirageFS")]
#[command(author = "Seuriin (Github: SSL-ACTX)")]
#[command(version = "1.3.0")]
#[command(about = "High-Stealth Steganographic Filesystem", long_about = "MirageFS mounts an encrypted filesystem inside standard image/video files.")]
struct Cli {
    #[arg(value_name = "MOUNT_POINT")]
    mount_point: PathBuf,
    #[arg(value_name = "MEDIA_FILES", required = true, num_args = 1..)]
    image_files: Vec<PathBuf>,
    #[arg(short, long)]
    format: bool,
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
    #[arg(short, long, help = "Serve via WebDAV instead of mounting (No FUSE required)")]
    webdav: bool,
    #[arg(long, default_value = "8080", help = "Port for WebDAV server")]
    port: u16,
}

fn print_banner() {
    println!(r#"
    ██▄  ▄██ ▄▄ ▄▄▄▄   ▄▄▄   ▄▄▄▄ ▄▄▄▄▄ ██████ ▄█████
    ██ ▀▀ ██ ██ ██▄█▄ ██▀██ ██ ▄▄ ██▄▄  ██▄▄   ▀▀▀▄▄▄
    ██    ██ ██ ██ ██ ██▀██ ▀███▀ ██▄▄▄ ██     █████▀

    v1.3.0 | By Seuriin (SSL-ACTX)
    "#);
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
        writeln!(buf, "[{} {}] {}",
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

    // Verify Media Files Exist
    for path in &cli.image_files {
        if !path.exists() {
            anyhow::bail!("Media file not found: {:?}", path);
        }
    }

    // Prepare Mount Point (Only for FUSE mode)
    #[cfg(feature = "fuse")]
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
    info!("Initializing storage array with {} carrier(s)...", cli.image_files.len());

    for path in cli.image_files {
        let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

        info!("Loading carrier: {:?}", path);

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
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let fs = match MirageFS::new(Box::new(raid_controller), cli.format, uid, gid) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Filesystem Init Error: {}", e);
            anyhow::bail!("Failed to initialize MirageFS.");
        }
    };

    // --- Launch Mode Selection ---

    if cli.webdav {
        return run_webdav(fs, cli.port);
    }

    #[cfg(feature = "fuse")]
    {
        run_fuse(fs, cli.mount_point)
    }

    #[cfg(not(feature = "fuse"))]
    {
        info!("MirageFS compiled without FUSE support. Defaulting to WebDAV.");
        run_webdav(fs, cli.port)
    }
}

// --- Mode Implementations ---

fn run_webdav(fs: MirageFS, port: u16) -> anyhow::Result<()> {
    info!("Starting WebDAV Mode (FUSE Disabled)...");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        webdav_server::start_webdav_server(fs, port).await;
    });

    Ok(())
}

#[cfg(feature = "fuse")]
fn run_fuse(fs: MirageFS, mount_point: PathBuf) -> anyhow::Result<()> {
    let options = vec![
        MountOption::RW,
        MountOption::FSName("mirage".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
        MountOption::DefaultPermissions,
    ];

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
            let _ = Command::new("umount")
            .arg(&mount_path)
            .status();
        }
    }).ok();

    match fuser::mount2(fs, mount_point, &options) {
        Ok(_) => {
            info!("Unmounted successfully.");
            Ok(())
        },
        Err(e) => {
            error!("FUSE Mount Failed: {}", e);
            warn!("If FUSE is not installed, try running with --webdav");
            Err(anyhow::anyhow!("FUSE mount failed"))
        }
    }
}

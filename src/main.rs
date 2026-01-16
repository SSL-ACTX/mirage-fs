// src/main.rs
use clap::{Parser, ArgAction};
use fuser::MountOption;
use log::{info, error, LevelFilter};
use std::fs;
use std::path::PathBuf;
use std::io::{self, Write};
use env_logger::Builder;
use std::process::Command;

mod block_device;
mod raid_device;
mod mirage_fs;
mod png_disk;
mod jpeg_disk;
mod webp_disk;
mod mp4_disk;

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
#[command(about = "High-Stealth Steganographic Filesystem", long_about = "MirageFS mounts an encrypted filesystem inside standard media files.\n\nSupports Multi-Image RAID 0 (Striping) for heat distribution.")]
struct Cli {
    #[arg(value_name = "MOUNT_POINT")]
    mount_point: PathBuf,
    #[arg(value_name = "MEDIA_FILES", required = true, num_args = 1..)]
    media_files: Vec<PathBuf>,
    #[arg(short, long)]
    format: bool,
        #[arg(short, long, action = ArgAction::Count)]
        verbose: u8,
}

fn print_banner() {
    println!(r#"
    ██▄  ▄██ ▄▄ ▄▄▄▄   ▄▄▄   ▄▄▄▄ ▄▄▄▄▄ ██████ ▄█████
    ██ ▀▀ ██ ██ ██▄█▄ ██▀██ ██ ▄▄ ██▄▄  ██▄▄   ▀▀▀▄▄▄
    ██    ██ ██ ██ ██ ██▀██ ▀███▀ ██▄▄▄ ██     █████▀

    v1.2.0 | By Seuriin (SSL-ACTX)
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

    if std::env::var("RUST_LOG").is_err() {
        let v = if cli.verbose == 0 { 1 } else { cli.verbose };
        init_logger(v);
    } else {
        env_logger::init();
    }

    print_banner();

    if !cli.mount_point.exists() {
        info!("Creating mount point at {:?}", cli.mount_point);
        fs::create_dir_all(&cli.mount_point)?;
    }

    // Password Prompt
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

    // Initialize all disks
    let mut disks: Vec<Box<dyn BlockDevice>> = Vec::new();

    info!("Initializing storage array with {} carrier(s)...", cli.media_files.len());

    for path in cli.media_files {
        if !path.exists() {
            anyhow::bail!("Image file '{:?}' not found.", path);
        }

        let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "unknown".to_string());

        info!("Loading carrier: {:?}", path);

        let disk: Box<dyn BlockDevice> = match extension.as_str() {
            "png" => {
                Box::new(PngDisk::new(path, &password, cli.format)?)
            },
            "jpg" | "jpeg" => {
                Box::new(JpegDisk::new(path, &password, cli.format)?)
            },
            "webp" => {
                Box::new(WebPDisk::new(path, &password, cli.format)?)
            },
            "mp4" | "m4v" | "mov" => {
                Box::new(Mp4Disk::new(path, &password, cli.format)?)
            },
            _ => anyhow::bail!("Unsupported file extension: .{}", extension),
        };

        disks.push(disk);
    }

    // Wrap in RAID Controller
    let raid_controller = Raid0Device::new(disks, cli.format)?;

    // Pass the controller to the filesystem
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // MirageFS sees the RAID array as a single, large block device.
    // It doesn't know (or care) that the data is being striped.
    let fs = match MirageFS::new(Box::new(raid_controller), cli.format, uid, gid) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Filesystem Init Error: {}", e);
            anyhow::bail!("Failed to initialize MirageFS.");
        }
    };

    let options = vec![
        MountOption::RW,
        MountOption::FSName("mirage".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
        MountOption::DefaultPermissions,
    ];

    info!("Mounting at {:?}", cli.mount_point);
    info!("Owner: UID={}, GID={}", uid, gid);
    info!("Press Ctrl+C to unmount.");

    let mount_path = cli.mount_point.clone();

    ctrlc::set_handler(move || {
        info!("\n[!] Received Ctrl+C. Force unmounting...");
        let status = Command::new("fusermount")
        .arg("-u")
        .arg("-z")
        .arg(&mount_path)
        .status();

        if status.is_err() || !status.unwrap().success() {
            let _ = Command::new("umount")
            .arg(&mount_path)
            .status();
        }
    }).ok();

    if let Err(e) = fuser::mount2(fs, cli.mount_point, &options) {
        error!("Mount failed: {}", e);
        return Ok(());
    }

    info!("Unmounted successfully.");
    Ok(())
}

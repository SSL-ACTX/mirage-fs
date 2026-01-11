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
mod mirage_fs;
mod png_disk;
mod jpeg_disk;
mod webp_disk;

use block_device::BlockDevice;
use mirage_fs::MirageFS;
use png_disk::PngDisk;
use jpeg_disk::JpegDisk;
use webp_disk::WebPDisk;

#[derive(Parser)]
#[command(name = "MirageFS")]
#[command(author = "Seuriin (Github: SSL-ACTX)")]
#[command(version = "1.0.0")]
#[command(about = "High-Stealth Steganographic Filesystem", long_about = "MirageFS mounts an encrypted filesystem inside standard image files (PNG/JPEG/WebP) using advanced steganography techniques.\n\nSupports:\n- PNG: PRNG Scatter (LSB)\n- JPEG & WebP: Adobe DNG Morphing (Segment Injection)")]
struct Cli {
    #[arg(value_name = "MOUNT_POINT")]
    mount_point: PathBuf,
    #[arg(value_name = "IMAGE_FILE")]
    image_file: PathBuf,
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

    v1.0.0 | By Seuriin (SSL-ACTX)
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

    if !cli.image_file.exists() {
        anyhow::bail!("Image file '{:?}' not found.", cli.image_file);
    }

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

    info!("Loading container {:?}...", cli.image_file);

    let extension = cli.image_file.extension()
    .and_then(|ext| ext.to_str())
    .map(|s| s.to_lowercase())
    .unwrap_or_else(|| "unknown".to_string());

    let disk: Box<dyn BlockDevice> = match extension.as_str() {
        "png" => {
            info!("Mode: PNG (PRNG Scatter LSB)");
            Box::new(PngDisk::new(cli.image_file.clone(), &password, cli.format)?)
        },
        "jpg" | "jpeg" => {
            info!("Mode: JPEG (Adobe DNG Morphing)");
            Box::new(JpegDisk::new(cli.image_file.clone(), &password, cli.format)?)
        },
        "webp" => {
            info!("Mode: WebP (Adobe DNG Morphing)");
            Box::new(WebPDisk::new(cli.image_file.clone(), &password, cli.format)?)
        },
        _ => anyhow::bail!("Unsupported file extension: .{}", extension),
    };

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let fs = match MirageFS::new(disk, cli.format, uid, gid) {
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

        // Fallback
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

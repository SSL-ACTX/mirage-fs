<div align="center">

![MirageFS Banner](https://capsule-render.vercel.app/api?type=waving&color=0:121212,100:FF4500&height=220&section=header&text=MirageFS&fontSize=90&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&rotate=2&stroke=FF4500&strokeWidth=2&desc=The%20Invisible%20Filesystem&descSize=20&descAlignY=60)


![Version](https://img.shields.io/badge/version-1.4.0-blue.svg?style=for-the-badge)
![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg?style=for-the-badge&logo=linux)

**Mount encrypted, hidden storage inside innocent media files.**

[Installation](#-installation) • [Usage](#-usage) • [Hybrid RAID](#-hybrid-raid-tiered-striping) • [Technical Details](#-technical-deep-dive) • [Disclaimer](#-disclaimer)

</div>

---

## 📖 Overview

**MirageFS** is a high-stealth steganographic filesystem built in Rust. It allows you to format and mount standard media files (`.png`, `.jpg`, `.webp`, `.mp4`, `.mov`) as fully functional read/write drives.

Unlike traditional steganography tools that simply hide a static payload, MirageFS implements a **virtual block device** inside the media. This means you can interact with your hidden files in real-time using your OS's native file explorer (`cp`, `mv`, `vim`, `mkdir`, `rmdir`, etc.) without extracting them first.

## 🚀 Key Features

### 🛡️ Military-Grade Encryption
Your data is secured with state-of-the-art authenticated encryption.
* **Cipher:** **XChaCha20-Poly1305** (Extended Nonce + MAC authentication).
* **KDF:** **Argon2id** (Resistant to GPU/ASIC brute-force attacks).
* **Nonce Randomization:** Every block write generates a unique nonce; writing the same file twice produces completely different ciphertext.

### 🖥️ Embedded Web Interface (New!)
MirageFS now ships with a stunning, self-hosted **Web Management UI** served directly from the binary.
* **Visual File Manager:** Navigate folders, view file details, and manage storage with a modern web UI.
* **Drag & Drop Upload:** Encrypt files instantly by dragging them into the browser window.
* **Zero Client Setup:** Works on any device with a web browser (Mobile/Desktop) without installing WebDAV clients.

### 🌐 Universal Driverless Access
MirageFS includes an embedded **WebDAV Server**.
* **No Drivers Required:** Works on restricted systems (corporate laptops, public computers) where you cannot install FUSE or kernel drivers.
* **Network Capable:** Mount your hidden drive over the LAN or VPN.
* **Cross-Platform:** Native integration with Windows Explorer, macOS Finder, iOS, and Android.

### ⛓️ Hybrid "Smart" RAID Controller
MirageFS introduces a sophisticated **Tiered RAID 0** system that automatically balances stealth and capacity.
* **Zone 1 (High Stealth):** Stripes data across **ALL** devices (e.g., Image + Video). This maximizes entropy dilution, making the payload harder to detect forensically.
* **Zone 2 (Overflow):** Once static carriers (like PNGs) are full, the controller seamlessly transitions to **Overflow Mode**, writing remaining data exclusively to expandable carriers (MP4s).
* **Result:** You get the forensic safety of striping *plus* the massive capacity of video files in a single logical volume.

### 🥷 Advanced Steganography
MirageFS employs distinct, format-optimized strategies to defeat forensic analysis.

| Media Format | Strategy | Stealth Technique |
| :--- | :--- | :--- |
| **MP4 / MOV** | **Shadow `mdat` Injection** | Appends a secondary `mdat` atom ignored by standard players. Data is encapsulated in valid **H.264 NAL Units** (Type 12 "Filler Data") to look like video stream padding. |
| **PNG** | **Feistel Bijective Mapping** | Uses a **Feistel Network** and **Cycle Walking** to map logical blocks to physical pixels in $O(1)$ time. Salt locations are derived from the password. |
| **JPEG** | **DNG Morphing** | Data is injected into `APP1` segments mimicking valid **Adobe DNG Private Data** (Tag `0xC634`) inside a standard TIFF structure. |
| **WebP** | **RIFF Morphing** | Similar to JPEG, data is disguised as vendor-specific metadata inside the `EXIF` chunk of the RIFF container. |

### 📂 Full Filesystem Semantics
MirageFS is not just a key-value store; it is a compliant POSIX-like filesystem.
* **Directory Support:** Create nested folders (`mkdir`), remove them (`rmdir`), and organize your data hierarchy.
* **Atomic Renames:** Move and rename files/folders instantly (`mv`).
* **Auto-Shrink:** Deleting files triggers a "swap-and-pop" compaction. The MP4 container physically shrinks on disk to reflect the deleted data, leaving no "slack space" evidence.

---

## 📦 Installation

MirageFS supports two modes: **Native FUSE** (High Performance) and **WebDAV** (High Compatibility).

### Option 1: Native FUSE (Recommended for Linux/macOS)
Requires **FUSE (Filesystem in Userspace)** drivers installed on the host.

* **Debian/Ubuntu/WSL2:**
    ```bash
    sudo apt update && sudo apt install fuse3 libfuse3-dev pkg-config
    ```
* **Fedora:**
    ```bash
    sudo dnf install fuse3 fuse3-devel pkg-config
    ```
* **macOS:**
    Install [macFUSE](https://macfuse.github.io/).

### Option 2: Portable / No-Driver Mode
No dependencies required! MirageFS will automatically fallback to WebDAV mode if FUSE is not detected.

### Build from Source
```bash
# Clone the repository
git clone https://github.com/SSL-ACTX/mirage-fs.git
cd mirage-fs

# Build Release Binary
cargo build --release

# (Optional) Install globally
sudo cp target/release/mirage /usr/local/bin/mirage


```

---

## 🎮 Usage

### 1️⃣ Formatting (Destructive)

Create a new secret drive inside a carrier image or video (or a combination).

> [!WARNING]
> This overwrites any data previously hidden in the carrier. It does **not** destroy the visible image/video playback, but modifies the internal bit structure.

```bash
# Syntax: mirage <MOUNT_POINT> <MEDIA_FILES...> --format

# Video Mode (Massive Capacity)
mirage /tmp/secret holiday_video.mp4 --format

# Hybrid Mode (Best Stealth: Image + Video Striping)
mirage /tmp/secret cover.png movie.mp4 --format


```

### 2️⃣ Mounting (Smart Detect)

Run the command normally. MirageFS will attempt to mount via FUSE. If FUSE is unavailable (e.g., on Windows or restricted Linux), it will **automatically** start the WebDAV server.

```bash
mirage /tmp/secret cover.png movie.mp4


```

### 3️⃣ Web UI (Browser Access)

You can access the new graphical interface by opening the server address in any web browser.

**Link:** `http://127.0.0.1:8080` (Default)

* **Drag & Drop:** Upload files instantly.
* **Manage:** Create folders, delete items, and browse your hidden filesystem.

### 4️⃣ WebDAV Mode (Manual / Network Share)

You can force WebDAV mode (bypassing FUSE) to mount the drive as a Network Share. This is useful for systems without FUSE drivers.

```bash
# Start Server on Port 8080
mirage /mnt/point cover.png movie.mp4 --webdav --port 8080


```

**How to Access:**

* **Windows:** Open File Explorer -> Right Click "This PC" -> "Map Network Drive" -> `http://127.0.0.1:8080`
* **macOS:** Finder -> Go -> Connect to Server (`Cmd+K`) -> `http://127.0.0.1:8080`
* **Linux (GNOME/Nautilus):** Files App -> Other Locations -> Connect to Server -> `dav://127.0.0.1:8080`
* **Linux (CLI):** `mount -t davfs http://127.0.0.1:8080 /mnt/mountpoint`

> [!NOTE]
> Visiting the root URL (`http://127.0.0.1:8080`) in a browser loads the **Web UI**. To mount the filesystem as a native drive in your OS, you must use the "Connect to Server" / "Map Network Drive" feature of your file manager, not a web browser.

### 5️⃣ Unmounting

To close the drive and flush all data:

* **Press** `Ctrl + C` in the terminal.
* **Or run:** `fusermount -u /tmp/secret` (FUSE mode only)

---

## 🔧 Technical Deep Dive

### ⬛ MP4 "Shadow Injection" Engine

MirageFS exploits the atom structure of ISO Base Media Files (MP4/MOV).
Standard players read the `moov` (Movie) atom to find the location of video frames in the `mdat` (Media Data) atom.

1. **Injection:** We append a **second** `mdat` atom to the end of the file. Standard players stop reading after the first `mdat`, making our payload invisible to playback.
2. **Camouflage:** Raw encrypted data looks like random noise (high entropy), which is suspicious. We wrap every encrypted block in **H.264 NAL Unit headers** (specifically `Type 12: Filler Data`).
3. **Result:** To a forensic tool or packet inspector, the hidden data appears to be valid video stream padding/bitrate filler.

### 🟦 The PNG "Feistel" Engine

MirageFS treats the PNG pixels as a domain of size . A custom **Feistel Network** creates a bijective (1-to-1) permutation between the *Logical Block Address* and the *Physical Pixel Index*.

* **Zero Memory Overhead:** No mapping table is stored. Locations are calculated mathematically on the fly.
* **Collision Avoidance:** The engine smartly skips "Salt" pixels during the permutation step to ensure the RAID header is never overwritten.

### 🟥 Hybrid RAID: Tiered Striping

When mixing static carriers (PNG/JPG) with dynamic carriers (MP4), a standard RAID 0 would be limited by the smallest drive. MirageFS uses a **Tiered Controller**:

* **Zone 1:** Data is striped across both the PNG and the MP4. This dilutes the entropy.
* **Zone 2:** When the PNG fills up (reaching the "Symmetric Stripe Limit"), the controller automatically detects the MP4 is expandable. It continues writing data to the MP4 only.
* **Read/Write Logic:** The controller calculates `Logical_Index % Device_Count` for Zone 1 addresses, and transparently re-maps higher addresses to the remaining dynamic devices.

### 🟧 The JPEG/WebP "Morphing" Engine

Compressed formats like JPEG destroy LSB data. MirageFS exploits the metadata layer instead.

1. **Dilution:** High-entropy encrypted data is expanded (7 bits → 8 bytes) to lower its statistical randomness.
2. **Camouflage:** Data is wrapped in valid **TIFF headers** and labeled as `DNGPrivateData` (Tag `0xC634`).
3. **Result:** Forensic tools ignore the data, identifying it as "proprietary Adobe metadata" rather than a suspicious payload.

---

## 🖥️ Platform Notes

<details>
<summary><strong>🐧 Linux (Native)</strong></summary>
Works out of the box with standard FUSE installation.
</details>

<details>
<summary><strong>🪟 Windows (WSL2 / Native)</strong></summary>
MirageFS works perfectly on Windows via the new <strong>WebDAV Mode</strong>.

1. Run MirageFS: `mirage.exe X: video.mp4 --webdav`
2. Map the drive in Explorer to `http://127.0.0.1:8080`
3. Enjoy your hidden drive as letter `Z:` (or similar).

> **Legacy WSL2 FUSE:**
> If you prefer FUSE inside WSL2, ensure `/etc/fuse.conf` has `user_allow_other` uncommented.

</details>

<details>
<summary><strong>🍎 macOS</strong></summary>

* **Preferred:** Use WebDAV mode (`Cmd+K` -> `http://127.0.0.1:8080`) for zero-configuration access.
* **FUSE:** Requires <a href="https://macfuse.github.io/">macFUSE</a> and manual approval of kernel extensions in System Settings.

</details>

---

## ⚠️ Disclaimer

> [!IMPORTANT]
> **For Educational and Research Use Only.**
> MirageFS is a proof-of-concept tool designed to demonstrate advanced steganography and filesystem concepts.
> * Do not use this for critical data storage without backups.
> * While the encryption is strong, steganography is an arms race; a sufficiently motivated forensic adversary with knowledge of this specific tool could potentially detect the modification artifacts.
> 
> 

---

<div align="center">

**Author:** Seuriin ([SSL-ACTX](https://github.com/SSL-ACTX))

*v1.4.0*

</div>

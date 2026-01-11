<div align="center">

![MirageFS Banner](https://capsule-render.vercel.app/api?type=waving&color=0:121212,100:FF4500&height=220&section=header&text=MirageFS&fontSize=90&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&rotate=2&stroke=FF4500&strokeWidth=2&desc=The%20Invisible%20Filesystem&descSize=20&descAlignY=60)


![Version](https://img.shields.io/badge/version-1.1.0-blue.svg?style=for-the-badge)
![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2%20%7C%20macOS-lightgrey.svg?style=for-the-badge&logo=linux)

**Mount encrypted, hidden storage inside innocent image files.**

[Installation](#-installation) • [Usage](#-usage) • [Technical Details](#-technical-deep-dive) • [Disclaimer](#-disclaimer)

</div>

---

## 📖 Overview

**MirageFS** is a high-stealth steganographic filesystem built in Rust. It allows you to format and mount standard image files (`.png`, `.jpg`, `.webp`) as fully functional read/write drives.

Unlike traditional steganography tools that simply hide a static payload, MirageFS implements a **virtual block device** inside the image. This means you can interact with your hidden files in real-time using your OS's native file explorer (`cp`, `mv`, `vim`, `mkdir`, etc.) without extracting them first.

## 🚀 Key Features

### 🛡️ Military-Grade Encryption
Your data is secured with state-of-the-art authenticated encryption.
* **Cipher:** **XChaCha20-Poly1305** (Extended Nonce + MAC authentication).
* **KDF:** **Argon2id** (Resistant to GPU/ASIC brute-force attacks).
* **Nonce Randomization:** Every block write generates a unique nonce; writing the same file twice produces completely different ciphertext.

### 🥷 Advanced Steganography
MirageFS employs distinct, format-optimized strategies to defeat forensic analysis.

| Image Format | Strategy | Stealth Technique |
| :--- | :--- | :--- |
| **PNG** | **PRNG Scatter** | Bits are scattered non-sequentially across the LSB layer using a CSPRNG seeded by your key. Defeats visual analysis and Chi-Square tests. |
| **JPEG** | **DNG Morphing** | Data is injected into `APP1` segments mimicking valid **Adobe DNG Private Data** (Tag `0xC634`) inside a standard TIFF structure. |
| **WebP** | **RIFF Morphing** | Similar to JPEG, data is disguised as vendor-specific metadata inside the `EXIF` chunk of the RIFF container. |

### 👻 Forensic Resistance
* **Entropy Dilution:** Encrypted data is "diluted" (expanded) to lower its entropy density to ~7.0 bits/byte, making it statistically indistinguishable from standard camera metadata or sensor noise.
* **Tool Blindness:** Standard forensic tools like `binwalk`, `zsteg`, and `foremost` fail to detect the filesystem because it lacks standard headers and structurally blends into the container.

---

## 📦 Installation

### 1. Prerequisites
MirageFS relies on **FUSE (Filesystem in Userspace)**.

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

### 2. Build from Source
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

Create a new secret drive inside a carrier image.

> [!WARNING]
> This overwrites any data previously hidden in the image. It does **not** destroy the visible image itself, but modifies the internal bit structure.

```bash
# Syntax: mirage <MOUNT_POINT> <IMAGE_FILE> --format

mkdir /tmp/secret
mirage /tmp/secret vacation.png --format

```

### 2️⃣ Mounting

Unlock and mount the drive to access your files.

```bash
mirage /tmp/secret vacation.png

```

You can now open `/tmp/secret` in your file manager. Any file copied here is encrypted and embedded into `vacation.png` on the fly.

### 3️⃣ Unmounting

To close the drive and flush all data:

* Press `Ctrl + C` in the terminal.
* **Or** run: `fusermount -u /tmp/secret`

---

## 🔧 Technical Deep Dive

### 🟦 The PNG "Scatter" Engine

Traditional LSB steganography fills pixels sequentially (left-to-right), creating obvious "static" blocks that are easily detected visually or statistically.

**MirageFS Approach:**

1. **Derivation:** Password derives a seed via Argon2id.
2. **Shuffle:** A `ChaCha20` RNG generates a deterministic list of pixel coordinates.
3. **Scatter:** Data blocks are written to these scattered coordinates.
4. **Result:** Noise is spread evenly across the entire image, mimicking natural ISO sensor noise.

### 🟧 The JPEG/WebP "Morphing" Engine

Compressed formats like JPEG destroy LSB data during re-encoding. MirageFS exploits the metadata layer instead.

**MirageFS Approach:**

1. **Dilution:** High-entropy encrypted data is expanded (7 bits → 8 bytes) to lower its statistical randomness.
2. **Camouflage:** Data is wrapped in valid **TIFF headers**.
3. **Injection:** The blob is labeled as `DNGPrivateData` (Tag `0xC634`).
4. **Result:** Forensic tools ignore the data, identifying it as "proprietary Adobe metadata" rather than a suspicious payload.

---

## 🖥️ Platform Notes

<details>
<summary><strong>🐧 Linux (Native)</strong></summary>
Works out of the box with standard FUSE installation.
</details>

<details>
<summary><strong>🪟 Windows (WSL2)</strong></summary>
MirageFS works perfectly in WSL2, allowing you to browse hidden files using <strong>Windows Explorer</strong>.

> **WSL2 Visibility Fix:**
> If you cannot see files in Windows Explorer, ensure `/etc/fuse.conf` has `user_allow_other` uncommented.
> 1. `sudo nano /etc/fuse.conf`
> 2. Uncomment `user_allow_other`
> 3. Navigate to `\\wsl$\Ubuntu\tmp\secret` in Explorer.
> 
> 

</details>

<details>
<summary><strong>🍎 macOS</strong></summary>
Requires <a href="https://macfuse.github.io/">macFUSE</a>. The code automatically detects UID/GID, but macOS security policies may require manual approval for FUSE kernel extensions in System Settings.
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

*v1.0.0*

</div>

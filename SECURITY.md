# Security Policy

MirageFS is a security-focused tool designed to demonstrate advanced steganography and filesystem concepts. We take the security of our users and their data seriously.

## 📦 Supported Versions

Security updates and patches are provided for the following versions:

| Version | Supported          |
| :------ | :----------------- |
| 1.4.x   | :white_check_mark: |
| 1.3.x   | :white_check_mark: |
| < 1.3.0 | :x:                |

## 🛡️ Reporting a Vulnerability

If you discover a security vulnerability in MirageFS, please **do not** open a public issue. We appreciate your help in disclosing the issue to us responsibly.

### How to Report
Please report vulnerabilities privately via one of the following methods:
1.  **GitHub Security Advisory:** Open a [Draft Security Advisory](https://github.com/SSL-ACTX/mirage-fs/security/advisories/new) on the repository (Preferred).
2.  **Email:** Contact the maintainer directly at [seuriin@gmail.com](mailto:seuriin@gmail.com) (if applicable).

### What to Include
* A description of the vulnerability.
* Steps to reproduce the issue (POC code or commands).
* Potential impact (e.g., data leakage, denial of service, forensic detection).

We aim to acknowledge reports within **48 hours** and will provide a timeline for a fix.

## 🎯 Threat Model & Scope

MirageFS is a powerful tool, but it is not magic. To understand what constitutes a "security failure," please review our threat model:

### In Scope (We want to know!)
* **Cryptographic Weaknesses:** Flaws in the XChaCha20-Poly1305 implementation, Argon2id parameter choices, or nonce reuse.
* **Data Leakage:** Cases where hidden data is inadvertently written to the host filesystem or leaked via the WebDAV interface to unauthorized clients.
* **Authentication Bypass:** Bypassing the Web UI or Volume password prompts.
* **Memory Safety:** Buffer overflows or use-after-free vulnerabilities in the Rust code.

### Out of Scope (Known Limitations)
* **Forensic Detection:** While we strive for high stealth, steganography is an arms race. A report stating "I detected the hidden volume using statistical analysis tool X" is a **feature request/enhancement**, not a security vulnerability, unless the detection is trivial (e.g., a visible file header).
* **Compromised Host:** If the host machine running MirageFS is compromised (keyloggers, root access), the security of the volume cannot be guaranteed.
* **Traffic Analysis:** An adversary observing your network traffic (WebDAV) may infer you are transferring data, even if they cannot read it.

## ⚠️ Disclaimer

MirageFS is provided "as is", without warranty of any kind. While we implement military-grade encryption standards, this software is primarily a proof-of-concept for educational and research purposes. Do not rely on it for protecting life-critical data.

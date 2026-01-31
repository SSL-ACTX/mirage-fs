# Contributing to MirageFS

First off, thank you for considering contributing to MirageFS! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

MirageFS is a security-focused tool, so we value code clarity, stability, and safety. Whether you're fixing a bug, improving the steganography engines, or polishing the new Web UI, your help is welcome.

## 🛠️ Getting Started

### Prerequisites
You will need the **Rust toolchain** installed on your machine.
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

```

### Setting Up the Environment

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
```bash
git clone https://github.com/YOUR_USERNAME/mirage-fs.git
cd mirage-fs

```

3. **Build** the project to ensure everything is working:
```bash
cargo build

```

## 💻 Development Workflow

1. **Create a Branch**
Create a new branch for your feature or fix. Please use descriptive names:
```bash
git checkout -b feat/new-stego-algo
# or
git checkout -b fix/webdav-crash

```


2. **Make Your Changes**
* **Rust Backend:** Keep code idiomatic. If modifying core logic (`mirage_fs.rs`, `block_device.rs`), ensure you understand the locking mechanisms.
* **Web UI:** If modifying `src/web_assets.rs`, remember that the HTML/JS is embedded. Test thoroughly in a browser.


3. **Test Your Changes**
* Run the standard test suite:
```bash
cargo test

```

* Manual testing is crucial for this project. Try mounting a drive, copying files, and unmounting.
* **WebDAV Testing:** Run with `--webdav` and connect via a client or browser to verify UI changes.


4. **Format and Lint**
Before committing, please ensure your code adheres to standard Rust style guidelines.
```bash
cargo fmt --all
cargo clippy -- -D warnings

```

## 📬 Submitting a Pull Request

1. Push your branch to your fork.
2. Open a Pull Request (PR) against the `main` branch of the original repository.
3. **Description:** clearly explain *what* you changed and *why*.
4. If your PR fixes an open issue, link to it (e.g., "Closes #123").

## 🐛 Reporting Bugs

If you find a bug but don't know how to fix it, please open an Issue!

* **Title:** Clear and concise summary.
* **Steps to Reproduce:** detailed instructions to make the bug happen.
* **Expected vs. Actual Behavior:** What should have happened vs. what did happen.
* **Environment:** OS (Linux/Windows/macOS), Terminal, FUSE version (if applicable).

## 🎨 Coding Style

* **Rust:** We use `rustfmt` for code formatting.
* **Comments:** Comment complex logic, especially crypto/steganography math.
* **Safety:** Avoid `unsafe` blocks unless absolutely necessary and well-justified.

## 📜 License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 License, as defined in the `README.md`.

---

<div align="center">
  <p>Happy Hacking! 🕵️‍♂️ </p>
</div>

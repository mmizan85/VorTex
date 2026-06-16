


# 🔐 Vortex Vault

<p align="center">
  <img src="vortex_icon.ico" alt="Vortex Vault Logo" width="120px" height="120px" />
</p>

<h3 align="center">Advanced Zero-Knowledge File Security System with Git-Like Workflow</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-darkgreen.svg?style=for-the-badge" alt="Platforms" />
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-vividpurple?style=for-the-badge" alt="Encryption" />
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License" />
</p>

---

## 🌌 Introduction

**Vortex Vault** is a production-ready, cross-platform Command Line Interface (CLI) cryptographic utility designed to secure private files and directories selectively. Operating under a strict **Zero-Knowledge Architecture**, your master PIN never enters disk storage in plaintext. Leveraging robust **AES-256-GCM** encryption and an industry-standard **PBKDF2** key derivation framework, it guarantees supreme military-grade data privacy.

---

## 📸 Screenshots & Visuals

> 💡 *Tip: Replace these placeholders with your actual application screenshots once uploaded to your repository assets folder.*

### 🖥️ High-Performance Interactive CLI Menu
<p align="center">
  <img src="assets/screenshots/cli_status_dashboard.png" alt="Vortex Status Dashboard" width="85%" />
</p>
<!--
### 🛡️ Secure OS Global Registry Auto-Recovery
<p align="center">
  <img src="assets/screenshots/auto_recovery_demostration.png" alt="Global Recovery Mechanism" width="85%" />
</p>
-->

---

## ✨ Features & Architecture Highlights

* **🛡️ Cryptographic Key Hierarchy:** Derives a Key Encryption Key (KEK) via PBKDF2-HMAC-SHA-256 with `480,000 iterations` (OWASP 2023 Compliant) to safely wrap the Data Encryption Key (DEK).
* **🔗 Chunked Processing & AAD Binding:** Large asset payloads are structured inside `.vtx` wrappers utilizing Additional Authenticated Data (`b"<file_uuid>:<chunk_index>"`), locking out chunk-swapping or truncation vectors.
* **📂 OS-Level Global Database Registry:** Automatically backs up vault configurations into Windows `AppData/Local` (or Unix `~/.config`). Even if your local hidden `.vortex` folder is accidentally deleted, your environment auto-reconstructs natively upon execution!
* **⚡ Double-Alias Mapping:** Fully compatible with both `vortex` and short-form `vtx` CLI runtime invocation signatures.
* **🧠 Anti-Intrusion Lockout & Audit Trails:** Features an active background lockout matrix that freezes operations after 3 failed access attempts, backed by an unencrypted persistent audit log.

---

## 🛠️ Installation & Setup Guide

Vortex Vault can be deployed using either the raw Python developer pipeline or via the standalone high-performance Windows binary executable installer package.

### 🐍 Method 1: Python Developer Installation (Cross-Platform)

Ensure you have **Python 3.8 or later** installed on your system terminal framework.

```bash
# 1. Clone the repository framework
git clone https://github.com/mmizan85/VorTex.git
cd VorTex

# 2. Deploy core package dependencies
pip install -r requirements.txt

# 3. Mount and bind development links natively
pip install -e .

# 4. Verify cross-platform runtime operational state
vortex --version
# OR use short-form alias
vtx --version

```

### 🪟 Method 2: High-Performance Windows Standalone Installer

For standard users, download our single-bundle high-speed deployment framework compiled with professional **Inno Setup (LZMA2/Ultra64 Compression Engine)**.

1. Navigate to the [GitHub Releases](https://github.com/mmizan85/VorTex/releases) portal page.
2. Download the unified executable payload: `VortexVault_Setup.exe`.
3. Open the setup wizard file and proceed with the automated installation parameters.
4. **Boom! 🎉** The installer securely updates your Windows Environment System Path variables natively. Open any fresh PowerShell instance or Command Prompt anywhere and start managing your workspace immediately using `vortex` or `vtx`.

---

## ⌨️ Command Operational Protocol Guide

Vortex Vault implements a highly explicit, clear, and clean terminal matrix formatting scheme driven by the Python `Rich` package.

| Target Command | Sub-Parameters | Operational Protocol & System Actions | Execution Sample Pattern |
| --- | --- | --- | --- |
| **`init`** | `-s, --selective` <br>`-t, --timeout <min>` | Mounts and initializes a completely fresh, isolated zero-knowledge cryptographic vault configuration framework in your active working path directory. | `vortex init`<br>`vortex init -s`<br>`vortex init -t 15` |
| **`add`** | `<paths...>`<br> `-s, --selective` | Appends specific raw local file paths or deep directories into the local tracking registry manifest files database. | `vortex add payroll.db`<br>`vortex add -s` |
| **`lock`** | `[target_path]` | Runs an atomic, secure AES-256-GCM sweep over tracked items. Overwrites the plaintext source assets with zeroes before erasing them safely from physical sectors. | `vortex lock`<br>`vortex lock secure_media/` |
| **`unlock`** | `None` | Evaluates master authentication signatures, validates size integrity blocks, and entirely decrypts targets back to normal plaintext storage state. | `vortex unlock` |
| **`status`** | `None` | Builds an interactive visual reporting matrix tracking live vs scrambled objects, along with active auto-lock time counts. | `vortex status` |
| **`untrack`** | `<target_path>` | Decrypts the targeted file context, isolates it completely from the underlying ledger, and pushes it out to normal unmanaged storage. | `vortex untrack assets/` |
| **`reset`** | `None` | Bypasses standard authentication limits via a unique 16-character Master Recovery Key string block to override corrupted or forgotten passcodes. | `vortex reset` |
| **`purge`** | `None` | Emergency destruction protocol. Mass decrypts files, completely sweeps cryptographic local arrays, deletes logging states, and burns the `.vortex` structure. | `vortex purge` |

---

## 📁 Source Tree Layout

```modula2
VorTex/
├── assets/                     # Media files, graphics, and documentation screenshots
│   └── screenshots/
├── vortex/                     # Core system implementation packages
│   ├── __init__.py             # Engine package properties metadata
│   ├── audit.py                # Logging pipelines for monitoring security state
│   ├── cli.py                  # Custom Rich interface CLI layout configuration
│   ├── crypto_engine.py        # Cryptographic layer foundations (AES-GCM / PBKDF2)
│   ├── exceptions.py           # Specialized exception handler classifications
│   ├── file_ops.py             # Atomic file processing layers and zeroing tasks
│   ├── security.py             # Memory-cleaning primitives and runtime safeguards
│   ├── selector.py             # Multi-select dropdown checkboxes framework terminal UI
│   └── vault_manager.py        # Core structural logic & OS Global Registry management
├── installer_config.iss        # Premium Inno Setup configuration scripts source
├── main.py                     # Global unified execution endpoint router
├── requirements.txt            # System component dependency matrix
└── setup.py                    # Global platform packaging and linking definitions

```

---

## 🔧 Performance & PyInstaller Compilation Optimization

To construct a high-speed runtime optimized directly for Windows administrative file management structures, execute the standard compilation payload:

```bash
pyinstaller --onefile --name=vortex --clean --icon=vortex_icon.ico main.py

```

This single administrative bypass pipeline optimizes loading latencies, maps resource allocation hooks efficiently, and encapsulates the complete system logic structure elegantly.

---

## 👑 Lead Engineer & System Architect

* **Mohammad Mijanur Rahman** ([@MohammadMizan](https://github.com/mmizan85))
* Feel free to drop a 🌟 on the repo if this security engine helped secure your localized automation pipelines!

---

## 📄 License

This project configuration is licensed under the terms defined within the **MIT License**.

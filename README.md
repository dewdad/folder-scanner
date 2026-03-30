# folder-scanner

Cross-platform security scanner that integrates into your file manager's right-click menu. Scans files and folders for vulnerabilities, malware, and suspicious patterns using multiple engines in parallel.

## Scanner Engines

| Engine | Detects | Method |
|--------|---------|--------|
| **[Trivy](https://github.com/aquasecurity/trivy)** | CVEs, secrets, misconfigs, license issues | Subprocess &rarr; JSON |
| **[ClamAV](https://www.clamav.net/)** | Viruses, trojans, malware (8M+ signatures) | Subprocess &rarr; stdout |
| **[YARA](https://virustotal.github.io/yara-x/)** | Backdoors, webshells, suspicious patterns | Subprocess (yr/yara CLI) |
| **Windows Defender** | Microsoft cloud-backed threat intelligence | MpCmdRun.exe (Windows only) |

All scanners run in parallel. Missing scanners are auto-bootstrapped on first use or gracefully skipped.

## Installation

### From source

```bash
cargo install --path .
```

### Setup

```bash
# Download scanner tools + register right-click context menu
folder-scanner install
```

This will:
1. Download Trivy binary from GitHub Releases
2. Download YARA community rule sets (Neo23x0/signature-base, Yara-Rules)
3. Check for ClamAV (prints install instructions if missing)
4. Register "Scan with FolderScanner" in your file manager

## Usage

### Command Line

```bash
# Scan a directory
folder-scanner scan ./my-project

# Scan with JSON output
folder-scanner scan ./my-project -f json

# Scan with HTML report, open in browser
folder-scanner scan ./my-project -f html --open

# Only show high/critical findings
folder-scanner scan ./my-project -s high

# Save report to file
folder-scanner scan ./my-project -f json -o report.json
```

### Right-Click Menu

After running `folder-scanner install`, right-click any file or folder in your file manager and select **"Scan with FolderScanner"**.

### Other Commands

```bash
folder-scanner status            # Show installed scanners and versions
folder-scanner update            # Update binary + all signature databases
folder-scanner update --sigs-only # Update only signatures
folder-scanner uninstall         # Remove context menu entries
```

## File Manager Support

### Windows
- **Windows Explorer** &mdash; Registry-based context menu (HKCU, no admin required)

### macOS
- **Finder** &mdash; Automator Quick Action (Services menu)

### Linux
- **Nautilus** (GNOME) &mdash; Scripts directory
- **Dolphin** (KDE) &mdash; ServiceMenus `.desktop` file
- **Thunar** (XFCE) &mdash; Custom actions (`uca.xml`)
- **Nemo** (Cinnamon) &mdash; `.nemo_action` file
- **PCManFM** (LXDE/LXQt) &mdash; Desktop action file
- **Caja** (MATE) &mdash; Scripts directory

All managers are auto-detected during install. No elevated permissions required on any platform.

## Report Formats

| Format | Flag | Description |
|--------|------|-------------|
| **Text** | `-f text` (default) | Colored terminal output with tables |
| **JSON** | `-f json` | Machine-readable, CI/CD friendly |
| **HTML** | `-f html` | Self-contained dark-themed report |

## Auto-Update

```bash
# Update everything (binary + all signature DBs)
folder-scanner update

# Update only signature databases
folder-scanner update --sigs-only
```

Updates:
- **Binary**: Self-update from GitHub Releases
- **Trivy DB**: Official vulnerability database (`trivy image --download-db-only`)
- **ClamAV**: Virus definitions via `freshclam`
- **YARA rules**: Re-downloads community rule archives

## Building

```bash
cargo build              # Debug build
cargo build --release    # Release build (LTO + strip)
cargo check              # Type-check only (fast)
```

### Cross-Compilation

The binary embeds its target triple via `build.rs` for self-update asset matching. Build for the target platform directly or use cross-compilation:

```bash
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin
cargo build --release --target x86_64-pc-windows-msvc
```

## Project Structure

```
folder-scanner/
├── src/
│   ├── main.rs              # CLI entry point (5 commands)
│   ├── cli.rs               # clap argument definitions
│   ├── config.rs            # Platform paths and constants
│   ├── platform/            # Platform detection utilities
│   ├── scanner/             # Scanner trait + 4 engine implementations
│   ├── context_menu/        # File manager integration (Win/Mac/Linux)
│   ├── report/              # Terminal, JSON, HTML renderers
│   └── updater/             # Self-update + signature management
├── templates/
│   └── report.html          # HTML report template (minijinja)
├── build.rs                 # Bakes TARGET triple for self-update
└── Cargo.toml
```

## License

MIT

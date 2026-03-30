# PROJECT KNOWLEDGE BASE

**Generated:** 2026-03-30
**Branch:** master (no commits yet)

## OVERVIEW

Cross-platform Rust CLI that scans files/folders for vulnerabilities and malware using Trivy + ClamAV + YARA + Windows Defender in parallel, with file manager context menu integration across Windows/macOS/Linux.

## STRUCTURE

```
folder-scanner/
├── src/
│   ├── main.rs              # Entry: 5 commands (scan/install/uninstall/update/status)
│   ├── cli.rs               # clap derive: Cli, Commands, ScanArgs, UpdateArgs, OutputFormat, Severity
│   ├── config.rs            # All path resolution + constants (tools_dir, yara_rules_dir, GitHub URLs)
│   ├── platform/mod.rs      # trivy_download_url(), command_exists(), detect_file_managers()
│   ├── scanner/             # → see src/scanner/AGENTS.md
│   ├── context_menu/        # → see src/context_menu/AGENTS.md
│   ├── report/
│   │   ├── mod.rs           # ScanReport model: merges ScannerResult[] → unified findings
│   │   ├── terminal.rs      # comfy-table + console colored output
│   │   ├── json.rs          # serde_json::to_string_pretty wrapper
│   │   └── html.rs          # minijinja template renderer
│   └── updater/
│       ├── mod.rs           # bootstrap_all(), update_self(), update_signatures()
│       └── download.rs      # download_file() w/ progress, get_github_latest_release(), extract_*()
├── templates/
│   └── report.html          # Self-contained dark-themed Jinja2 template (minijinja)
├── build.rs                 # Bakes TARGET triple via cargo env
└── Cargo.toml               # edition 2021, 25 deps
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add new scanner engine | `src/scanner/` | Implement `Scanner` trait, add to `build_scanner_list()` |
| Change scan output | `src/report/` | Three renderers: terminal, json, html |
| Modify context menu text | `src/context_menu/{platform}.rs` | Each platform has its own label strings |
| Change tool download URLs | `src/config.rs` | `TRIVY_GITHUB_*`, `YARA_RULE_REPOS` constants |
| Add CLI flag | `src/cli.rs` | clap derive structs, then wire in `main.rs` |
| Update self-update repo | `src/config.rs` | `GITHUB_OWNER`, `GITHUB_REPO` |
| Change app data paths | `src/config.rs` | `data_dir()`, `cache_dir()`, `tools_dir()` |
| HTML report styling | `templates/report.html` | Inline CSS, no external deps |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Scanner` | trait | `scanner/mod.rs:119` | Core interface: name, is_available, scan, bootstrap |
| `Finding` | struct | `scanner/mod.rs:78` | Universal finding model (all scanners produce these) |
| `FindingSeverity` | enum | `scanner/mod.rs:12` | Unknown < Low < Medium < High < Critical (Ord) |
| `ScannerResult` | struct | `scanner/mod.rs:102` | Per-engine result: success, error, findings, duration |
| `ScanReport` | struct | `report/mod.rs:13` | Unified report: merges all ScannerResults |
| `run_all_scanners` | fn | `scanner/mod.rs:137` | Parallel orchestrator: spawn per scanner, auto-bootstrap |
| `build_scanner_list` | fn | `scanner/mod.rs:204` | Constructs Vec<Box<dyn Scanner>> per platform |
| `install/uninstall` | fn | `context_menu/mod.rs` | Platform-dispatched context menu registration |
| `bootstrap_all` | fn | `updater/mod.rs:12` | Downloads Trivy + YARA rules + checks ClamAV |

## CONVENTIONS

- **Error handling**: `anyhow::Result` everywhere. `?` propagation, `.with_context()` for messages. No `.unwrap()` in production paths.
- **Cross-platform**: `#[cfg(target_os = "...")]` on module declarations in `mod.rs` files. Platform files use `#![cfg(...)]` file-level attributes.
- **Async**: tokio runtime. Scanners use `tokio::process::Command`. `self_update` is blocking → wrapped in `spawn_blocking`.
- **Subprocess pattern**: All external tools (trivy, clamscan, yara, MpCmdRun, tar, PowerShell) invoked via `tokio::process::Command` or `std::process::Command`.
- **Serde**: Trivy JSON uses `#[serde(rename_all = "PascalCase")]` to match Go output. Internal types use default snake_case.
- **Graceful degradation**: Missing scanners → skip with warning, never fail the whole scan.

## ANTI-PATTERNS (THIS PROJECT)

- **NEVER** use `unsafe` except the single `SHChangeNotify` FFI call in `context_menu/windows.rs` (documented SAFETY comment)
- **NEVER** `.unwrap()` on fallible operations in scan/bootstrap paths — use `?` or handle gracefully
- **NEVER** auto-quarantine files — Windows Defender always uses `-DisableRemediation`
- **NEVER** add `#[allow(unused)]` as a blanket — only `#[allow(dead_code)]` on specific serde fields

## COMMANDS

```bash
cargo check                              # Type-check (fast)
cargo build                              # Debug build
cargo build --release                    # Release build (LTO + strip)
cargo run -- scan <path>                 # Scan a path
cargo run -- scan <path> -f json         # JSON output
cargo run -- scan <path> -f html --open  # HTML report + open browser
cargo run -- install                     # Download tools + register context menus
cargo run -- update                      # Update binary + all signatures
cargo run -- status                      # Show scanner availability
```

## NOTES

- No tests yet — project is in initial implementation phase
- `self_update` crate asset matching requires GitHub release assets named with `env!("TARGET")` triple
- Trivy bootstrap downloads platform-specific archive (zip on Windows, tar.gz on Unix)
- YARA scanner prefers `yr` (YARA-X) CLI → falls back to classic `yara` → fails gracefully if neither available
- Linux context_menu installs for ALL detected file managers simultaneously
- HTML template uses minijinja Jinja2 syntax, NOT Handlebars
- `edition = "2021"` (not 2024) for broader toolchain compatibility

# SCANNER MODULE

Core domain logic. Trait-based polymorphic scanner architecture with parallel orchestration.

## STRUCTURE

```
scanner/
├── mod.rs       # Scanner trait + Finding/ScannerResult types + run_all_scanners orchestrator
├── trivy.rs     # Trivy subprocess (JSON output) — vulnerabilities, secrets, misconfigs
├── clamav.rs    # ClamAV subprocess (stdout parse) — malware signature detection
├── yara.rs      # YARA-X/classic CLI subprocess — pattern matching with community rules
└── defender.rs  # Windows Defender MpCmdRun (#[cfg(windows)]) — cloud-backed threat intel
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add new scanner | `mod.rs:build_scanner_list()` | Construct + push `Box::new(YourScanner::new())` |
| Change scanner interface | `mod.rs:Scanner` trait | 4 methods: `name`, `is_available`, `scan`, `bootstrap` |
| Change parallel behavior | `mod.rs:run_all_scanners()` | Uses `tokio::spawn` per scanner, collects via `join` |
| Add finding metadata | `mod.rs:Finding` | `metadata: serde_json::Value` — scanner-specific extras |
| Change severity mapping | Each scanner's `scan()` | `FindingSeverity::from_str_loose()` for string → enum |
| Change Trivy JSON parsing | `trivy.rs` | `TrivyReport`/`TrivyResult`/`TrivyVulnerability` — `#[serde(rename_all = "PascalCase")]` |

## CONVENTIONS

- **Scanner lifecycle**: `is_available()` → `bootstrap()` (if missing) → `is_available()` again → `scan()`. See `run_all_scanners()`.
- **Auto-bootstrap**: `run_all_scanners` auto-calls `bootstrap()` for unavailable scanners before giving up.
- **Error ≠ failure**: Scanners return `ScannerResult { success: false, error: Some(...) }` rather than `Err(...)` for expected failures (tool not found, parse errors). `Err(...)` is for unexpected panics.
- **Duration**: Set to 0 by scanner impls; overwritten by orchestrator using `Instant::now()` timing.
- **Subprocess**: All use `tokio::process::Command`. Trivy → JSON stdout. ClamAV → text stdout (`<path>: <virus> FOUND`). YARA → NDJSON or text. Defender → exit code + best-effort stdout parse.
- **Platform gating**: `defender.rs` uses `#![cfg(target_os = "windows")]`. `build_scanner_list()` conditionally includes Defender via `#[cfg(target_os = "windows")]`.

## ANTI-PATTERNS

- **NEVER** add a scanner that blocks the async runtime — always use `tokio::process::Command` (async) or wrap blocking in `spawn_blocking`
- **NEVER** `.unwrap()` on subprocess output — tools may not exist, output may be empty/corrupt
- **NEVER** auto-quarantine or modify scanned files — use `-DisableRemediation` for Defender, read-only flags for others

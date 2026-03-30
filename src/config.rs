use anyhow::{Context, Result};
use std::path::PathBuf;

/// Application name used for directory naming
const APP_NAME: &str = "folder-scanner";

/// Returns the application data directory.
/// - Linux: ~/.local/share/folder-scanner
/// - macOS: ~/Library/Application Support/folder-scanner
/// - Windows: %LOCALAPPDATA%/folder-scanner
pub fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().context("Could not determine local data directory")?;
    Ok(base.join(APP_NAME))
}

/// Returns the application cache directory.
/// - Linux: ~/.cache/folder-scanner
/// - macOS: ~/Library/Caches/folder-scanner
/// - Windows: %LOCALAPPDATA%/folder-scanner/cache
pub fn cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir().context("Could not determine cache directory")?;
    Ok(base.join(APP_NAME))
}

/// Returns the directory where scanner tools are stored (trivy binary, etc.)
pub fn tools_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("tools"))
}

/// Returns the directory where YARA rules are stored
pub fn yara_rules_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("yara-rules"))
}

/// Returns the Trivy cache directory (for vulnerability DB)
pub fn trivy_cache_dir() -> Result<PathBuf> {
    Ok(cache_dir()?.join("trivy"))
}

/// Returns the directory where scan reports are cached
pub fn reports_dir() -> Result<PathBuf> {
    Ok(cache_dir()?.join("reports"))
}

/// Returns the expected path to the Trivy binary
pub fn trivy_binary_path() -> Result<PathBuf> {
    let name = if cfg!(windows) { "trivy.exe" } else { "trivy" };
    Ok(tools_dir()?.join(name))
}

/// Returns the expected path to the clamscan binary.
/// First checks our tools dir, then falls back to system PATH.
pub fn clamscan_binary_path() -> PathBuf {
    // Check common system locations first
    #[cfg(target_os = "windows")]
    {
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let candidate = PathBuf::from(&program_files)
            .join("ClamAV")
            .join("clamscan.exe");
        if candidate.exists() {
            return candidate;
        }
    }

    // Fall back to PATH lookup
    PathBuf::from(if cfg!(windows) {
        "clamscan.exe"
    } else {
        "clamscan"
    })
}

/// Returns the expected path to freshclam binary
pub fn freshclam_binary_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let candidate = PathBuf::from(&program_files)
            .join("ClamAV")
            .join("freshclam.exe");
        if candidate.exists() {
            return candidate;
        }
    }

    PathBuf::from(if cfg!(windows) {
        "freshclam.exe"
    } else {
        "freshclam"
    })
}

/// Returns the path to Windows Defender's MpCmdRun.exe
#[cfg(target_os = "windows")]
pub fn windows_defender_path() -> Option<PathBuf> {
    let platform_dir = PathBuf::from(r"C:\ProgramData\Microsoft\Windows Defender\Platform");
    if let Ok(entries) = std::fs::read_dir(&platform_dir) {
        // Find the latest version directory
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.path())
            .collect();
        versions.sort();
        if let Some(latest) = versions.last() {
            let exe = latest.join("MpCmdRun.exe");
            if exe.exists() {
                return Some(exe);
            }
        }
    }

    // Fallback to legacy path
    let fallback = PathBuf::from(r"C:\Program Files\Windows Defender\MpCmdRun.exe");
    if fallback.exists() {
        return Some(fallback);
    }

    None
}

/// Ensure all application directories exist
pub fn ensure_dirs() -> Result<()> {
    let dirs = [
        data_dir()?,
        cache_dir()?,
        tools_dir()?,
        yara_rules_dir()?,
        trivy_cache_dir()?,
        reports_dir()?,
    ];
    for dir in &dirs {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    }
    Ok(())
}

/// GitHub repository owner for self-update
pub const GITHUB_OWNER: &str = "dewdad";
/// GitHub repository name for self-update
pub const GITHUB_REPO: &str = "folder-scanner";

/// Trivy GitHub release info
pub const TRIVY_GITHUB_OWNER: &str = "aquasecurity";
pub const TRIVY_GITHUB_REPO: &str = "trivy";

/// YARA rule repository URLs
pub const YARA_RULE_REPOS: &[(&str, &str)] = &[
    (
        "signature-base",
        "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz",
    ),
    (
        "yara-rules",
        "https://github.com/Yara-Rules/rules/archive/refs/heads/master.tar.gz",
    ),
];

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;

use crate::config;
use crate::platform;
use crate::scanner::{Finding, FindingCategory, FindingSeverity, Scanner, ScannerResult};

pub struct ClamAvScanner;

impl ClamAvScanner {
    pub fn new() -> Self {
        ClamAvScanner
    }

    /// Returns the clamscan binary path to use (configured path if exists, else PATH fallback)
    fn clamscan_bin() -> String {
        let configured = config::clamscan_binary_path();
        if configured.exists() {
            configured.to_string_lossy().to_string()
        } else {
            // Just use the bare name and let the OS find it in PATH
            if cfg!(windows) {
                "clamscan.exe".to_string()
            } else {
                "clamscan".to_string()
            }
        }
    }
}

#[async_trait]
impl Scanner for ClamAvScanner {
    fn name(&self) -> &str {
        "clamav"
    }

    async fn is_available(&self) -> bool {
        let configured = config::clamscan_binary_path();
        if configured.exists() {
            return true;
        }
        platform::command_exists("clamscan")
    }

    async fn scan(&self, target: &Path) -> Result<ScannerResult> {
        let clamscan_bin = Self::clamscan_bin();

        let output = Command::new(&clamscan_bin)
            .args([
                "--recursive",
                "--infected",
                "--no-summary",
                "--stdout",
                &target.to_string_lossy(),
            ])
            .output()
            .await
            .with_context(|| format!("Failed to execute clamscan binary: {}", clamscan_bin))?;

        let exit_code = output.status.code().unwrap_or(-1);

        // Exit codes:
        //   0 = no infections found
        //   1 = virus(es) found
        //   2 = some error(s) occurred
        if exit_code == 2 {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: false,
                error: Some(format!("clamscan reported an error: {}", stderr.trim())),
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        // Parse lines like: <path>: <virus_name> FOUND
        for line in stdout.lines() {
            let line = line.trim();
            if !line.ends_with("FOUND") {
                continue;
            }

            // Format: "<file_path>: <virus_name> FOUND"
            // Split at the last ': ' occurrence before ' FOUND'
            let without_found = line.trim_end_matches("FOUND").trim_end();
            if let Some(colon_pos) = without_found.rfind(": ") {
                let file_path = without_found[..colon_pos].to_string();
                let virus_name = without_found[colon_pos + 2..].trim().to_string();

                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Malware,
                    severity: FindingSeverity::Critical,
                    file_path,
                    title: virus_name.clone(),
                    description: format!("ClamAV detected malware: {}", virus_name),
                    remediation: Some(
                        "Quarantine or delete the infected file immediately and run a full system scan."
                            .to_string(),
                    ),
                    reference_url: None,
                    metadata: serde_json::json!({ "virus_name": virus_name }),
                });
            } else {
                // Unexpected format — record the raw line
                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Malware,
                    severity: FindingSeverity::Critical,
                    file_path: target.to_string_lossy().to_string(),
                    title: "Unknown malware".to_string(),
                    description: format!("ClamAV reported: {}", line),
                    remediation: Some("Investigate the file reported by ClamAV.".to_string()),
                    reference_url: None,
                    metadata: serde_json::json!({ "raw_line": line }),
                });
            }
        }

        Ok(ScannerResult {
            scanner_name: self.name().to_string(),
            success: true,
            error: None,
            duration_ms: 0,
            findings,
            version: None,
        })
    }

    async fn bootstrap(&self) -> Result<()> {
        // ClamAV cannot be auto-downloaded portably. Print instructions and return Ok.
        if self.is_available().await {
            tracing::info!("ClamAV (clamscan) is already available.");
            return Ok(());
        }

        tracing::warn!(
            "ClamAV is not installed. Please install it manually:\n\
             - Linux (Debian/Ubuntu): sudo apt-get install clamav\n\
             - Linux (RHEL/Fedora):   sudo dnf install clamav clamav-update\n\
             - macOS (Homebrew):      brew install clamav\n\
             - Windows:               https://www.clamav.net/downloads\n\
             After installation, run 'freshclam' to update the virus database."
        );

        // Bootstrap is best-effort; return Ok so the scanner is simply skipped.
        Ok(())
    }
}

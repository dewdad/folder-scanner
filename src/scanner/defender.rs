#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;

use crate::config;
use crate::scanner::{Finding, FindingCategory, FindingSeverity, Scanner, ScannerResult};

pub struct DefenderScanner;

impl DefenderScanner {
    pub fn new() -> Self {
        DefenderScanner
    }

    /// Parse Windows Defender stdout to extract threat information.
    /// The output format is not perfectly stable, so we do a best-effort parse.
    fn parse_defender_output(stdout: &str, target: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let target_str = target.to_string_lossy().to_string();

        // Try to extract threat names from lines like:
        //   Threat                  : <ThreatName>
        //   File                    : <FilePath>
        let mut current_threat: Option<String> = None;
        let mut current_file: Option<String> = None;

        for line in stdout.lines() {
            let line = line.trim();

            if let Some(threat) = line.strip_prefix("Threat").and_then(|s| {
                let s = s.trim_start_matches([' ', '\t', ':']);
                let s = s.trim_start();
                if !s.is_empty() { Some(s.to_string()) } else { None }
            }) {
                // Flush previous finding if any
                if let Some(t) = current_threat.take() {
                    let file_path = current_file.take().unwrap_or_else(|| target_str.clone());
                    findings.push(build_finding(target_str.clone(), t, file_path));
                }
                current_threat = Some(threat);
            } else if let Some(file) = line.strip_prefix("File").and_then(|s| {
                let s = s.trim_start_matches([' ', '\t', ':']);
                let s = s.trim_start();
                if !s.is_empty() { Some(s.to_string()) } else { None }
            }) {
                current_file = Some(file);
            }
        }

        // Flush last pending finding
        if let Some(t) = current_threat.take() {
            let file_path = current_file.take().unwrap_or_else(|| target_str.clone());
            findings.push(build_finding(target_str.clone(), t, file_path));
        }

        // If nothing was parsed from stdout but exit code indicated a threat,
        // the caller will add a generic finding.
        findings
    }
}

fn build_finding(target_str: String, threat_name: String, file_path: String) -> Finding {
    Finding {
        scanner: "windows-defender".to_string(),
        category: FindingCategory::Malware,
        severity: FindingSeverity::Critical,
        file_path,
        title: threat_name.clone(),
        description: format!("Windows Defender detected a threat: {}", threat_name),
        remediation: Some(
            "The file has been flagged by Windows Defender. \
             Review the threat in Windows Security and quarantine or delete if confirmed malicious."
                .to_string(),
        ),
        reference_url: Some(
            "https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/".to_string(),
        ),
        metadata: serde_json::json!({
            "threat_name": threat_name,
            "scan_target": target_str,
        }),
    }
}

#[async_trait]
impl Scanner for DefenderScanner {
    fn name(&self) -> &str {
        "windows-defender"
    }

    async fn is_available(&self) -> bool {
        config::windows_defender_path().is_some()
    }

    async fn scan(&self, target: &Path) -> Result<ScannerResult> {
        let defender_path = config::windows_defender_path()
            .context("Windows Defender (MpCmdRun.exe) not found")?;

        let output = Command::new(&defender_path)
            .args([
                "-Scan",
                "-ScanType",
                "3", // Custom scan
                "-DisableRemediation",
                "-File",
                &target.to_string_lossy(),
            ])
            .output()
            .await
            .with_context(|| {
                format!("Failed to execute Windows Defender at {}", defender_path.display())
            })?;

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Exit code 2 = threat found
        // Exit code 0 = clean
        // Other codes = error
        if exit_code == 0 {
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: true,
                error: None,
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        }

        if exit_code == 2 {
            let mut findings = Self::parse_defender_output(&stdout, target);

            if findings.is_empty() {
                // Generic finding when we couldn't parse specific threat info
                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Malware,
                    severity: FindingSeverity::Critical,
                    file_path: target.to_string_lossy().to_string(),
                    title: "Threat detected".to_string(),
                    description: format!(
                        "Windows Defender detected a threat in '{}'. \
                         Review Windows Security for details.",
                        target.display()
                    ),
                    remediation: Some(
                        "Open Windows Security → Virus & threat protection → Protection history \
                         to view details and take action."
                            .to_string(),
                    ),
                    reference_url: Some(
                        "https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "exit_code": exit_code,
                        "stdout_excerpt": &stdout[..stdout.len().min(512)],
                    }),
                });
            }

            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: true,
                error: None,
                duration_ms: 0,
                findings,
                version: None,
            });
        }

        // Any other non-zero exit code is an error
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(ScannerResult {
            scanner_name: self.name().to_string(),
            success: false,
            error: Some(format!(
                "Windows Defender exited with code {} — stderr: {}",
                exit_code,
                stderr.trim()
            )),
            duration_ms: 0,
            findings: vec![],
            version: None,
        })
    }

    async fn bootstrap(&self) -> Result<()> {
        // Windows Defender is built-in; no installation needed.
        tracing::info!("Windows Defender is built-in and requires no bootstrap.");
        Ok(())
    }
}

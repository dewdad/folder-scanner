use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;
use tokio::process::Command;
use walkdir::WalkDir;

use crate::config;
use crate::platform;
use crate::scanner::{Finding, FindingCategory, FindingSeverity, Scanner, ScannerResult};

// ---------------------------------------------------------------------------
// NDJSON output struct for `yr scan --output-format ndjson`
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct YrMatch {
    rule: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub struct YaraScanner;

impl YaraScanner {
    pub fn new() -> Self {
        YaraScanner
    }

    /// Collect all .yar / .yara files under a directory
    fn collect_rule_files(rules_dir: &Path) -> Vec<std::path::PathBuf> {
        WalkDir::new(rules_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                let path = e.path();
                matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("yar") | Some("yara")
                )
            })
            .map(|e| e.into_path())
            .collect()
    }

    /// Try scanning with `yr` (YARA-X CLI), return findings or None if yr not available
    async fn scan_with_yr(
        &self,
        rules_dir: &Path,
        target: &Path,
    ) -> Option<Vec<Finding>> {
        if !platform::command_exists("yr") {
            return None;
        }

        let output = Command::new("yr")
            .args([
                "scan",
                "--output-format",
                "ndjson",
                "--recursive",
                &rules_dir.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
            .await
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<YrMatch>(line) {
                Ok(m) => {
                    let matched_path = m
                        .path
                        .clone()
                        .unwrap_or_else(|| target.to_string_lossy().to_string());
                    let tags_str = if m.tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [tags: {}]", m.tags.join(", "))
                    };
                    findings.push(Finding {
                        scanner: self.name().to_string(),
                        category: FindingCategory::SuspiciousPattern,
                        severity: FindingSeverity::High,
                        file_path: matched_path.clone(),
                        title: m.rule.clone(),
                        description: format!(
                            "YARA rule '{}' matched file '{}'{}",
                            m.rule, matched_path, tags_str
                        ),
                        remediation: None,
                        reference_url: None,
                        metadata: serde_json::json!({
                            "rule": m.rule,
                            "namespace": m.namespace,
                            "tags": m.tags,
                        }),
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to parse yr NDJSON line: {} — {}", line, e);
                }
            }
        }

        Some(findings)
    }

    /// Fall back to classic `yara` CLI, scanning each rule file individually
    async fn scan_with_classic_yara(
        &self,
        rule_files: &[std::path::PathBuf],
        target: &Path,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule_file in rule_files {
            let output = match Command::new("yara")
                .args([
                    "-r",
                    &rule_file.to_string_lossy(),
                    &target.to_string_lossy(),
                ])
                .output()
                .await
            {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(
                        "Failed to run yara with rule file {}: {}",
                        rule_file.display(),
                        e
                    );
                    continue;
                }
            };

            let stdout = String::from_utf8_lossy(&output.stdout);

            // Classic yara output: `<rule_name> <file_path>` per line
            for line in stdout.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                let (rule_name, matched_path) = if parts.len() == 2 {
                    (parts[0].to_string(), parts[1].to_string())
                } else {
                    (line.to_string(), target.to_string_lossy().to_string())
                };

                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::SuspiciousPattern,
                    severity: FindingSeverity::High,
                    file_path: matched_path.clone(),
                    title: rule_name.clone(),
                    description: format!(
                        "YARA rule '{}' matched file '{}'",
                        rule_name, matched_path
                    ),
                    remediation: None,
                    reference_url: None,
                    metadata: serde_json::json!({
                        "rule": rule_name,
                        "rule_file": rule_file.to_string_lossy(),
                    }),
                });
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for YaraScanner {
    fn name(&self) -> &str {
        "yara"
    }

    async fn is_available(&self) -> bool {
        let rules_dir = match config::yara_rules_dir() {
            Ok(d) => d,
            Err(_) => return false,
        };

        if !rules_dir.exists() {
            return false;
        }

        // Check if at least one .yar or .yara file exists
        WalkDir::new(&rules_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_type().is_file()
                    && matches!(
                        e.path().extension().and_then(|s| s.to_str()),
                        Some("yar") | Some("yara")
                    )
            })
    }

    async fn scan(&self, target: &Path) -> Result<ScannerResult> {
        let rules_dir = config::yara_rules_dir().context("Failed to determine YARA rules directory")?;

        if !rules_dir.exists() {
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: false,
                error: Some(format!(
                    "YARA rules directory does not exist: {}",
                    rules_dir.display()
                )),
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        }

        let rule_files = Self::collect_rule_files(&rules_dir);

        if rule_files.is_empty() {
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: true,
                error: Some("No .yar or .yara rule files found.".to_string()),
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        }

        // Prefer yr (YARA-X) if available; fall back to classic yara
        let findings = if let Some(yr_findings) = self.scan_with_yr(&rules_dir, target).await {
            yr_findings
        } else if platform::command_exists("yara") {
            self.scan_with_classic_yara(&rule_files, target).await
        } else {
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: false,
                error: Some(
                    "Neither 'yr' (YARA-X) nor 'yara' (classic) CLI was found in PATH. \
                     Please install one to enable YARA scanning."
                        .to_string(),
                ),
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        };

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
        tracing::info!("Bootstrapping YARA scanner: downloading rule archives...");

        let rules_dir = config::yara_rules_dir().context("Failed to determine YARA rules directory")?;
        tokio::fs::create_dir_all(&rules_dir)
            .await
            .context("Failed to create YARA rules directory")?;

        let client = reqwest::Client::builder()
            .user_agent("folder-scanner/0.1")
            .build()
            .context("Failed to build HTTP client")?;

        for (repo_name, url) in config::YARA_RULE_REPOS {
            tracing::info!("Downloading YARA rules from {} ({})", repo_name, url);

            let bytes = match client.get(*url).send().await {
                Ok(resp) => match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("Failed to download YARA rules from {}: {}", url, e);
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to fetch YARA rules from {}: {}", url, e);
                    continue;
                }
            };

            let archive_path = rules_dir.join(format!("{}.tar.gz", repo_name));
            if let Err(e) = tokio::fs::write(&archive_path, &bytes).await {
                tracing::warn!("Failed to write YARA archive for {}: {}", repo_name, e);
                continue;
            }

            let dest_dir = rules_dir.join(repo_name);
            if let Err(e) = tokio::fs::create_dir_all(&dest_dir).await {
                tracing::warn!("Failed to create destination directory for {}: {}", repo_name, e);
                let _ = tokio::fs::remove_file(&archive_path).await;
                continue;
            }

            // Extract using system tar (available on Linux/macOS and Windows 10+)
            let archive_str = archive_path.to_string_lossy().to_string();
            let dest_str = dest_dir.to_string_lossy().to_string();

            let status = Command::new("tar")
                .args(["xzf", &archive_str, "-C", &dest_str, "--strip-components=1"])
                .status()
                .await;

            match status {
                Ok(s) if s.success() => {
                    tracing::info!("Extracted YARA rules for '{}'.", repo_name);
                }
                Ok(s) => {
                    tracing::warn!(
                        "tar extraction failed for '{}' (exit code: {:?})",
                        repo_name,
                        s.code()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to run tar for '{}': {}", repo_name, e);
                }
            }

            let _ = tokio::fs::remove_file(&archive_path).await;
        }

        tracing::info!("YARA rules bootstrap complete.");
        Ok(())
    }
}

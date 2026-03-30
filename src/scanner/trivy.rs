use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

use crate::config;
use crate::platform;
use crate::scanner::{Finding, FindingCategory, FindingSeverity, Scanner, ScannerResult};

// ---------------------------------------------------------------------------
// Trivy JSON output structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyReport {
    #[allow(dead_code)]
    schema_version: Option<u32>,
    #[allow(dead_code)]
    artifact_name: Option<String>,
    #[allow(dead_code)]
    artifact_type: Option<String>,
    #[serde(default)]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    target: String,
    class: Option<String>,
    #[serde(rename = "Type")]
    result_type: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<TrivyVulnerability>,
    #[serde(default)]
    secrets: Vec<TrivySecret>,
    #[serde(default)]
    misconfigurations: Vec<TrivyMisconfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyVulnerability {
    vulnerability_id: String,
    pkg_name: String,
    installed_version: String,
    severity: String,
    fixed_version: Option<String>,
    title: Option<String>,
    description: Option<String>,
    primary_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivySecret {
    rule_id: String,
    category: String,
    severity: String,
    title: String,
    #[serde(rename = "Match")]
    match_field: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyMisconfig {
    #[serde(rename = "ID")]
    id: String,
    title: String,
    description: String,
    severity: String,
    resolution: Option<String>,
}

// ---------------------------------------------------------------------------
// TrivyScanner
// ---------------------------------------------------------------------------

pub struct TrivyScanner;

impl TrivyScanner {
    pub fn new() -> Self {
        TrivyScanner
    }
}

#[async_trait]
impl Scanner for TrivyScanner {
    fn name(&self) -> &str {
        "trivy"
    }

    async fn is_available(&self) -> bool {
        // Check configured binary path first
        if let Ok(path) = config::trivy_binary_path() {
            if path.exists() {
                return true;
            }
        }
        // Fall back to PATH
        platform::command_exists("trivy")
    }

    async fn scan(&self, target: &Path) -> Result<ScannerResult> {
        let trivy_bin = if let Ok(p) = config::trivy_binary_path() {
            if p.exists() {
                p.to_string_lossy().to_string()
            } else {
                "trivy".to_string()
            }
        } else {
            "trivy".to_string()
        };

        let cache_dir = config::trivy_cache_dir().unwrap_or_else(|_| std::path::PathBuf::from(".trivy-cache"));

        let output = Command::new(&trivy_bin)
            .args([
                "fs",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                "--cache-dir",
                &cache_dir.to_string_lossy(),
                "--timeout",
                "10m",
                &target.to_string_lossy(),
            ])
            .output()
            .await
            .with_context(|| format!("Failed to execute trivy binary: {}", trivy_bin))?;

        // Trivy exits 0 (clean) or non-zero (findings / error)
        // Stdout is JSON regardless; stderr may have warnings
        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.trim().is_empty() {
            return Ok(ScannerResult {
                scanner_name: self.name().to_string(),
                success: true,
                error: None,
                duration_ms: 0,
                findings: vec![],
                version: None,
            });
        }

        let report: TrivyReport = serde_json::from_str(&stdout).with_context(|| {
            format!(
                "Failed to parse trivy JSON output (first 512 chars): {}",
                &stdout[..stdout.len().min(512)]
            )
        })?;

        let mut findings = Vec::new();

        for result in &report.results {
            let file_path = result.target.clone();
            let pkg_type = result.result_type.as_deref().unwrap_or("unknown");

            // Vulnerabilities
            for vuln in &result.vulnerabilities {
                let description = vuln
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("{} in {} {}", vuln.vulnerability_id, vuln.pkg_name, vuln.installed_version));

                let remediation = vuln
                    .fixed_version
                    .as_ref()
                    .map(|v| format!("Upgrade {} to version {}", vuln.pkg_name, v));

                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Vulnerability,
                    severity: FindingSeverity::from_str_loose(&vuln.severity),
                    file_path: file_path.clone(),
                    title: vuln.vulnerability_id.clone(),
                    description,
                    remediation,
                    reference_url: vuln.primary_url.clone(),
                    metadata: serde_json::json!({
                        "pkg_name": vuln.pkg_name,
                        "installed_version": vuln.installed_version,
                        "fixed_version": vuln.fixed_version,
                        "pkg_type": pkg_type,
                        "title": vuln.title,
                    }),
                });
            }

            // Secrets
            for secret in &result.secrets {
                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Secret,
                    severity: FindingSeverity::from_str_loose(&secret.severity),
                    file_path: file_path.clone(),
                    title: secret.title.clone(),
                    description: format!(
                        "Secret detected: {} (category: {})",
                        secret.title, secret.category
                    ),
                    remediation: Some("Remove the secret from the file and rotate the credential immediately.".to_string()),
                    reference_url: None,
                    metadata: serde_json::json!({
                        "rule_id": secret.rule_id,
                        "category": secret.category,
                        "match": secret.match_field,
                    }),
                });
            }

            // Misconfigurations
            for misconfig in &result.misconfigurations {
                findings.push(Finding {
                    scanner: self.name().to_string(),
                    category: FindingCategory::Misconfiguration,
                    severity: FindingSeverity::from_str_loose(&misconfig.severity),
                    file_path: file_path.clone(),
                    title: format!("{}: {}", misconfig.id, misconfig.title),
                    description: misconfig.description.clone(),
                    remediation: misconfig.resolution.clone(),
                    reference_url: None,
                    metadata: serde_json::json!({
                        "id": misconfig.id,
                        "class": result.class,
                    }),
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
        tracing::info!("Bootstrapping trivy: fetching latest release info from GitHub...");

        // Fetch latest version from GitHub API
        let client = reqwest::Client::builder()
            .user_agent("folder-scanner/0.1")
            .build()
            .context("Failed to build HTTP client")?;

        let api_url = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            config::TRIVY_GITHUB_OWNER,
            config::TRIVY_GITHUB_REPO
        );

        let release: Value = client
            .get(&api_url)
            .send()
            .await
            .context("Failed to fetch trivy release info")?
            .json()
            .await
            .context("Failed to parse trivy release JSON")?;

        let tag = release["tag_name"]
            .as_str()
            .context("Missing tag_name in GitHub release")?;

        // Strip leading 'v'
        let version = tag.trim_start_matches('v');

        let download_url = platform::trivy_download_url(version)
            .context("Unsupported platform for trivy download")?;

        tracing::info!("Downloading trivy {} from {}", version, download_url);

        let bytes = client
            .get(&download_url)
            .send()
            .await
            .context("Failed to download trivy archive")?
            .bytes()
            .await
            .context("Failed to read trivy archive bytes")?;

        let tools_dir = config::tools_dir().context("Failed to determine tools directory")?;
        tokio::fs::create_dir_all(&tools_dir)
            .await
            .context("Failed to create tools directory")?;

        // Write archive to a temp file
        let archive_ext = if cfg!(target_os = "windows") { "zip" } else { "tar.gz" };
        let archive_path = tools_dir.join(format!("trivy_archive.{}", archive_ext));

        tokio::fs::write(&archive_path, &bytes)
            .await
            .context("Failed to write trivy archive to disk")?;

        // Extract using platform commands
        #[cfg(target_os = "windows")]
        {
            let tools_dir_str = tools_dir.to_string_lossy().to_string();
            let archive_str = archive_path.to_string_lossy().to_string();
            let status = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Expand-Archive -Force -Path '{}' -DestinationPath '{}'",
                        archive_str, tools_dir_str
                    ),
                ])
                .status()
                .await
                .context("Failed to run PowerShell Expand-Archive")?;

            if !status.success() {
                anyhow::bail!("PowerShell Expand-Archive failed");
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let tools_dir_str = tools_dir.to_string_lossy().to_string();
            let archive_str = archive_path.to_string_lossy().to_string();
            let status = Command::new("tar")
                .args(["xzf", &archive_str, "-C", &tools_dir_str])
                .status()
                .await
                .context("Failed to extract trivy archive with tar")?;

            if !status.success() {
                anyhow::bail!("tar extraction of trivy archive failed");
            }
        }

        // Clean up archive
        let _ = tokio::fs::remove_file(&archive_path).await;

        // Make binary executable on Unix
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(bin_path) = config::trivy_binary_path() {
                if bin_path.exists() {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&bin_path)
                        .context("Failed to read trivy binary metadata")?
                        .permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&bin_path, perms)
                        .context("Failed to set trivy binary permissions")?;
                }
            }
        }

        tracing::info!("Trivy {} installed successfully.", version);
        Ok(())
    }
}

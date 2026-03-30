pub mod clamav;
pub mod trivy;
pub mod yara;

#[cfg(target_os = "windows")]
pub mod defender;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Severity levels for findings, ordered from least to most severe
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Unknown => write!(f, "UNKNOWN"),
            FindingSeverity::Low => write!(f, "LOW"),
            FindingSeverity::Medium => write!(f, "MEDIUM"),
            FindingSeverity::High => write!(f, "HIGH"),
            FindingSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl FindingSeverity {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "LOW" => Self::Low,
            "MEDIUM" => Self::Medium,
            "HIGH" => Self::High,
            "CRITICAL" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

/// Category of a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Known vulnerability (CVE)
    Vulnerability,
    /// Malware / virus detection
    Malware,
    /// Suspicious pattern match (YARA)
    SuspiciousPattern,
    /// Exposed secret / credential
    Secret,
    /// Misconfiguration (IaC, Dockerfile, etc.)
    Misconfiguration,
    /// License compliance issue
    License,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::Vulnerability => write!(f, "Vulnerability"),
            FindingCategory::Malware => write!(f, "Malware"),
            FindingCategory::SuspiciousPattern => write!(f, "Suspicious Pattern"),
            FindingCategory::Secret => write!(f, "Secret"),
            FindingCategory::Misconfiguration => write!(f, "Misconfiguration"),
            FindingCategory::License => write!(f, "License"),
        }
    }
}

/// A single finding from any scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which scanner produced this finding
    pub scanner: String,
    /// Category of the finding
    pub category: FindingCategory,
    /// Severity level
    pub severity: FindingSeverity,
    /// File path where the finding was detected
    pub file_path: String,
    /// Short title/identifier (e.g., CVE ID, virus name, YARA rule name)
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Recommendation or fix (if available)
    pub remediation: Option<String>,
    /// URL for more information
    pub reference_url: Option<String>,
    /// Additional metadata (scanner-specific)
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Result from a single scanner engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    /// Name of the scanner engine
    pub scanner_name: String,
    /// Whether the scanner ran successfully
    pub success: bool,
    /// Error message if the scanner failed
    pub error: Option<String>,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Findings from this scanner
    pub findings: Vec<Finding>,
    /// Scanner version info
    pub version: Option<String>,
}

/// Trait that all scanner engines implement
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    /// Human-readable name of this scanner
    fn name(&self) -> &str;

    /// Check if this scanner's tools are available
    async fn is_available(&self) -> bool;

    /// Run the scan on the given path
    async fn scan(&self, target: &Path) -> Result<ScannerResult>;

    /// Attempt to install/bootstrap this scanner's tools
    async fn bootstrap(&self) -> Result<()> {
        Ok(()) // default: no-op
    }
}

/// Run all available scanners in parallel on the given path.
/// Auto-bootstraps missing scanners if possible.
pub async fn run_all_scanners(target: &Path) -> Vec<ScannerResult> {
    let scanners: Vec<Box<dyn Scanner>> = build_scanner_list();
    let mut handles = Vec::new();

    for scanner in scanners {
        let target = target.to_path_buf();
        let handle = tokio::spawn(async move {
            // Check availability, try bootstrap if missing
            if !scanner.is_available().await {
                tracing::info!("{} not found, attempting bootstrap...", scanner.name());
                if let Err(e) = scanner.bootstrap().await {
                    tracing::warn!("Failed to bootstrap {}: {}", scanner.name(), e);
                    return ScannerResult {
                        scanner_name: scanner.name().to_string(),
                        success: false,
                        error: Some(format!("Not available and bootstrap failed: {e}")),
                        duration_ms: 0,
                        findings: vec![],
                        version: None,
                    };
                }
                // Re-check after bootstrap
                if !scanner.is_available().await {
                    return ScannerResult {
                        scanner_name: scanner.name().to_string(),
                        success: false,
                        error: Some("Still not available after bootstrap".to_string()),
                        duration_ms: 0,
                        findings: vec![],
                        version: None,
                    };
                }
            }

            let start = std::time::Instant::now();
            match scanner.scan(&target).await {
                Ok(mut result) => {
                    result.duration_ms = start.elapsed().as_millis() as u64;
                    result
                }
                Err(e) => ScannerResult {
                    scanner_name: scanner.name().to_string(),
                    success: false,
                    error: Some(format!("{e:#}")),
                    duration_ms: start.elapsed().as_millis() as u64,
                    findings: vec![],
                    version: None,
                },
            }
        });
        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::error!("Scanner task panicked: {e}");
            }
        }
    }
    results
}

/// Build the list of all scanner engines for this platform
fn build_scanner_list() -> Vec<Box<dyn Scanner>> {
    let mut scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(trivy::TrivyScanner::new()),
        Box::new(clamav::ClamAvScanner::new()),
        Box::new(yara::YaraScanner::new()),
    ];

    #[cfg(target_os = "windows")]
    {
        scanners.push(Box::new(defender::DefenderScanner::new()));
    }

    scanners
}

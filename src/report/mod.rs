pub mod html;
pub mod json;
pub mod terminal;

use crate::cli::Severity;
use crate::scanner::{FindingSeverity, ScannerResult, Finding};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Unified scan report merging results from all scanner engines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Unique report identifier
    pub id: String,
    /// Path that was scanned
    pub target_path: String,
    /// When the scan was performed
    pub scan_time: DateTime<Local>,
    /// Total scan duration in milliseconds
    pub total_duration_ms: u64,
    /// Minimum severity filter applied
    pub min_severity: String,
    /// Per-scanner results summary
    pub scanner_summaries: Vec<ScannerSummary>,
    /// All findings from all scanners (filtered by severity)
    pub findings: Vec<Finding>,
    /// Aggregate statistics
    pub stats: ScanStats,
}

/// Summary of a single scanner's execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerSummary {
    pub name: String,
    pub success: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub finding_count: usize,
    pub version: Option<String>,
}

/// Aggregate statistics for the entire scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unknown_count: usize,
    pub scanners_run: usize,
    pub scanners_failed: usize,
}

impl ScanReport {
    /// Build a ScanReport from multiple ScannerResults
    pub fn from_scanner_results(
        target: &Path,
        results: Vec<ScannerResult>,
        min_severity: Severity,
    ) -> Self {
        let min_finding_severity = match min_severity {
            Severity::Low => FindingSeverity::Low,
            Severity::Medium => FindingSeverity::Medium,
            Severity::High => FindingSeverity::High,
            Severity::Critical => FindingSeverity::Critical,
        };

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut scanner_summaries: Vec<ScannerSummary> = Vec::new();
        let mut total_duration_ms: u64 = 0;

        for result in &results {
            let filtered: Vec<Finding> = result
                .findings
                .iter()
                .filter(|f| f.severity >= min_finding_severity)
                .cloned()
                .collect();

            scanner_summaries.push(ScannerSummary {
                name: result.scanner_name.clone(),
                success: result.success,
                error: result.error.clone(),
                duration_ms: result.duration_ms,
                finding_count: filtered.len(),
                version: result.version.clone(),
            });

            total_duration_ms = total_duration_ms.max(result.duration_ms); // parallel = max
            all_findings.extend(filtered);
        }

        // Sort findings by severity (critical first)
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let stats = ScanStats {
            total_findings: all_findings.len(),
            critical_count: all_findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Critical)
                .count(),
            high_count: all_findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::High)
                .count(),
            medium_count: all_findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Medium)
                .count(),
            low_count: all_findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Low)
                .count(),
            unknown_count: all_findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Unknown)
                .count(),
            scanners_run: results.len(),
            scanners_failed: results.iter().filter(|r| !r.success).count(),
        };

        ScanReport {
            id: uuid::Uuid::new_v4().to_string(),
            target_path: target.to_string_lossy().to_string(),
            scan_time: Local::now(),
            total_duration_ms,
            min_severity: min_severity.to_string(),
            scanner_summaries,
            findings: all_findings,
            stats,
        }
    }

    /// Count findings by severity
    pub fn count_by_severity(&self, severity: FindingSeverity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }
}

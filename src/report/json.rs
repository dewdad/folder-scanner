use crate::report::ScanReport;
use anyhow::Result;

/// Serialize the scan report to pretty-printed JSON.
/// Returns the JSON string; the caller is responsible for writing it to disk or stdout.
pub fn render(report: &ScanReport) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}

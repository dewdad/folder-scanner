use crate::report::ScanReport;
use crate::scanner::FindingSeverity;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};
use console::style;

/// Render the scan report as a formatted terminal string with color and tables.
/// The caller is responsible for printing the returned string.
pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();

    // ── Section 1: Header ──────────────────────────────────────────────────────
    out.push_str(&render_header(report));
    out.push('\n');

    // ── Section 2: Scanner Summary ────────────────────────────────────────────
    out.push_str(&render_scanner_summary(report));
    out.push('\n');

    // ── Section 3: Findings ───────────────────────────────────────────────────
    out.push_str(&render_findings(report));
    out.push('\n');

    // ── Section 4: Statistics ─────────────────────────────────────────────────
    out.push_str(&render_statistics(report));

    out
}

fn render_header(report: &ScanReport) -> String {
    let mut s = String::new();
    let title = style("╔══ Security Scan Report ══╗").bold().cyan();
    s.push_str(&format!("{}\n", title));
    s.push_str(&format!(
        "  {} {}\n",
        style("Target:").bold(),
        report.target_path
    ));
    s.push_str(&format!(
        "  {} {}\n",
        style("Scanned:").bold(),
        report.scan_time.format("%Y-%m-%d %H:%M:%S %Z")
    ));
    let duration_sec = report.total_duration_ms as f64 / 1000.0;
    s.push_str(&format!(
        "  {} {:.2}s\n",
        style("Duration:").bold(),
        duration_sec
    ));
    s.push_str(&format!(
        "  {} {}\n",
        style("Min Severity:").bold(),
        report.min_severity
    ));
    s
}

fn render_scanner_summary(report: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "{}\n",
        style("Scanner Overview").bold().underlined()
    ));

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Scanner").add_attribute(Attribute::Bold),
            Cell::new("Status").add_attribute(Attribute::Bold),
            Cell::new("Findings").add_attribute(Attribute::Bold),
            Cell::new("Duration").add_attribute(Attribute::Bold),
            Cell::new("Version").add_attribute(Attribute::Bold),
        ]);

    for summary in &report.scanner_summaries {
        let status_cell = if summary.success {
            Cell::new("✓ OK").fg(Color::Green)
        } else {
            Cell::new("✗ FAILED").fg(Color::Red)
        };

        let findings_cell =
            Cell::new(summary.finding_count.to_string()).set_alignment(CellAlignment::Right);

        let duration = format!("{:.2}s", summary.duration_ms as f64 / 1000.0);
        let version = summary.version.as_deref().unwrap_or("-").to_string();

        table.add_row(vec![
            Cell::new(&summary.name),
            status_cell,
            findings_cell,
            Cell::new(duration),
            Cell::new(version),
        ]);
    }

    s.push_str(&format!("{}\n", table));
    s
}

fn render_findings(report: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}\n", style("Findings").bold().underlined()));

    if report.findings.is_empty() {
        s.push_str(&format!(
            "  {}\n",
            style("No findings at or above the minimum severity threshold.").green()
        ));
        return s;
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity").add_attribute(Attribute::Bold),
            Cell::new("Scanner").add_attribute(Attribute::Bold),
            Cell::new("Category").add_attribute(Attribute::Bold),
            Cell::new("File").add_attribute(Attribute::Bold),
            Cell::new("Title").add_attribute(Attribute::Bold),
        ]);

    // Findings arrive pre-sorted by severity (critical first) from ScanReport::from_scanner_results
    for finding in &report.findings {
        let sev_cell = severity_cell(&finding.severity);
        let file_display = truncate_path(&finding.file_path, 40);

        table.add_row(vec![
            sev_cell,
            Cell::new(&finding.scanner),
            Cell::new(finding.category.to_string()),
            Cell::new(file_display),
            Cell::new(&finding.title),
        ]);
    }

    s.push_str(&format!("{}\n", table));
    s
}

fn render_statistics(report: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}\n", style("Statistics").bold().underlined()));

    let stats = &report.stats;

    let total_label = format!("Total Findings: {}", stats.total_findings);
    s.push_str(&format!("  {}\n", style(total_label).bold()));

    let entries = [
        (
            "Critical",
            stats.critical_count,
            Color::Red,
            Attribute::Bold,
        ),
        ("High", stats.high_count, Color::Red, Attribute::NoBold),
        (
            "Medium",
            stats.medium_count,
            Color::Yellow,
            Attribute::NoBold,
        ),
        ("Low", stats.low_count, Color::Blue, Attribute::NoBold),
        ("Unknown", stats.unknown_count, Color::White, Attribute::Dim),
    ];

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity").add_attribute(Attribute::Bold),
            Cell::new("Count").add_attribute(Attribute::Bold),
        ]);

    for (label, count, color, attr) in &entries {
        table.add_row(vec![
            Cell::new(label).fg(*color).add_attribute(*attr),
            Cell::new(count.to_string()).set_alignment(CellAlignment::Right),
        ]);
    }

    s.push_str(&format!("{}\n", table));

    s.push_str(&format!(
        "  {} {} ({} failed)\n",
        style("Scanners:").bold(),
        stats.scanners_run,
        stats.scanners_failed
    ));

    s
}

/// Apply severity-appropriate color to a table cell.
fn severity_cell(severity: &FindingSeverity) -> Cell {
    match severity {
        FindingSeverity::Critical => Cell::new("CRITICAL")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
        FindingSeverity::High => Cell::new("HIGH").fg(Color::Red),
        FindingSeverity::Medium => Cell::new("MEDIUM").fg(Color::Yellow),
        FindingSeverity::Low => Cell::new("LOW").fg(Color::Blue),
        FindingSeverity::Unknown => Cell::new("UNKNOWN").fg(Color::White),
    }
}

/// Shorten a file path to at most `max_len` characters, truncating with "…" prefix.
fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        let start = path.len() - (max_len - 1);
        format!("…{}", &path[start..])
    }
}

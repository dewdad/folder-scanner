use crate::report::ScanReport;
use anyhow::{Context, Result};
use minijinja::{context, value::Value, Environment};

/// The compiled HTML template, embedded at compile time.
const TEMPLATE_SRC: &str = include_str!("../../templates/report.html");

/// Render the scan report as a self-contained HTML page.
/// Returns the rendered HTML string; the caller writes it to disk or serves it.
pub fn render(report: &ScanReport) -> Result<String> {
    let mut env = Environment::new();

    env.add_template("report.html", TEMPLATE_SRC)
        .context("Failed to load HTML report template")?;

    let tmpl = env
        .get_template("report.html")
        .context("Failed to retrieve HTML report template")?;

    // Convert the entire ScanReport (and its sub-fields) to minijinja Values so
    // the template can access every field without a custom serialization layer.
    let report_value = Value::from_serialize(report);
    let findings_value = Value::from_serialize(&report.findings);
    let stats_value = Value::from_serialize(&report.stats);
    let summaries_value = Value::from_serialize(&report.scanner_summaries);

    let html = tmpl
        .render(context! {
            report      => report_value,
            findings    => findings_value,
            stats       => stats_value,
            scanner_summaries => summaries_value,
        })
        .context("Failed to render HTML report template")?;

    Ok(html)
}

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "folder-scanner",
    version,
    about = "Cross-platform security scanner with file manager integration",
    long_about = "Scans files and folders for vulnerabilities, malware, and security issues \
                  using Trivy, ClamAV, YARA rules, and platform-native scanners. \
                  Integrates with your file manager's context menu for one-click scanning."
)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a file or directory for vulnerabilities and malware
    Scan(ScanArgs),

    /// Install context menu integration and download scanner tools
    Install,

    /// Remove context menu integration
    Uninstall,

    /// Update the binary and/or scanner signatures and databases
    Update(UpdateArgs),

    /// Show status of installed scanners and their versions
    Status,
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Path to scan (file or directory)
    pub path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Minimum severity to include in results
    #[arg(short, long, value_enum, default_value_t = Severity::Low)]
    pub severity: Severity,

    /// Write report to file instead of stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Open HTML report in browser after generation
    #[arg(long)]
    pub open: bool,
}

#[derive(clap::Args)]
pub struct UpdateArgs {
    /// Only update signatures and databases, not the binary itself
    #[arg(long)]
    pub sigs_only: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Html,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

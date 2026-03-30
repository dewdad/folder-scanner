mod cli;
mod config;
mod context_menu;
mod platform;
mod report;
mod scanner;
mod updater;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, OutputFormat};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if cli.verbose {
        tracing::info!("Verbose mode enabled");
    }

    match cli.command {
        Commands::Scan(args) => cmd_scan(args).await?,
        Commands::Install => cmd_install().await?,
        Commands::Uninstall => cmd_uninstall().await?,
        Commands::Update(args) => cmd_update(args).await?,
        Commands::Status => cmd_status().await?,
    }

    Ok(())
}

async fn cmd_scan(args: cli::ScanArgs) -> Result<()> {
    let path = args.path.canonicalize().unwrap_or_else(|_| args.path.clone());

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    // Ensure app directories exist
    config::ensure_dirs()?;

    let term = console::Term::stderr();
    term.write_line(&format!(
        "{} Scanning {}...",
        console::style(">>>").cyan().bold(),
        console::style(path.display()).yellow()
    ))?;

    // Run all scanners in parallel
    let results = scanner::run_all_scanners(&path).await;

    // Build unified report
    let scan_report = report::ScanReport::from_scanner_results(&path, results, args.severity);

    // Output report in requested format
    match args.format {
        OutputFormat::Text => {
            let rendered = report::terminal::render(&scan_report);
            if let Some(output_path) = &args.output {
                // Strip ANSI for file output
                let stripped = console::strip_ansi_codes(&rendered);
                std::fs::write(output_path, stripped.as_ref())?;
                term.write_line(&format!(
                    "{} Report written to {}",
                    console::style(">>>").green().bold(),
                    output_path.display()
                ))?;
            } else {
                println!("{rendered}");
            }
        }
        OutputFormat::Json => {
            let json = report::json::render(&scan_report)?;
            if let Some(output_path) = &args.output {
                std::fs::write(output_path, &json)?;
            } else {
                println!("{json}");
            }
        }
        OutputFormat::Html => {
            let html = report::html::render(&scan_report)?;
            let output_path = args.output.unwrap_or_else(|| {
                config::reports_dir()
                    .unwrap_or_else(|_| std::env::temp_dir())
                    .join(format!(
                        "scan-report-{}.html",
                        chrono::Local::now().format("%Y%m%d-%H%M%S")
                    ))
            });
            std::fs::write(&output_path, &html)?;
            term.write_line(&format!(
                "{} HTML report written to {}",
                console::style(">>>").green().bold(),
                output_path.display()
            ))?;
            if args.open {
                open::that(&output_path)?;
            }
        }
    }

    // Summary line
    let total_findings = scan_report.findings.len();
    let critical = scan_report.count_by_severity(scanner::FindingSeverity::Critical);
    let high = scan_report.count_by_severity(scanner::FindingSeverity::High);

    if total_findings == 0 {
        term.write_line(&format!(
            "\n{} No issues found!",
            console::style("✓").green().bold()
        ))?;
    } else {
        term.write_line(&format!(
            "\n{} Found {} issue(s): {} critical, {} high",
            console::style("!").red().bold(),
            total_findings,
            critical,
            high,
        ))?;
    }

    Ok(())
}

async fn cmd_install() -> Result<()> {
    config::ensure_dirs()?;

    let term = console::Term::stderr();
    term.write_line(&format!(
        "{} Installing folder-scanner...",
        console::style(">>>").cyan().bold()
    ))?;

    // Step 1: Bootstrap scanner tools
    term.write_line("  Downloading scanner tools...")?;
    updater::bootstrap_all().await?;

    // Step 2: Register context menus
    term.write_line("  Registering context menu...")?;
    context_menu::install()?;

    term.write_line(&format!(
        "\n{} Installation complete! Right-click any file or folder to scan.",
        console::style("✓").green().bold()
    ))?;

    Ok(())
}

async fn cmd_uninstall() -> Result<()> {
    let term = console::Term::stderr();

    context_menu::uninstall()?;

    term.write_line(&format!(
        "{} Context menu entries removed.",
        console::style("✓").green().bold()
    ))?;

    Ok(())
}

async fn cmd_update(args: cli::UpdateArgs) -> Result<()> {
    config::ensure_dirs()?;

    let term = console::Term::stderr();
    term.write_line(&format!(
        "{} Updating...",
        console::style(">>>").cyan().bold()
    ))?;

    if !args.sigs_only {
        term.write_line("  Checking for binary updates...")?;
        updater::update_self().await?;
    }

    term.write_line("  Updating scanner databases and signatures...")?;
    updater::update_signatures().await?;

    term.write_line(&format!(
        "\n{} All updates complete.",
        console::style("✓").green().bold()
    ))?;

    Ok(())
}

async fn cmd_status() -> Result<()> {
    let term = console::Term::stderr();
    term.write_line(&format!(
        "{} folder-scanner v{}",
        console::style(">>>").cyan().bold(),
        env!("CARGO_PKG_VERSION")
    ))?;
    term.write_line("")?;

    // Check each scanner
    let scanners: Vec<Box<dyn scanner::Scanner>> = vec![
        Box::new(scanner::trivy::TrivyScanner::new()),
        Box::new(scanner::clamav::ClamAvScanner::new()),
        Box::new(scanner::yara::YaraScanner::new()),
    ];

    #[cfg(target_os = "windows")]
    let scanners = {
        let mut s = scanners;
        s.push(Box::new(scanner::defender::DefenderScanner::new()));
        s
    };

    for s in &scanners {
        let available = s.is_available().await;
        let icon = if available {
            console::style("✓").green()
        } else {
            console::style("✗").red()
        };
        term.write_line(&format!("  {icon} {}", s.name()))?;
    }

    // Check context menu registration
    term.write_line("")?;
    let registered = context_menu::is_registered();
    let icon = if registered {
        console::style("✓").green()
    } else {
        console::style("✗").red()
    };
    term.write_line(&format!("  {icon} Context menu integration"))?;

    Ok(())
}

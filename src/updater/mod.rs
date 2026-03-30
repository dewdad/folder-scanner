pub mod download;

use crate::config;
use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;

// ── Public API ────────────────────────────────────────────────────────────────

/// Download / install Trivy binary + YARA rules, and check for ClamAV.
/// Safe to call on a fresh installation; all operations are idempotent.
pub async fn bootstrap_all() -> Result<()> {
    println!("Bootstrapping scanner tools…");

    // Ensure the required directories exist before writing anything into them.
    config::ensure_dirs().context("Failed to create application directories")?;

    // Run the three bootstrap tasks; continue even if one fails so the user
    // gets as much set up as possible.
    let trivy_result = bootstrap_trivy().await;
    let yara_result = bootstrap_yara().await;
    let clam_result = check_clamav().await;

    trivy_result.context("Trivy bootstrap failed")?;
    yara_result.context("YARA rules bootstrap failed")?;
    clam_result.context("ClamAV check failed")?;

    println!("Bootstrap complete.");
    Ok(())
}

/// Self-update the binary from GitHub Releases using the `self_update` crate.
pub async fn update_self() -> Result<()> {
    println!("Checking for binary update…");

    // self_update performs blocking I/O, so run it on the blocking thread pool.
    tokio::task::spawn_blocking(|| {
        let status = self_update::backends::github::Update::configure()
            .repo_owner(config::GITHUB_OWNER)
            .repo_name(config::GITHUB_REPO)
            .bin_name(env!("CARGO_PKG_NAME"))
            .current_version(self_update::cargo_crate_version!())
            .show_download_progress(true)
            .build()
            .context("Failed to configure self-updater")?
            .update()
            .context("Self-update failed")?;

        if status.updated() {
            println!("Updated to version {}.", status.version());
        } else {
            println!("Already up to date ({}).", status.version());
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Self-update task panicked")??;

    Ok(())
}

/// Update all signature databases: Trivy vulnerability DB, ClamAV signatures,
/// and re-download YARA rule archives.
pub async fn update_signatures() -> Result<()> {
    println!("Updating signature databases…");

    let trivy_result = update_trivy_db().await;
    let clam_result = update_clamav_db().await;
    let yara_result = bootstrap_yara().await; // re-download rule archives

    trivy_result.context("Trivy DB update failed")?;
    clam_result.context("ClamAV DB update failed")?;
    yara_result.context("YARA rules update failed")?;

    println!("Signature update complete.");
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Download the latest Trivy binary from GitHub Releases and install it to
/// the application tools directory.
async fn bootstrap_trivy() -> Result<()> {
    let tools_dir = config::tools_dir().context("Could not resolve tools directory")?;
    let trivy_path = config::trivy_binary_path().context("Could not resolve Trivy binary path")?;

    if trivy_path.exists() {
        println!("Trivy already installed at {}", trivy_path.display());
        return Ok(());
    }

    println!("Downloading Trivy…");

    let version = download::get_github_latest_release(
        config::TRIVY_GITHUB_OWNER,
        config::TRIVY_GITHUB_REPO,
    )
    .await
    .context("Failed to fetch latest Trivy version")?;

    // Strip leading 'v' for use inside asset names.
    let ver_bare = version.trim_start_matches('v');

    let (archive_name, is_tar) = trivy_asset_name(ver_bare);
    let download_url = format!(
        "https://github.com/{}/{}/releases/download/{}/{}",
        config::TRIVY_GITHUB_OWNER,
        config::TRIVY_GITHUB_REPO,
        version,
        archive_name
    );

    let archive_path = tools_dir.join(&archive_name);
    download::download_file(&download_url, &archive_path)
        .await
        .context("Failed to download Trivy archive")?;

    if is_tar {
        download::extract_tar_gz(&archive_path, &tools_dir)
            .context("Failed to extract Trivy tar.gz")?;
    } else {
        download::extract_zip(&archive_path, &tools_dir)
            .context("Failed to extract Trivy zip")?;
    }

    // Clean up the archive after extraction.
    let _ = std::fs::remove_file(&archive_path);

    // Make the binary executable on Unix-like platforms.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&trivy_path)
            .context("Trivy binary not found after extraction")?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&trivy_path, perms)
            .context("Failed to set executable permission on Trivy binary")?;
    }

    println!("Trivy {} installed at {}", version, trivy_path.display());
    Ok(())
}

/// Download YARA rule archives to the yara-rules directory.
async fn bootstrap_yara() -> Result<()> {
    let yara_dir = config::yara_rules_dir().context("Could not resolve YARA rules directory")?;

    for (name, url) in config::YARA_RULE_REPOS {
        println!("Downloading YARA rules: {name}…");

        let archive_name = format!("{name}.tar.gz");
        let archive_path = yara_dir.join(&archive_name);
        let dest_dir = yara_dir.join(name);

        download::download_file(url, &archive_path)
            .await
            .with_context(|| format!("Failed to download YARA rule archive: {name}"))?;

        std::fs::create_dir_all(&dest_dir)
            .with_context(|| format!("Failed to create YARA rules directory: {}", dest_dir.display()))?;

        download::extract_tar_gz(&archive_path, &dest_dir)
            .with_context(|| format!("Failed to extract YARA rules: {name}"))?;

        let _ = std::fs::remove_file(&archive_path);
        println!("YARA rules '{name}' installed to {}", dest_dir.display());
    }

    Ok(())
}

/// Check if ClamAV is installed and print installation guidance if not.
async fn check_clamav() -> Result<()> {
    let clamscan = config::clamscan_binary_path();

    // A quick availability check — try running `clamscan --version`.
    let available = Command::new(&clamscan)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if available {
        println!("ClamAV is installed.");
    } else {
        eprintln!("ClamAV is not installed or not found in PATH.");
        eprintln!("To install ClamAV:");

        #[cfg(target_os = "windows")]
        eprintln!("  Download the installer from https://www.clamav.net/downloads and run it.");

        #[cfg(target_os = "macos")]
        eprintln!("  Run: brew install clamav");

        #[cfg(target_os = "linux")]
        eprintln!("  Run: sudo apt-get install clamav  (Debian/Ubuntu)");
        #[cfg(target_os = "linux")]
        eprintln!("       sudo dnf install clamav       (Fedora/RHEL)");
    }

    Ok(())
}

/// Run `trivy image --download-db-only` to refresh the vulnerability database.
async fn update_trivy_db() -> Result<()> {
    let trivy = config::trivy_binary_path().context("Could not resolve Trivy binary path")?;
    if !trivy.exists() {
        println!("Trivy is not installed; skipping DB update.");
        return Ok(());
    }

    let cache_dir = config::trivy_cache_dir().context("Could not resolve Trivy cache directory")?;

    println!("Updating Trivy vulnerability database…");

    let status = Command::new(&trivy)
        .args([
            "image",
            "--download-db-only",
            "--cache-dir",
            cache_dir.to_string_lossy().as_ref(),
        ])
        .status()
        .await
        .context("Failed to spawn Trivy DB update process")?;

    if !status.success() {
        anyhow::bail!("Trivy DB update exited with status: {}", status);
    }

    println!("Trivy DB updated successfully.");
    Ok(())
}

/// Run `freshclam` to update the ClamAV virus signatures.
/// Silently skips if freshclam is not available.
async fn update_clamav_db() -> Result<()> {
    let freshclam = config::freshclam_binary_path();

    let available = Command::new(&freshclam)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if !available {
        println!("freshclam not found; skipping ClamAV DB update.");
        return Ok(());
    }

    println!("Updating ClamAV virus definitions…");

    let status = Command::new(&freshclam)
        .status()
        .await
        .context("Failed to spawn freshclam process")?;

    if !status.success() {
        // freshclam may return a non-zero exit code when definitions are already up to date
        // on some distributions, so we warn rather than hard-fail.
        eprintln!(
            "freshclam exited with status {} — definitions may already be current.",
            status
        );
    } else {
        println!("ClamAV definitions updated successfully.");
    }

    Ok(())
}

/// Returns the platform-specific Trivy release asset name and whether it is a
/// tar.gz archive (true) or a zip archive (false).
fn trivy_asset_name(ver: &str) -> (String, bool) {
    // Trivy release asset naming convention (as of v0.50+):
    //   trivy_{version}_{OS}-{Arch}.tar.gz  (Linux / macOS)
    //   trivy_{version}_windows-64bit.zip   (Windows)
    let (os, arch, ext, is_tar) = if cfg!(target_os = "windows") {
        ("windows", "64bit", "zip", false)
    } else if cfg!(target_os = "macos") {
        let arch = if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else {
            "64bit"
        };
        ("macOS", arch, "tar.gz", true)
    } else {
        // Linux
        let arch = if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else {
            "64bit"
        };
        ("Linux", arch, "tar.gz", true)
    };

    (format!("trivy_{ver}_{os}-{arch}.{ext}"), is_tar)
}

use anyhow::{Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use tokio::io::AsyncWriteExt;

// ── HTTP Download ─────────────────────────────────────────────────────────────

/// Download a file from `url` to `dest`, showing an `indicatif` progress bar.
///
/// The destination file is created (or overwritten) atomically: data is first
/// written to a temporary file in the same directory, then renamed into place.
pub async fn download_file(url: &str, dest: &Path) -> Result<()> {
    let client = build_client()?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("HTTP request failed for {url}"))?
        .error_for_status()
        .with_context(|| format!("Server returned error for {url}"))?;

    let total_bytes = response.content_length();

    let pb = ProgressBar::new(total_bytes.unwrap_or(0));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-"),
    );
    pb.set_message(format!(
        "Downloading {}",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
    ));

    // Write to a sibling temp file first to avoid leaving a partial download.
    let tmp_path = dest.with_extension("tmp");
    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("Failed to create temporary file: {}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.with_context(|| format!("Failed to read response chunk from {url}"))?;
        file.write_all(&bytes)
            .await
            .with_context(|| format!("Failed to write to {}", tmp_path.display()))?;
        pb.inc(bytes.len() as u64);
    }

    file.flush()
        .await
        .with_context(|| format!("Failed to flush {}", tmp_path.display()))?;
    drop(file);

    pb.finish_with_message(format!(
        "Downloaded {}",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
    ));

    // Atomically rename into the final location.
    tokio::fs::rename(&tmp_path, dest)
        .await
        .with_context(|| {
            format!(
                "Failed to rename {} to {}",
                tmp_path.display(),
                dest.display()
            )
        })?;

    Ok(())
}

// ── GitHub Releases API ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

/// Query the GitHub Releases API and return the latest release tag (e.g. `"v0.51.0"`).
pub async fn get_github_latest_release(owner: &str, repo: &str) -> Result<String> {
    let client = build_client()?;

    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");

    let release: GithubRelease = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("Failed to query GitHub releases API for {owner}/{repo}"))?
        .error_for_status()
        .with_context(|| format!("GitHub API returned an error for {owner}/{repo}"))?
        .json()
        .await
        .context("Failed to deserialize GitHub releases API response")?;

    Ok(release.tag_name)
}

// ── Archive Extraction ────────────────────────────────────────────────────────

/// Extract a `.tar.gz` archive at `archive` into the directory `dest`.
///
/// Delegates to the system `tar` command (available on all supported platforms:
/// Windows 10 1803+, macOS, and Linux).
pub fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("Failed to create extraction directory: {}", dest.display()))?;

    let status = std::process::Command::new("tar")
        .args([
            "-xzf",
            archive.to_string_lossy().as_ref(),
            "-C",
            dest.to_string_lossy().as_ref(),
            "--strip-components=1", // flatten the top-level directory inside the archive
        ])
        .status()
        .context("Failed to spawn tar process")?;

    if !status.success() {
        anyhow::bail!(
            "tar exited with status {} while extracting {}",
            status,
            archive.display()
        );
    }

    Ok(())
}

/// Extract a `.zip` archive at `archive` into the directory `dest`.
///
/// On Windows, uses PowerShell's `Expand-Archive`.
/// On Unix, uses the `unzip` command-line tool.
pub fn extract_zip(archive: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("Failed to create extraction directory: {}", dest.display()))?;

    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
                    archive.display(),
                    dest.display()
                ),
            ])
            .status()
            .context("Failed to spawn PowerShell for zip extraction")?;

        if !status.success() {
            anyhow::bail!(
                "PowerShell Expand-Archive exited with status {} for {}",
                status,
                archive.display()
            );
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let status = std::process::Command::new("unzip")
            .args([
                "-o",
                archive.to_string_lossy().as_ref(),
                "-d",
                dest.to_string_lossy().as_ref(),
            ])
            .status()
            .context("Failed to spawn unzip process")?;

        if !status.success() {
            anyhow::bail!(
                "unzip exited with status {} while extracting {}",
                status,
                archive.display()
            );
        }
    }

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Construct a shared `reqwest::Client` with a descriptive User-Agent.
fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("Failed to build HTTP client")
}

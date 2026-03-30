//! Linux context menu integration for six popular file managers.
//!
//! Uses `crate::platform::detect_file_managers()` to discover which file
//! managers are present and installs the appropriate integration for each.
//!
//! Supported file managers:
//!   1. Nautilus (GNOME)  — script in ~/.local/share/nautilus/scripts/
//!   2. Dolphin (KDE)     — .desktop in ~/.local/share/kio/servicemenus/
//!   3. Thunar (XFCE)     — action block in ~/.config/Thunar/uca.xml
//!   4. Nemo (Cinnamon)   — .nemo_action in ~/.local/share/nemo/actions/
//!   5. PCManFM (LXDE/Qt) — .desktop in ~/.local/share/file-manager/actions/
//!   6. Caja (MATE)       — script in ~/.config/caja/scripts/

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::platform::detect_file_managers;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn data_dir() -> Result<PathBuf> {
    dirs::data_local_dir().context("Could not determine local data directory (~/.local/share)")
}

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir().context("Could not determine config directory (~/.config)")
}

// ---------------------------------------------------------------------------
// Nautilus
// ---------------------------------------------------------------------------

fn nautilus_script_path() -> Result<PathBuf> {
    Ok(data_dir()?
        .join("nautilus")
        .join("scripts")
        .join("Scan with FolderScanner"))
}

fn nautilus_script_content(exe: &str) -> String {
    format!(
        "#!/usr/bin/env bash\n\
         # Folder Scanner — Nautilus context menu script\n\
         IFS=$'\\n'\n\
         for f in $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS; do\n\
         \t'{}' scan \"$f\"\n\
         done\n",
        exe.replace('\'', "'\\''")
    )
}

fn install_nautilus(exe: &str) -> Result<()> {
    let path = nautilus_script_path()?;
    ensure_parent(&path)?;
    fs::write(&path, nautilus_script_content(exe))
        .with_context(|| format!("Failed to write Nautilus script: {}", path.display()))?;
    set_executable(&path)?;
    Ok(())
}

fn uninstall_nautilus() -> Result<()> {
    remove_if_exists(&nautilus_script_path()?)
}

fn is_registered_nautilus() -> bool {
    nautilus_script_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Dolphin (KDE)
// ---------------------------------------------------------------------------

fn dolphin_desktop_path() -> Result<PathBuf> {
    Ok(data_dir()?
        .join("kio")
        .join("servicemenus")
        .join("folder-scanner.desktop"))
}

fn dolphin_desktop_content(exe: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Service\n\
         ServiceTypes=KonqPopupMenu/Plugin\n\
         MimeType=all/all;inode/directory;\n\
         Actions=FolderScannerScan;\n\
         \n\
         [Desktop Action FolderScannerScan]\n\
         Name=Scan with FolderScanner\n\
         Icon=system-search\n\
         Exec={} scan %F\n",
        exe
    )
}

fn install_dolphin(exe: &str) -> Result<()> {
    let path = dolphin_desktop_path()?;
    ensure_parent(&path)?;
    fs::write(&path, dolphin_desktop_content(exe))
        .with_context(|| format!("Failed to write Dolphin service menu: {}", path.display()))?;
    // KDE requires service menu .desktop files to be executable.
    set_executable(&path)?;
    Ok(())
}

fn uninstall_dolphin() -> Result<()> {
    remove_if_exists(&dolphin_desktop_path()?)
}

fn is_registered_dolphin() -> bool {
    dolphin_desktop_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Thunar (XFCE)
// ---------------------------------------------------------------------------

const THUNAR_ACTION_ID: &str = "folder-scanner-scan-1";

fn thunar_uca_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("Thunar").join("uca.xml"))
}

fn thunar_action_block(exe: &str) -> String {
    format!(
        "\t<action>\n\
         \t\t<icon>system-search</icon>\n\
         \t\t<name>Scan with FolderScanner</name>\n\
         \t\t<unique-id>{}</unique-id>\n\
         \t\t<command>{} scan %F</command>\n\
         \t\t<description>Scan selected files/folders with FolderScanner</description>\n\
         \t\t<range></range>\n\
         \t\t<patterns>*</patterns>\n\
         \t\t<startup-notify/>\n\
         \t\t<audio-files/>\n\
         \t\t<image-files/>\n\
         \t\t<other-files/>\n\
         \t\t<text-files/>\n\
         \t\t<video-files/>\n\
         \t\t<directories/>\n\
         \t</action>\n",
        THUNAR_ACTION_ID, exe
    )
}

fn install_thunar(exe: &str) -> Result<()> {
    let path = thunar_uca_path()?;
    ensure_parent(&path)?;

    if path.exists() {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read: {}", path.display()))?;

        // Already registered — do nothing.
        if contents.contains(THUNAR_ACTION_ID) {
            return Ok(());
        }

        // Insert our action just before the closing </actions> tag.
        let new_contents = if let Some(pos) = contents.rfind("</actions>") {
            let block = thunar_action_block(exe);
            format!("{}{}{}", &contents[..pos], block, &contents[pos..])
        } else {
            // File exists but has no </actions>; replace wholesale.
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n{}</actions>\n",
                thunar_action_block(exe)
            )
        };

        fs::write(&path, new_contents)
            .with_context(|| format!("Failed to write: {}", path.display()))?;
    } else {
        // File does not exist — create it from scratch.
        let contents = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n{}</actions>\n",
            thunar_action_block(exe)
        );
        fs::write(&path, contents)
            .with_context(|| format!("Failed to create: {}", path.display()))?;
    }

    Ok(())
}

fn uninstall_thunar() -> Result<()> {
    let path = thunar_uca_path()?;
    if !path.exists() {
        return Ok(());
    }

    let contents =
        fs::read_to_string(&path).with_context(|| format!("Failed to read: {}", path.display()))?;

    if !contents.contains(THUNAR_ACTION_ID) {
        return Ok(());
    }

    // Remove the <action>...</action> block that contains our unique-id.
    let new_contents = remove_thunar_action_block(&contents);
    fs::write(&path, new_contents)
        .with_context(|| format!("Failed to write: {}", path.display()))?;

    Ok(())
}

/// Remove the `<action>…</action>` block that contains `THUNAR_ACTION_ID`.
fn remove_thunar_action_block(xml: &str) -> String {
    // Find the opening <action> that precedes our unique-id.
    let id_pos = match xml.find(THUNAR_ACTION_ID) {
        Some(p) => p,
        None => return xml.to_owned(),
    };

    // Walk backwards to find the start of the enclosing <action> tag.
    let before = &xml[..id_pos];
    let action_start = match before.rfind("<action>") {
        Some(p) => p,
        None => return xml.to_owned(),
    };

    // Find the matching </action> after our id position.
    let after_id = &xml[id_pos..];
    let end_tag = "</action>";
    let rel_end = match after_id.find(end_tag) {
        Some(p) => p,
        None => return xml.to_owned(),
    };
    let action_end = id_pos + rel_end + end_tag.len();

    // Also consume a trailing newline if present.
    let action_end = if xml.as_bytes().get(action_end) == Some(&b'\n') {
        action_end + 1
    } else {
        action_end
    };

    format!("{}{}", &xml[..action_start], &xml[action_end..])
}

fn is_registered_thunar() -> bool {
    thunar_uca_path()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .map(|s| s.contains(THUNAR_ACTION_ID))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Nemo (Cinnamon)
// ---------------------------------------------------------------------------

fn nemo_action_path() -> Result<PathBuf> {
    Ok(data_dir()?
        .join("nemo")
        .join("actions")
        .join("folder-scanner.nemo_action"))
}

fn nemo_action_content(exe: &str) -> String {
    format!(
        "[Nemo Action]\n\
         Active=true\n\
         Name=Scan with FolderScanner\n\
         Comment=Scan selected files/folders with FolderScanner\n\
         Exec={} scan %F\n\
         Icon-Name=system-search\n\
         Selection=any\n\
         Extensions=any;\n",
        exe
    )
}

fn install_nemo(exe: &str) -> Result<()> {
    let path = nemo_action_path()?;
    ensure_parent(&path)?;
    fs::write(&path, nemo_action_content(exe))
        .with_context(|| format!("Failed to write Nemo action: {}", path.display()))?;
    Ok(())
}

fn uninstall_nemo() -> Result<()> {
    remove_if_exists(&nemo_action_path()?)
}

fn is_registered_nemo() -> bool {
    nemo_action_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// PCManFM (LXDE / PCManFM-Qt)
// ---------------------------------------------------------------------------

fn pcmanfm_desktop_path() -> Result<PathBuf> {
    Ok(data_dir()?
        .join("file-manager")
        .join("actions")
        .join("folder-scanner.desktop"))
}

fn pcmanfm_desktop_content(exe: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Action\n\
         Name=Scan with FolderScanner\n\
         Icon=system-search\n\
         Profiles=profile-zero;\n\
         \n\
         [X-Action-Profile profile-zero]\n\
         MimeTypes=all/all;\n\
         Exec={} scan %F\n\
         Name=Default Profile\n",
        exe
    )
}

fn install_pcmanfm(exe: &str) -> Result<()> {
    let path = pcmanfm_desktop_path()?;
    ensure_parent(&path)?;
    fs::write(&path, pcmanfm_desktop_content(exe))
        .with_context(|| format!("Failed to write PCManFM action: {}", path.display()))?;
    Ok(())
}

fn uninstall_pcmanfm() -> Result<()> {
    remove_if_exists(&pcmanfm_desktop_path()?)
}

fn is_registered_pcmanfm() -> bool {
    pcmanfm_desktop_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Caja (MATE)
// ---------------------------------------------------------------------------

fn caja_script_path() -> Result<PathBuf> {
    Ok(config_dir()?
        .join("caja")
        .join("scripts")
        .join("Scan with FolderScanner"))
}

fn caja_script_content(exe: &str) -> String {
    format!(
        "#!/usr/bin/env bash\n\
         # Folder Scanner — Caja context menu script\n\
         IFS=$'\\n'\n\
         for f in $CAJA_SCRIPT_SELECTED_FILE_PATHS; do\n\
         \t'{}' scan \"$f\"\n\
         done\n",
        exe.replace('\'', "'\\''")
    )
}

fn install_caja(exe: &str) -> Result<()> {
    let path = caja_script_path()?;
    ensure_parent(&path)?;
    fs::write(&path, caja_script_content(exe))
        .with_context(|| format!("Failed to write Caja script: {}", path.display()))?;
    set_executable(&path)?;
    Ok(())
}

fn uninstall_caja() -> Result<()> {
    remove_if_exists(&caja_script_path()?)
}

fn is_registered_caja() -> bool {
    caja_script_path().map(|p| p.exists()).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install context menu entries for all detected file managers.
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("Failed to determine current executable path")?;
    let exe_str = exe
        .to_str()
        .context("Executable path contains non-UTF-8 characters")?;

    let managers = detect_file_managers();

    if managers.nautilus {
        install_nautilus(exe_str)?;
    }
    if managers.dolphin {
        install_dolphin(exe_str)?;
    }
    if managers.thunar {
        install_thunar(exe_str)?;
    }
    if managers.nemo {
        install_nemo(exe_str)?;
    }
    if managers.pcmanfm {
        install_pcmanfm(exe_str)?;
    }
    if managers.caja {
        install_caja(exe_str)?;
    }

    Ok(())
}

/// Remove context menu entries for all file managers (safe if already absent).
pub fn uninstall() -> Result<()> {
    uninstall_nautilus()?;
    uninstall_dolphin()?;
    uninstall_thunar()?;
    uninstall_nemo()?;
    uninstall_pcmanfm()?;
    uninstall_caja()?;
    Ok(())
}

/// Return `true` if any file manager integration file exists.
pub fn is_registered() -> bool {
    is_registered_nautilus()
        || is_registered_dolphin()
        || is_registered_thunar()
        || is_registered_nemo()
        || is_registered_pcmanfm()
        || is_registered_caja()
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

/// Create parent directories for a file path if they don't already exist.
fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    Ok(())
}

/// Set the executable bit (chmod 755) on a file.
fn set_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for: {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;
    Ok(())
}

/// Remove a file if it exists; succeed silently if it does not.
fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to remove: {}", path.display())),
    }
}

//! Windows context menu registration via the registry.
//!
//! Registers "Scan with FolderScanner" entries under HKEY_CURRENT_USER\Software\Classes
//! for three locations:
//!   - `*\shell\FolderScanner`          — all files
//!   - `Directory\shell\FolderScanner`  — directories (right-click on folder)
//!   - `Directory\Background\shell\FolderScanner` — directory background
//!
//! Uses the `winreg` crate for registry I/O and `windows-sys` for the
//! SHChangeNotify shell broadcast that makes Explorer pick up the changes
//! without requiring a logoff/reboot.

use anyhow::{Context, Result};
use winreg::{
    enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE},
    RegKey,
};

/// Registry root under HKCU\Software\Classes where we write our keys.
const CLASSES_ROOT: &str = "Software\\Classes";

/// The shell sub-key name used for all three registration points.
const SHELL_KEY_NAME: &str = "FolderScanner";

/// Human-readable label shown in the context menu.
const MENU_LABEL: &str = "Scan with FolderScanner";

/// The three parent paths (relative to HKCU\Software\Classes) where we register.
const SHELL_PARENTS: &[&str] = &[
    r"*\shell",
    r"Directory\shell",
    r"Directory\Background\shell",
];

/// Register all three context menu entries.
///
/// Creates the following key structure for each parent:
/// ```text
/// HKCU\Software\Classes\<parent>\FolderScanner
///     (Default) = "Scan with FolderScanner"
///     Icon      = "<exe>,0"
///   \command
///     (Default) = '"<exe>" scan "%1"'   (or "%V" for Directory\Background)
/// ```
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("Failed to determine current executable path")?;
    let exe_str = exe
        .to_str()
        .context("Executable path contains non-UTF-8 characters")?;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = hkcu
        .open_subkey_with_flags(CLASSES_ROOT, KEY_READ | KEY_WRITE)
        .context("Failed to open HKCU\\Software\\Classes")?;

    for parent in SHELL_PARENTS {
        // Determine the command argument placeholder.
        // Directory\Background uses %V (the folder path); everything else uses %1.
        let arg_placeholder = if *parent == r"Directory\Background\shell" {
            "%V"
        } else {
            "%1"
        };

        let shell_subkey = format!("{}\\{}", parent, SHELL_KEY_NAME);
        let command_subkey = format!("{}\\command", shell_subkey);

        // Create (or open) the verb key and set label + icon.
        let (verb_key, _) = classes
            .create_subkey_with_flags(&shell_subkey, KEY_READ | KEY_WRITE)
            .with_context(|| format!("Failed to create registry key: {}", shell_subkey))?;
        verb_key
            .set_value("", &MENU_LABEL)
            .with_context(|| format!("Failed to set default value on: {}", shell_subkey))?;
        let icon_value = format!("{},0", exe_str);
        verb_key
            .set_value("Icon", &icon_value)
            .with_context(|| format!("Failed to set Icon value on: {}", shell_subkey))?;

        // Create (or open) the command key and set the invocation string.
        let (cmd_key, _) = classes
            .create_subkey_with_flags(&command_subkey, KEY_READ | KEY_WRITE)
            .with_context(|| format!("Failed to create registry key: {}", command_subkey))?;
        let cmd_value = format!("\"{}\" scan \"{}\"", exe_str, arg_placeholder);
        cmd_key
            .set_value("", &cmd_value)
            .with_context(|| format!("Failed to set command value on: {}", command_subkey))?;
    }

    // Notify the shell so Explorer picks up the new association immediately.
    notify_shell();

    Ok(())
}

/// Remove all three context menu entries from the registry.
///
/// Missing keys are silently ignored so that partial uninstall or
/// repeated calls are both safe.
pub fn uninstall() -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = hkcu
        .open_subkey_with_flags(CLASSES_ROOT, KEY_READ | KEY_WRITE)
        .context("Failed to open HKCU\\Software\\Classes")?;

    for parent in SHELL_PARENTS {
        let shell_subkey = format!("{}\\{}", parent, SHELL_KEY_NAME);
        match classes.delete_subkey_all(&shell_subkey) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to delete registry key: {}", shell_subkey));
            }
        }
    }

    // Notify the shell so Explorer reflects the removal immediately.
    notify_shell();

    Ok(())
}

/// Return `true` if the `*\shell\FolderScanner` registry key exists,
/// indicating that the context menu is registered.
pub fn is_registered() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let probe_path = format!("{}\\{}\\{}", CLASSES_ROOT, r"*\shell", SHELL_KEY_NAME);
    hkcu.open_subkey_with_flags(&probe_path, KEY_READ).is_ok()
}

/// Broadcast a shell change notification so Explorer refreshes its
/// file-association cache without requiring a sign-out.
///
/// `SHChangeNotify` is the correct, documented API for this purpose.
/// The `unsafe` block is unavoidable because it is a raw Win32 call.
fn notify_shell() {
    use windows_sys::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    // SAFETY: Passing null item pointers is explicitly documented as valid
    // for SHCNE_ASSOCCHANGED; no memory is read or written through them.
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED as i32,
            SHCNF_IDLIST,
            std::ptr::null(),
            std::ptr::null(),
        );
    }
}

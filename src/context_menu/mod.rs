//! Cross-platform context menu registration for Folder Scanner.
//!
//! This module provides platform-specific implementations for registering
//! and unregistering "Scan with FolderScanner" context menu entries in
//! the native file manager on Windows, macOS, and Linux.

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
mod linux;

/// Register the "Scan with FolderScanner" context menu entry on the current platform.
pub fn install() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::install()
    }
    #[cfg(target_os = "macos")]
    {
        macos::install()
    }
    #[cfg(target_os = "linux")]
    {
        linux::install()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Context menu registration is not supported on this platform")
    }
}

/// Remove the "Scan with FolderScanner" context menu entry on the current platform.
pub fn uninstall() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::uninstall()
    }
    #[cfg(target_os = "macos")]
    {
        macos::uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Context menu unregistration is not supported on this platform")
    }
}

/// Check whether the "Scan with FolderScanner" context menu is currently registered.
pub fn is_registered() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::is_registered()
    }
    #[cfg(target_os = "macos")]
    {
        macos::is_registered()
    }
    #[cfg(target_os = "linux")]
    {
        linux::is_registered()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

/// Returns the Trivy download URL for the current platform
pub fn trivy_download_url(version: &str) -> Option<String> {
    let (os_str, arch_str, ext) = platform_triple()?;
    Some(format!(
        "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os_str}-{arch_str}.{ext}"
    ))
}

/// Returns (os_name, arch_name, extension) for Trivy release assets
fn platform_triple() -> Option<(&'static str, &'static str, &'static str)> {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        return None;
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "64bit"
    } else if cfg!(target_arch = "aarch64") {
        "ARM64"
    } else {
        return None;
    };

    let ext = if cfg!(target_os = "windows") {
        "zip"
    } else {
        "tar.gz"
    };

    Some((os, arch, ext))
}

/// Check if a command exists in PATH
pub fn command_exists(name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("where")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Detect installed file managers on Linux
#[cfg(target_os = "linux")]
pub struct InstalledFileManagers {
    pub nautilus: bool,
    pub dolphin: bool,
    pub thunar: bool,
    pub nemo: bool,
    pub pcmanfm: bool,
    pub caja: bool,
}

#[cfg(target_os = "linux")]
pub fn detect_file_managers() -> InstalledFileManagers {
    InstalledFileManagers {
        nautilus: command_exists("nautilus"),
        dolphin: command_exists("dolphin"),
        thunar: command_exists("thunar"),
        nemo: command_exists("nemo"),
        pcmanfm: command_exists("pcmanfm") || command_exists("pcmanfm-qt"),
        caja: command_exists("caja"),
    }
}

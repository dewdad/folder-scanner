//! macOS context menu integration via an Automator Quick Action (Services menu).
//!
//! Creates a `.workflow` bundle at:
//!   `~/Library/Services/Scan with FolderScanner.workflow/`
//!
//! The bundle contains a "Run Shell Script" Automator action configured to
//! pass selected Finder items as arguments to `folder-scanner scan`.
//!
//! After install/uninstall, the Services cache is refreshed with `pbs -update`
//! so Finder shows the new entry without requiring a logout.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

/// Name of the workflow bundle (without the `.workflow` suffix).
const WORKFLOW_NAME: &str = "Scan with FolderScanner";

/// Returns the path to the `.workflow` bundle directory.
fn workflow_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home
        .join("Library")
        .join("Services")
        .join(format!("{}.workflow", WORKFLOW_NAME)))
}

/// Install the Automator Quick Action.
///
/// Creates the directory structure:
/// ```text
/// ~/Library/Services/Scan with FolderScanner.workflow/
///   Contents/
///     document.wflow   (Automator XML)
///     Info.plist
/// ```
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("Failed to determine current executable path")?;
    let exe_str = exe
        .to_str()
        .context("Executable path contains non-UTF-8 characters")?;

    let workflow = workflow_dir()?;
    let contents = workflow.join("Contents");

    std::fs::create_dir_all(&contents)
        .with_context(|| format!("Failed to create directory: {}", contents.display()))?;

    // Write the Automator workflow XML
    let wflow_path = contents.join("document.wflow");
    let wflow_xml = build_document_wflow(exe_str);
    std::fs::write(&wflow_path, wflow_xml)
        .with_context(|| format!("Failed to write: {}", wflow_path.display()))?;

    // Write Info.plist
    let plist_path = contents.join("Info.plist");
    let plist_xml = build_info_plist();
    std::fs::write(&plist_path, plist_xml)
        .with_context(|| format!("Failed to write: {}", plist_path.display()))?;

    // Refresh the Services cache so Finder shows the new action.
    refresh_services_cache();

    Ok(())
}

/// Remove the `.workflow` bundle and refresh the Services cache.
pub fn uninstall() -> Result<()> {
    let workflow = workflow_dir()?;
    if workflow.exists() {
        std::fs::remove_dir_all(&workflow)
            .with_context(|| format!("Failed to remove: {}", workflow.display()))?;
        refresh_services_cache();
    }
    Ok(())
}

/// Return `true` if the `.workflow` bundle directory exists.
pub fn is_registered() -> bool {
    workflow_dir().map(|p| p.exists()).unwrap_or(false)
}

/// Run `/System/Library/CoreServices/pbs -update` to flush the Services cache.
///
/// Errors are ignored — failure here is cosmetic (the workflow works after the
/// next login even without the cache refresh).
fn refresh_services_cache() {
    let _ = Command::new("/System/Library/CoreServices/pbs")
        .arg("-update")
        .output();
}

/// Build the Automator `document.wflow` XML content.
///
/// This is an Apple property-list that describes a "Run Shell Script" action
/// configured to receive file-system objects from Finder and pass them as
/// arguments to the shell script.
fn build_document_wflow(exe_path: &str) -> String {
    // The shell script iterates over each selected item and calls our binary.
    // exe_path is embedded literally; single-quotes inside the path are escaped.
    let safe_exe = exe_path.replace('\'', "'\\''");
    let shell_script = format!("for f in \"$@\"; do\n    '{}' scan \"$f\"\ndone", safe_exe);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key>
    <string>521</string>
    <key>AMApplicationVersion</key>
    <string>2.10</string>
    <key>AMDocumentVersion</key>
    <string>2</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>AMAccepts</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Optional</key>
                    <true/>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.path</string>
                    </array>
                </dict>
                <key>AMActionVersion</key>
                <string>2.0.3</string>
                <key>AMApplication</key>
                <array>
                    <string>Automator</string>
                </array>
                <key>AMParameterProperties</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <dict/>
                    <key>CheckedForUserDefaultShell</key>
                    <dict/>
                    <key>inputMethod</key>
                    <dict/>
                    <key>shell</key>
                    <dict/>
                    <key>source</key>
                    <dict/>
                </dict>
                <key>AMProvides</key>
                <dict>
                    <key>Container</key>
                    <string>List</string>
                    <key>Types</key>
                    <array>
                        <string>com.apple.cocoa.string</string>
                    </array>
                </dict>
                <key>ActionBundlePath</key>
                <string>/System/Library/Automator/Run Shell Script.action</string>
                <key>ActionName</key>
                <string>Run Shell Script</string>
                <key>ActionParameters</key>
                <dict>
                    <key>COMMAND_STRING</key>
                    <string>{}</string>
                    <key>CheckedForUserDefaultShell</key>
                    <true/>
                    <key>inputMethod</key>
                    <integer>1</integer>
                    <key>shell</key>
                    <string>/bin/bash</string>
                    <key>source</key>
                    <string></string>
                </dict>
                <key>BundleIdentifier</key>
                <string>com.apple.RunShellScript</string>
                <key>CFBundleVersion</key>
                <string>2.0.3</string>
                <key>CanShowSelectedItemsWhenRun</key>
                <false/>
                <key>CanShowWhenRun</key>
                <true/>
                <key>Category</key>
                <array>
                    <string>AMCategoryUtilities</string>
                </array>
                <key>ConnectionID</key>
                <integer>1</integer>
                <key>HideResultFromUser</key>
                <false/>
                <key>InputDataBinding</key>
                <dict/>
                <key>Stars</key>
                <real>0.0</real>
                <key>UUID</key>
                <string>72CCEEBB-7B26-4B96-BC5A-8F4813D9B6A1</string>
                <key>UnlocalizedApplications</key>
                <array>
                    <string>Automator</string>
                </array>
                <key>arguments</key>
                <dict/>
                <key>isViewVisible</key>
                <true/>
                <key>location</key>
                <string>309.500000:253.000000</string>
                <key>nibPath</key>
                <string>/System/Library/Automator/Run Shell Script.action/Contents/Resources/English.lproj/main.nib</string>
            </dict>
            <key>isViewVisible</key>
            <true/>
        </dict>
    </array>
    <key>connectors</key>
    <dict/>
    <key>workflowMetaData</key>
    <dict>
        <key>applicationBundleIDsByPath</key>
        <dict/>
        <key>applicationPathsByBundleID</key>
        <dict/>
        <key>inputTypeIdentifier</key>
        <string>com.apple.Automator.fileSystemObject</string>
        <key>outputTypeIdentifier</key>
        <string>com.apple.Automator.nothing</string>
        <key>presentationMode</key>
        <integer>11</integer>
        <key>processesInput</key>
        <true/>
        <key>serviceInputTypeIdentifier</key>
        <string>com.apple.Automator.fileSystemObject</string>
        <key>serviceOutputTypeIdentifier</key>
        <string>com.apple.Automator.nothing</string>
        <key>serviceProcessesInput</key>
        <true/>
        <key>workflowTypeIdentifier</key>
        <string>com.apple.Automator.servicesMenu</string>
    </dict>
</dict>
</plist>
"#,
        shell_script
    )
}

/// Build the `Info.plist` content that declares the Services menu item.
fn build_info_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSServices</key>
    <array>
        <dict>
            <key>NSMenuItem</key>
            <dict>
                <key>default</key>
                <string>{}</string>
            </dict>
            <key>NSMessage</key>
            <string>runWorkflowAsService</string>
            <key>NSRequiredContext</key>
            <dict>
                <key>NSApplicationIdentifier</key>
                <string>com.apple.finder</string>
            </dict>
            <key>NSSendFileTypes</key>
            <array>
                <string>public.item</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
"#,
        WORKFLOW_NAME
    )
}

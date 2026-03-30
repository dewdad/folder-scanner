# CONTEXT MENU MODULE

Cross-platform file manager integration. Registers "Scan with FolderScanner" right-click menu entries.

## STRUCTURE

```
context_menu/
├── mod.rs       # Dispatcher: install()/uninstall()/is_registered() → cfg-gated platform calls
├── windows.rs   # Registry (HKCU\Software\Classes) + SHChangeNotify shell broadcast
├── macos.rs     # Automator Quick Action (.workflow bundle in ~/Library/Services/)
└── linux.rs     # 6 file managers: Nautilus, Dolphin, Thunar, Nemo, PCManFM, Caja
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Change menu label | Each platform file | `MENU_LABEL` (Windows), `WORKFLOW_NAME` (macOS), inline strings (Linux) |
| Add new Linux file manager | `linux.rs` | Add `install_*`/`uninstall_*`/`is_registered_*` + wire into `install()` |
| Change Windows registry path | `windows.rs:SHELL_PARENTS` | Array of 3 registry parent keys |
| Change macOS Quick Action | `macos.rs:build_document_wflow()` | Full Automator XML plist builder |
| Add new platform | `mod.rs` | Add `#[cfg(target_os = "...")]` block + new module file |

## CONVENTIONS

- **Platform gating**: `mod.rs` uses `#[cfg(target_os)]` on `mod` declarations AND inside `install()`/`uninstall()`/`is_registered()`.
- **Linux linux.rs**: Uses `#![cfg(target_os = "linux")]` file-level attribute. All 6 managers follow identical pattern: path helper → content builder → install fn → uninstall fn → is_registered fn.
- **Detection-based install**: Linux `install()` calls `crate::platform::detect_file_managers()` and only installs for detected managers.
- **Idempotent uninstall**: `uninstall()` removes ALL file manager integrations regardless of detection (safe if absent).
- **No elevation**: All platforms use per-user paths (HKCU, ~/Library/Services, ~/.local/share). No sudo/admin required.

## ANTI-PATTERNS

- **NEVER** use `HKEY_LOCAL_MACHINE` on Windows — always `HKEY_CURRENT_USER` (no elevation needed)
- **NEVER** forget `SHChangeNotify` after registry writes — Explorer won't refresh without it
- **NEVER** write Thunar `uca.xml` while Thunar is running — it rewrites the file on exit, losing changes
- The single `unsafe` block for `SHChangeNotify` in `windows.rs` is documented and unavoidable

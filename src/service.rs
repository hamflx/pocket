use std::path::PathBuf;

use tracing::info;
use winfsp::host::{FileSystemHost, VolumeParams};

use crate::config::{effective_mounts, expand_mount_path, load_config};
use crate::RemoteFilesystem;

/// Ensure the WinFsp runtime DLL is loaded when using delay-loaded linkage.
/// This mirrors the C FspLoad behavior used in WinFsp's own tools.
#[cfg(windows)]
fn load_winfsp_dll() -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::LibraryLoader::LoadLibraryW;
    use windows::core::HSTRING;
    use windows_registry::LOCAL_MACHINE;

    const DLL_NAME: &str = "winfsp-x64.dll";

    unsafe {
        let dll = HSTRING::from(DLL_NAME);
        if let Ok(module) = LoadLibraryW(&dll) {
            if !module.is_invalid() {
                // Loaded from standard search path.
                return Ok(());
            }
        }
    }

    // Fallback: read InstallDir from HKLM\SOFTWARE\WinFsp and load from its bin\ directory.
    let key = LOCAL_MACHINE.open("SOFTWARE\\WOW6432Node\\WinFsp")?;
    let install_dir: String = key.get_string("InstallDir")?;

    let mut path = PathBuf::from(install_dir);
    path.push("bin");
    path.push(DLL_NAME);
    let dll_path = path.to_string_lossy().to_string();

    unsafe {
        let dll = HSTRING::from(dll_path);
        match LoadLibraryW(&dll) {
            Ok(module) if !module.is_invalid() => Ok(()),
            _ => Err("failed to load WinFsp runtime DLL".into()),
        }
    }
}

#[cfg(not(windows))]
fn load_winfsp_dll() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn build_volume_params() -> VolumeParams {
    let mut params = VolumeParams::default();
    params
        .sector_size(512)
        .sectors_per_allocation_unit(1)
        .persistent_acls(true)
        .unicode_on_disk(true)
        .case_sensitive_search(true)
        .case_preserved_names(true);
    params
}

#[cfg(windows)]
fn is_console_attached() -> bool {
    use windows::Win32::System::Console::GetConsoleWindow;
    unsafe { !GetConsoleWindow().is_invalid() }
}

#[cfg(not(windows))]
fn is_console_attached() -> bool {
    true
}

pub fn run_main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure WinFsp DLL is loaded when using delay-load linkage.
    load_winfsp_dll()?;

    let cfg = load_config();
    let mounts = effective_mounts(&cfg)?;

    let mut hosts: Vec<FileSystemHost<RemoteFilesystem>> = Vec::new();

    for (m, storage) in mounts {
        let mount_path = expand_mount_path(&m.mount_path);
        info!(
            "Initializing mount: name={:?}, path={}, backend={:?}",
            m.name, mount_path, storage.backend
        );

        let fs = RemoteFilesystem::new(&storage, m.prefix)?;
        let params = build_volume_params();
        let mut host = FileSystemHost::new(params, fs)?;
        host.mount(&mount_path)?;
        host.start()?;
        hosts.push(host);
    }

    info!("All mounts started.");

    // Check if running in service mode (no console attached)
    if is_console_attached() {
        println!("Press ENTER to stop.");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        for mut host in hosts {
            host.stop();
            host.unmount();
        }
    } else {
        info!("Running as background service. Use 'pocket uninstall' to stop.");
        // Keep the service running indefinitely
        std::thread::park();
    }

    Ok(())
}

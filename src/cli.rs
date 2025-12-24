use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, BackendKind, S3Config, StorageConfig, config_path};
use crate::credentials::store_encrypted_credentials;

#[derive(Parser, Debug)]
#[command(
    name = "pocket",
    author,
    version,
    about = "Remote filesystem with S3 backend"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Configure S3 backend and encrypted credentials
    ConfigS3(ConfigS3Args),
    /// Install pocket as a service with auto-start
    Install,
    /// Uninstall pocket service and remove auto-start
    Uninstall,
}

#[derive(Args, Debug)]
pub struct ConfigS3Args {
    /// S3 bucket name
    #[arg(long)]
    pub bucket: String,

    /// S3 region (optional)
    #[arg(long)]
    pub region: Option<String>,

    /// Optional S3 key prefix
    #[arg(long)]
    pub prefix: Option<String>,

    /// Optional custom S3 endpoint
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Credential profile name (base name of encrypted file, without extension)
    #[arg(long, default_value = "default")]
    pub credentials: String,

    /// S3 access key id (will be encrypted and stored separately)
    #[arg(long)]
    pub access_key_id: String,

    /// S3 secret access key (will be encrypted and stored separately)
    #[arg(long)]
    pub secret_access_key: String,
}

pub fn handle_command(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::ConfigS3(args) => handle_config_s3(args),
        Command::Install => handle_install(),
        Command::Uninstall => handle_uninstall(),
    }
}

fn handle_config_s3(args: ConfigS3Args) -> Result<(), Box<dyn std::error::Error>> {
    store_encrypted_credentials(
        &args.credentials,
        &args.access_key_id,
        &args.secret_access_key,
    )?;

    let path = config_path();
    let mut cfg = if let Ok(existing) = std::fs::read_to_string(&path) {
        toml::from_str::<AppConfig>(&existing)?
    } else {
        AppConfig::default()
    };

    cfg.storages.insert(
        "default".to_string(),
        StorageConfig {
            backend: BackendKind::S3,
            s3: Some(S3Config {
                bucket: args.bucket,
                access_key_id: None,
                secret_access_key: None,
                region: args.region,
                endpoint: args.endpoint,
                credentials: Some(args.credentials),
            }),
        },
    );

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let toml = toml::to_string_pretty(&cfg)?;
    std::fs::write(&path, toml)?;
    info!("Updated configuration at {}", path.display());

    Ok(())
}

#[cfg(windows)]
fn install_dir() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.data_local_dir().join("bin");
    }
    PathBuf::from("bin")
}

#[cfg(not(windows))]
fn install_dir() -> PathBuf {
    PathBuf::from("/usr/local/bin")
}

#[cfg(windows)]
fn handle_install() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use windows_registry::CURRENT_USER;

    // Get the current executable path
    let current_exe = std::env::current_exe()?;
    info!("Current executable: {}", current_exe.display());

    // Determine installation directory
    let install_directory = install_dir();
    fs::create_dir_all(&install_directory)?;

    let installed_exe = install_directory.join("pocket.exe");
    info!("Installing to: {}", installed_exe.display());

    // Copy the executable to the installation directory
    if current_exe != installed_exe {
        fs::copy(&current_exe, &installed_exe)?;
        info!("Copied executable to {}", installed_exe.display());
    } else {
        info!("Already installed at target location");
    }

    // Add to registry for auto-start (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
    let key = CURRENT_USER.create("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    key.set_string("Pocket", &format!("\"{}\"", installed_exe.display()))?;
    info!("Added to Windows startup registry");

    // Start the service in background (no console window)
    start_background_service(&installed_exe)?;
    info!("Started pocket service in background");

    println!("✓ Installation completed successfully!");
    println!("  Installed to: {}", installed_exe.display());
    println!("  Auto-start: Enabled");
    println!("  Service: Running in background");

    Ok(())
}

#[cfg(not(windows))]
fn handle_install() -> Result<(), Box<dyn std::error::Error>> {
    Err("Install command is only supported on Windows".into())
}

#[cfg(windows)]
fn handle_uninstall() -> Result<(), Box<dyn std::error::Error>> {
    use windows_registry::CURRENT_USER;

    // Remove from registry
    if let Ok(key) = CURRENT_USER.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
        if let Err(e) = key.remove_value("Pocket") {
            warn!("Failed to remove registry entry: {}", e);
        } else {
            info!("Removed from Windows startup registry");
        }
    } else {
        info!("No Windows startup registry entry found for Pocket");
    }

    // Stop running service (if any)
    stop_background_service()?;

    // Optionally remove installed binary
    let install_directory = install_dir();
    let installed_exe = install_directory.join("pocket.exe");
    if installed_exe.exists() {
        if let Err(e) = std::fs::remove_file(&installed_exe) {
            warn!(
                "Failed to remove installed executable {}: {}",
                installed_exe.display(),
                e
            );
        } else {
            info!("Removed installed executable {}", installed_exe.display());
        }
    }

    println!("✓ Uninstallation completed.");
    println!("  Removed from Windows startup registry (if present)");
    println!("  Stopped background service (if running)");
    println!("  Removed installed binary at: {}", installed_exe.display());

    Ok(())
}

#[cfg(not(windows))]
fn handle_uninstall() -> Result<(), Box<dyn std::error::Error>> {
    Err("Uninstall command is only supported on Windows".into())
}

#[cfg(windows)]
fn start_background_service(exe_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    Command::new(exe_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;

    info!("Started background service from {}", exe_path.display());
    Ok(())
}

#[cfg(windows)]
fn stop_background_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Use taskkill to stop any running pocket.exe instances
    let output = Command::new("taskkill")
        .args(["/F", "/IM", "pocket.exe"])
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                info!("Stopped pocket service");
            } else {
                debug!("No pocket service was running or failed to stop");
            }
        }
        Err(e) => {
            warn!("Failed to execute taskkill: {}", e);
        }
    }

    Ok(())
}

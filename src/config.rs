use std::collections::HashMap;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Backend 类型，目前支持内存和 S3。
#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Memory,
    S3,
}

impl Default for BackendKind {
    fn default() -> Self {
        BackendKind::Memory
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum S3Mode {
    Sync,
    Buffered,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct S3Config {
    pub bucket: String,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Base name (without extension) of encrypted credential file
    #[serde(default)]
    pub credentials: Option<String>,
    /// S3 I/O mode: sync (default) or buffered
    #[serde(default)]
    pub mode: Option<S3Mode>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct StorageConfig {
    #[serde(default)]
    pub backend: BackendKind,
    #[serde(default)]
    pub s3: Option<S3Config>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MountConfig {
    /// Optional identifier for logging / CLI
    #[serde(default)]
    pub name: Option<String>,
    /// Optional backend mode override for this mount (e.g. S3 buffered/sync)
    #[serde(default)]
    pub mode: Option<S3Mode>,
    /// Local directory path to mount on, e.g. `C:\Users\alice\.ssh`
    pub mount_path: String,
    /// Name of storage backend to use
    pub storage: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct AppConfig {
    /// Named storage backends that can be referenced from mounts
    #[serde(default)]
    pub storages: HashMap<String, StorageConfig>,
    /// Multi-mount configuration
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
}

pub fn config_path() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.config_dir().join("config.toml");
    }

    PathBuf::from("config.toml")
}

pub fn log_file_path() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.data_local_dir().join("logs").join("pocket.log");
    }

    PathBuf::from("logs").join("pocket.log")
}

/// Best-effort retrieval of the current user's home directory as a String.
fn home_dir_string() -> Option<String> {
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(home);
        }
    }

    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.is_empty() {
            return Some(profile);
        }
    }

    None
}

/// Expand "~", "$HOME" and "${HOME}" in a mount path using the current user's
/// home directory. If the home directory cannot be determined, the original
/// string is returned unchanged.
pub fn expand_mount_path(path: &str) -> String {
    let Some(home) = home_dir_string() else {
        return path.to_string();
    };

    // Handle leading "~" (e.g. "~/.ssh" or "~\pocket").
    let mut expanded = if path == "~" {
        home.clone()
    } else if path.starts_with("~/") || path.starts_with("~\\") {
        format!("{home}{}", &path[1..])
    } else {
        path.to_string()
    };

    // Substitute $HOME and ${HOME} anywhere in the path.
    expanded = expanded.replace("$HOME", &home);
    expanded = expanded.replace("${HOME}", &home);

    expanded
}

pub fn load_config() -> AppConfig {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml::from_str::<AppConfig>(&contents) {
            Ok(cfg) => {
                info!("Loaded configuration from {}", path.display());
                cfg
            }
            Err(err) => {
                error!("Failed to parse config file {}: {err}", path.display());
                AppConfig::default()
            }
        },
        Err(err) => {
            error!(
                "Config file {} not found or unreadable: {err}",
                path.display()
            );
            AppConfig::default()
        }
    }
}

/// Build the effective list of mounts and their resolved storage backends from
/// configuration. `storage = "memory"` is treated as a built-in in-memory
/// backend; other storage names must be defined in `[storages.<name>]`.
pub fn effective_mounts(
    cfg: &AppConfig,
) -> Result<Vec<(MountConfig, StorageConfig)>, Box<dyn std::error::Error>> {
    if cfg.mounts.is_empty() {
        return Err("no mounts configured in [mounts]".into());
    }

    let mut result = Vec::new();

    for m in &cfg.mounts {
        let storage_cfg = if m.storage.eq_ignore_ascii_case("memory") {
            StorageConfig {
                backend: BackendKind::Memory,
                s3: None,
            }
        } else if let Some(named) = cfg.storages.get(&m.storage) {
            named.clone()
        } else {
            return Err(format!(
                "mount '{}' refers to unknown storage '{}'",
                m.name.as_deref().unwrap_or("unnamed"),
                m.storage
            )
            .into());
        };

        result.push((m.clone(), storage_cfg));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_file() {
        // Basic sanity: storage = "memory" is treated as built-in memory backend.
        let toml_str = r#"
            [[mounts]]
            name = "mem"
            mount_path = "C:\\Users\\alice\\pocket-tmp"
            storage = "memory"
        "#;
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        let mounts = effective_mounts(&cfg).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].0.name.as_deref(), Some("mem"));
    }
}

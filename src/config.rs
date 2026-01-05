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

/// Expand "~" to home directory and environment variables ($VAR or ${VAR}) in a mount path.
/// If the home directory cannot be determined for "~", it is left unchanged.
/// Unknown environment variables are left unchanged.
pub fn expand_mount_path(path: &str) -> String {
    let mut expanded = path.to_string();

    // Handle leading "~" (e.g. "~/.ssh" or "~\pocket").
    if let Some(home) = home_dir_string() {
        if expanded == "~" {
            expanded = home;
        } else if expanded.starts_with("~/") || expanded.starts_with("~\\") {
            expanded = format!("{home}{}", &expanded[1..]);
        }
    }

    // Expand ${VAR} style environment variables first (more specific pattern).
    expanded = expand_env_vars_braced(&expanded);

    // Expand $VAR style environment variables.
    expanded = expand_env_vars_simple(&expanded);

    expanded
}

/// Expand ${VAR} style environment variables in a string.
fn expand_env_vars_braced(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut found_close = false;

            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                var_name.push(ch);
            }

            if found_close && !var_name.is_empty() {
                if let Ok(value) = std::env::var(&var_name) {
                    result.push_str(&value);
                } else {
                    // Variable not found, keep original
                    result.push_str(&format!("${{{}}}", var_name));
                }
            } else {
                // Malformed, keep original
                result.push('$');
                result.push('{');
                result.push_str(&var_name);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Expand $VAR style environment variables in a string.
/// Supports $VAR at any position, variable name ends at non-alphanumeric/non-underscore.
fn expand_env_vars_simple(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            // Check if next char starts a valid variable name (letter or underscore)
            if let Some(&next) = chars.peek() {
                if next.is_ascii_alphabetic() || next == '_' {
                    let mut var_name = String::new();

                    while let Some(&ch) = chars.peek() {
                        if ch.is_ascii_alphanumeric() || ch == '_' {
                            var_name.push(ch);
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if !var_name.is_empty() {
                        if let Ok(value) = std::env::var(&var_name) {
                            result.push_str(&value);
                        } else {
                            // Variable not found, keep original
                            result.push('$');
                            result.push_str(&var_name);
                        }
                        continue;
                    }
                }
            }
            result.push(c);
        } else {
            result.push(c);
        }
    }

    result
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

    #[test]
    fn test_expand_env_vars_braced() {
        // Set a test environment variable
        unsafe { std::env::set_var("POCKET_TEST_VAR", "test_value") };

        // Test ${VAR} style
        assert_eq!(
            expand_mount_path("${POCKET_TEST_VAR}/config"),
            "test_value/config"
        );
        assert_eq!(
            expand_mount_path("prefix/${POCKET_TEST_VAR}/suffix"),
            "prefix/test_value/suffix"
        );

        // Unknown variable should be kept as-is
        assert_eq!(
            expand_mount_path("${UNKNOWN_VAR_12345}/path"),
            "${UNKNOWN_VAR_12345}/path"
        );

        unsafe { std::env::remove_var("POCKET_TEST_VAR") };
    }

    #[test]
    fn test_expand_env_vars_simple() {
        // Set a test environment variable
        unsafe { std::env::set_var("POCKET_TEST_VAR2", "simple_value") };

        // Test $VAR style
        assert_eq!(
            expand_mount_path("$POCKET_TEST_VAR2/config"),
            "simple_value/config"
        );
        assert_eq!(
            expand_mount_path("prefix/$POCKET_TEST_VAR2/suffix"),
            "prefix/simple_value/suffix"
        );

        // Unknown variable should be kept as-is
        assert_eq!(
            expand_mount_path("$UNKNOWN_VAR_67890/path"),
            "$UNKNOWN_VAR_67890/path"
        );

        unsafe { std::env::remove_var("POCKET_TEST_VAR2") };
    }

    #[test]
    fn test_expand_tilde() {
        // Test ~ expansion (depends on HOME/USERPROFILE being set)
        let expanded = expand_mount_path("~/.ssh");
        assert!(!expanded.starts_with('~'), "~ should be expanded");
        assert!(expanded.ends_with("/.ssh") || expanded.ends_with("\\.ssh"));
    }

    #[test]
    #[cfg(windows)]
    fn test_expand_appdata() {
        // On Windows, $APPDATA should be expanded
        let expanded = expand_mount_path("$APPDATA/nushell");
        assert!(!expanded.starts_with('$'), "APPDATA should be expanded");
        assert!(expanded.contains("AppData") || expanded.contains("appdata"));
    }
}

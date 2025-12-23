use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use clap::{Args, Parser, Subcommand};
use directories::ProjectDirs;

use sysinfo::{Pid, System};
use widestring::{U16CStr, U16CString};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_HANDLE_EOF, HANDLE, HLOCAL, LocalFree, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HSTRING, PWSTR};
use winfsp::FspError;
use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor,
    OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};

use aws_config;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tracing::{debug, error, info, warn};
use winfsp_sys::FspFileSystemOperationProcessIdF;

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum BackendKind {
    Memory,
    S3,
}

impl Default for BackendKind {
    fn default() -> Self {
        BackendKind::Memory
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct S3Config {
    bucket: String,
    #[serde(default)]
    access_key_id: Option<String>,
    #[serde(default)]
    secret_access_key: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    /// Base name (without extension) of encrypted credential file
    #[serde(default)]
    credentials: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct StorageConfig {
    #[serde(default)]
    backend: BackendKind,
    #[serde(default)]
    s3: Option<S3Config>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct MountConfig {
    /// Optional identifier for logging / CLI
    #[serde(default)]
    name: Option<String>,
    /// Local directory path to mount on, e.g. `C:\Users\alice\.ssh`
    mount_path: String,
    /// Name of storage backend to use
    storage: String,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct AppConfig {
    /// Named storage backends that can be referenced from mounts
    #[serde(default)]
    storages: HashMap<String, StorageConfig>,
    /// Multi-mount configuration
    #[serde(default)]
    mounts: Vec<MountConfig>,
}

fn config_path() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.config_dir().join("config.toml");
    }

    PathBuf::from("config.toml")
}

fn log_file_path() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.data_local_dir().join("logs").join("pocket.log");
    }

    PathBuf::from("logs").join("pocket.log")
}

fn credentials_dir() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.config_dir().join("credentials");
    }

    PathBuf::from("credentials")
}

fn credentials_file_path(name: &str) -> PathBuf {
    credentials_dir().join(format!("{name}.bin"))
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
fn expand_mount_path(path: &str) -> String {
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

/// Ensure the WinFsp runtime DLL is loaded when using delay-loaded linkage.
/// This mirrors the C FspLoad behavior used in WinFsp's own tools.
#[cfg(windows)]
fn load_winfsp_dll() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;
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

#[cfg(windows)]
fn protect_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    use windows::core::PCWSTR;

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        CryptProtectData(
            &mut in_blob,
            PCWSTR::null(),
            Some(ptr::null()),
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));

        Ok(result)
    }
}

#[cfg(windows)]
fn unprotect_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    use windows::core::PWSTR;

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let mut descr: PWSTR = PWSTR::null();

        CryptUnprotectData(
            &mut in_blob,
            Some(&mut descr),
            Some(ptr::null()),
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )?;

        if !descr.is_null() {
            let _ = LocalFree(Some(HLOCAL(descr.0 as _)));
        }

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));

        Ok(result)
    }
}

#[cfg(windows)]
fn store_encrypted_credentials(
    name: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    let plaintext = format!("{access_key_id}\n{secret_access_key}");
    let encrypted = protect_data(plaintext.as_bytes())?;

    let dir = credentials_dir();
    fs::create_dir_all(&dir)?;

    let path = credentials_file_path(name);
    fs::write(&path, encrypted)?;

    info!("Stored encrypted S3 credentials at {}", path.display());
    Ok(())
}

#[cfg(windows)]
fn load_encrypted_credentials(name: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    use std::fs;

    let path = credentials_file_path(name);
    let encrypted = fs::read(&path)?;
    let decrypted = unprotect_data(&encrypted)?;
    let text = String::from_utf8(decrypted)?;

    let mut parts = text.splitn(2, '\n');
    let access_key_id = parts
        .next()
        .ok_or("missing access_key_id in decrypted credentials")?;
    let secret_access_key = parts
        .next()
        .ok_or("missing secret_access_key in decrypted credentials")?;

    Ok((access_key_id.to_string(), secret_access_key.to_string()))
}

#[cfg(not(windows))]
fn store_encrypted_credentials(
    _name: &str,
    _access_key_id: &str,
    _secret_access_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Encrypted credentials are only supported on Windows".into())
}

#[cfg(not(windows))]
fn load_encrypted_credentials(_name: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    Err("Encrypted credentials are only supported on Windows".into())
}

fn load_config() -> AppConfig {
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

/// Build the effective list of mounts and their resolved storage backends from
/// configuration. `storage = "memory"` is treated as a built-in in-memory
/// backend; other storage names must be defined in `[storages.<name>]`.
fn effective_mounts(
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

#[derive(Debug, Clone)]
struct MemEntry {
    is_dir: bool,
    data: Vec<u8>,
    attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
}

impl MemEntry {
    /// Fill a FileInfo struct with this entry's metadata
    fn fill_file_info(&self, file_info: &mut FileInfo) {
        file_info.file_attributes = self.attributes;
        if self.is_dir {
            file_info.file_size = 0;
            file_info.allocation_size = 0;
        } else {
            let size = self.data.len() as u64;
            file_info.file_size = size;
            file_info.allocation_size = size;
        }
        file_info.creation_time = self.creation_time;
        file_info.last_access_time = self.last_access_time;
        file_info.last_write_time = self.last_write_time;
        file_info.change_time = self.change_time;
    }
}

/// Get current time as Windows FILETIME (100-nanosecond intervals since January 1, 1601)
fn current_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Difference between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01)
    const FILETIME_UNIX_DIFF: u64 = 116444736000000000;
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = duration.as_secs() * 10_000_000 + duration.subsec_nanos() as u64 / 100;
    ticks + FILETIME_UNIX_DIFF
}

#[derive(Debug)]
struct RemoteFilesystemFileContext {
    path: String,
    is_dir: bool,
    pid: Option<u32>,
}

struct S3State {
    client: S3Client,
    bucket: String,
    key_prefix: String,
    runtime: Arc<Runtime>,
}

impl S3State {
    fn new(cfg: &S3Config, prefix: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let key_prefix = Self::normalize_prefix(prefix);

        let mut access_key_id: Option<String> = None;
        let mut secret_access_key: Option<String> = None;

        if let Some(ref name) = cfg.credentials {
            match load_encrypted_credentials(name) {
                Ok((id, secret)) => {
                    info!("Loaded encrypted S3 credentials from profile {name}");
                    access_key_id = Some(id);
                    secret_access_key = Some(secret);
                }
                Err(err) => {
                    error!("Failed to load encrypted S3 credentials for profile {name}: {err}");
                }
            }
        }

        if access_key_id.is_none() || secret_access_key.is_none() {
            if let (Some(id), Some(secret)) = (&cfg.access_key_id, &cfg.secret_access_key) {
                access_key_id = Some(id.clone());
                secret_access_key = Some(secret.clone());
            }
        }

        if let (Some(id), Some(secret)) = (&access_key_id, &secret_access_key) {
            if !id.is_empty() && !secret.is_empty() {
                unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", id) };
                unsafe { std::env::set_var("AWS_SECRET_ACCESS_KEY", secret) };
            } else {
                warn!(
                    "S3 credentials in config are empty; falling back to default credential chain"
                );
            }
        } else {
            info!("S3 credentials not fully set in config; using default credential chain");
        }

        if let Some(ref region) = cfg.region {
            if !region.is_empty() {
                unsafe { std::env::set_var("AWS_REGION", region) };
            }
        }

        let runtime = Runtime::new()?;
        let shared_config =
            runtime.block_on(aws_config::defaults(aws_config::BehaviorVersion::latest()).load());

        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&shared_config);
        if let Some(ref endpoint) = cfg.endpoint {
            info!("Using custom S3 endpoint: {}", endpoint);
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        let s3_config = s3_config_builder.build();
        let client = S3Client::from_conf(s3_config);

        Ok(S3State {
            client,
            bucket: cfg.bucket.clone(),
            key_prefix,
            runtime: Arc::new(runtime),
        })
    }

    fn normalize_prefix(prefix: Option<String>) -> String {
        let mut p = match prefix {
            Some(p) => p.trim().trim_start_matches('/').to_string(),
            None => String::new(),
        };

        if p.is_empty() {
            return String::new();
        }

        if !p.ends_with('/') {
            p.push('/');
        }

        p
    }

    fn path_to_key(&self, path: &str) -> Option<String> {
        if path == "\\" {
            return None;
        }

        let trimmed = path.trim_start_matches('\\');
        if trimmed.is_empty() {
            return None;
        }

        let key_part = trimmed.replace('\\', "/");
        if self.key_prefix.is_empty() {
            Some(key_part)
        } else {
            Some(format!("{}{}", self.key_prefix, key_part))
        }
    }

    fn upload_object(&self, key: String, data: Vec<u8>) {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let rt = self.runtime.clone();

        rt.block_on(async move {
            let body = ByteStream::from(data);
            if let Err(err) = client
                .put_object()
                .bucket(bucket)
                .key(key)
                .body(body)
                .send()
                .await
            {
                error!("S3 put_object error: {err:?}");
            }
        });
    }

    fn delete_object(&self, key: String) {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let rt = self.runtime.clone();

        rt.block_on(async move {
            if let Err(err) = client.delete_object().bucket(bucket).key(key).send().await {
                error!("S3 delete_object error: {err}");
            }
        });
    }

    fn key_to_path(&self, key: &str) -> Option<String> {
        let rel = if self.key_prefix.is_empty() {
            key
        } else {
            match key.strip_prefix(&self.key_prefix) {
                Some(r) => r,
                None => return None,
            }
        };

        if rel.is_empty() {
            return None;
        }

        let win = rel.replace('/', "\\");
        Some(format!(r"\{}", win))
    }

    fn load_all_objects(&self) -> Vec<(String, Vec<u8>)> {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let prefix = if self.key_prefix.is_empty() {
            None
        } else {
            Some(self.key_prefix.clone())
        };
        let rt = self.runtime.clone();

        rt.block_on(async move {
            let mut results: Vec<(String, Vec<u8>)> = Vec::new();

            let mut req = client.list_objects_v2().bucket(&bucket);
            if let Some(ref p) = prefix {
                req = req.prefix(p);
            }

            match req.send().await {
                Ok(resp) => {
                    if let Some(contents) = resp.contents {
                        for obj in contents {
                            if let Some(key) = obj.key() {
                                match client.get_object().bucket(&bucket).key(key).send().await {
                                    Ok(output) => match output.body.collect().await {
                                        Ok(aggregated) => {
                                            let bytes = aggregated.into_bytes().to_vec();
                                            results.push((key.to_string(), bytes));
                                        }
                                        Err(err) => {
                                            error!("S3 get_object body error for {}: {err}", key);
                                        }
                                    },
                                    Err(err) => {
                                        error!("S3 get_object error for {}: {err}", key);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    error!("S3 list_objects_v2 error: {err}");
                }
            }

            results
        })
    }
}

struct RemoteFilesystem {
    entries: RwLock<HashMap<String, MemEntry>>,
    security_descriptor: Vec<u8>,
    s3: Option<S3State>,
    process_name_cache: RwLock<HashMap<u32, String>>,
}

impl RemoteFilesystem {
    fn new(
        storage: &StorageConfig,
        prefix: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let custom_sd = Self::build_user_only_security_descriptor()?;
        if let Ok(custom_sddl) = Self::sd_to_sddl(&custom_sd) {
            debug!("Custom SD SDDL : {}", custom_sddl);
        } else {
            warn!("Failed to convert custom SD to SDDL");
        }

        let security_descriptor = custom_sd;
        let mut map = HashMap::new();

        let now = current_filetime();
        map.insert(
            "\\".to_string(),
            MemEntry {
                is_dir: true,
                data: Vec::new(),
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
            },
        );

        let s3 = match storage.backend {
            BackendKind::Memory => {
                info!("Using in-memory backend");
                None
            }
            BackendKind::S3 => {
                let s3_cfg = match storage.s3 {
                    Some(ref s3_cfg) if !s3_cfg.bucket.is_empty() => Some(s3_cfg.clone()),
                    _ => {
                        warn!(
                            "S3 backend selected but [storage.s3] configuration is missing or invalid; falling back to in-memory backend"
                        );
                        None
                    }
                };

                if let Some(s3_cfg) = s3_cfg {
                    match S3State::new(&s3_cfg, prefix.clone()) {
                        Ok(state) => {
                            info!(
                                "S3 backend enabled, bucket={}, prefix={}",
                                s3_cfg.bucket,
                                prefix.unwrap_or_default()
                            );
                            Some(state)
                        }
                        Err(err) => {
                            error!("Failed to initialize S3 backend: {err}");
                            None
                        }
                    }
                } else {
                    None
                }
            }
        };

        if let Some(ref s3_state) = s3 {
            Self::hydrate_from_s3(&mut map, s3_state);
        }

        Ok(RemoteFilesystem {
            entries: RwLock::new(map),
            security_descriptor,
            s3,
            process_name_cache: RwLock::new(HashMap::new()),
        })
    }

    fn normalize_path(file_name: &U16CStr) -> String {
        let s = file_name.to_string_lossy();
        if s.is_empty() || s == "\\" {
            "\\".to_string()
        } else if s.starts_with('\\') {
            s
        } else {
            format!(r"\{}", s)
        }
    }

    fn parent_path(path: &str) -> Option<String> {
        if path == "\\" {
            None
        } else if let Some(pos) = path.rfind('\\') {
            if pos == 0 {
                Some("\\".to_string())
            } else {
                Some(path[..pos].to_string())
            }
        } else {
            Some("\\".to_string())
        }
    }

    fn hydrate_from_s3(entries: &mut HashMap<String, MemEntry>, s3: &S3State) {
        let objects = s3.load_all_objects();
        if objects.is_empty() {
            return;
        }

        let now = current_filetime();
        for (key, data) in objects {
            if let Some(path) = s3.key_to_path(&key) {
                Self::ensure_parent_directories(entries, &path);
                entries.insert(
                    path.clone(),
                    MemEntry {
                        is_dir: false,
                        data,
                        attributes: FILE_ATTRIBUTE_ARCHIVE.0 | FILE_ATTRIBUTE_NORMAL.0,
                        creation_time: now,
                        last_access_time: now,
                        last_write_time: now,
                        change_time: now,
                    },
                );
            }
        }
    }

    fn ensure_parent_directories(entries: &mut HashMap<String, MemEntry>, path: &str) {
        let trimmed = path.trim_start_matches('\\');
        if trimmed.is_empty() {
            return;
        }

        let parts: Vec<&str> = trimmed.split('\\').collect();
        if parts.len() <= 1 {
            return;
        }

        let mut current = String::from("\\");
        for part in &parts[..parts.len() - 1] {
            if part.is_empty() {
                continue;
            }
            if current == "\\" {
                current = format!(r"\{}", part);
            } else {
                current = format!(r"{}\{}", current, part);
            }

            let now = current_filetime();
            entries.entry(current.clone()).or_insert(MemEntry {
                is_dir: true,
                data: Vec::new(),
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
            });
        }
    }

    // 当前的 SD 构造方式：基于当前用户 SID + SYSTEM + Administrators 的 SDDL
    fn build_user_only_security_descriptor() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        unsafe {
            // 打开当前进程的访问令牌，获取当前用户 SID
            let process = GetCurrentProcess();
            let mut token: HANDLE = HANDLE::default();
            OpenProcessToken(process, TOKEN_QUERY, &mut token)?;

            let mut buf = vec![0u8; 256];
            let mut return_length: u32 = 0;
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                &mut return_length,
            )?;

            CloseHandle(token)?;

            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let user_sid = token_user.User.Sid;

            // 将 SID 转成字符串形式，方便拼接 SDDL
            let mut sid_str = PWSTR::null();
            ConvertSidToStringSidW(user_sid, &mut sid_str)?;
            let sid_string = sid_str.to_string()?;
            debug!("sid_string: {}", sid_string);
            let _ = LocalFree(Some(HLOCAL(sid_str.0 as *mut _)));

            // 构造一个"当前用户作为 Owner 和 Group，且只有当前用户拥有完全控制（不继承）"的安全描述符
            // O:<SID>                     -> Owner 为当前用户
            // G:<SID>                     -> Group 也为当前用户
            // D:P(A;;FA;;;<SID>)          -> 当前用户完全控制，P标志表示Protected（阻止从父对象继承）
            let sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})", sid = sid_string);
            debug!("sddl: {}", sddl);

            let mut p_sd = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
            let mut sd_size: u32 = 0;
            let sddl_w = HSTRING::from(sddl);
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl_w,
                SDDL_REVISION_1,
                &mut p_sd,
                Some(&mut sd_size),
            )?;

            let sd_slice = std::slice::from_raw_parts(p_sd.0 as *const u8, sd_size as usize);
            let sd_vec = sd_slice.to_vec();

            debug!("sd_vec: {:?}", sd_vec);

            let _ = LocalFree(Some(HLOCAL(p_sd.0 as *mut _)));

            Ok(sd_vec)
        }
    }

    // 把 SD 转成 SDDL 字符串，便于打印对比
    fn sd_to_sddl(sd: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        unsafe {
            let mut sddl_ptr = PWSTR::null();
            let flags =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(sd.as_ptr() as *mut _),
                SDDL_REVISION_1,
                flags,
                &mut sddl_ptr,
                None,
            )?;

            let sddl = sddl_ptr.to_string()?;
            let _ = LocalFree(Some(HLOCAL(sddl_ptr.0 as *mut _)));

            Ok(sddl)
        }
    }

    // 获取进程名称（带缓存）
    fn get_process_name(&self, pid: u32) -> String {
        // 先查缓存
        {
            let cache = self.process_name_cache.read().unwrap();
            if let Some(name) = cache.get(&pid) {
                return name.clone();
            }
        }

        // 缓存未命中，使用 sysinfo 查询
        let mut sys = System::new();
        sys.refresh_processes(
            sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
            true,
        );

        let process_name = if let Some(process) = sys.process(Pid::from_u32(pid)) {
            process.name().to_string_lossy().to_string()
        } else {
            format!("<unknown:{}>", pid)
        };

        // 写入缓存
        {
            let mut cache = self.process_name_cache.write().unwrap();
            cache.insert(pid, process_name.clone());
        }

        process_name
    }
}

impl FileSystemContext for RemoteFilesystem {
    type FileContext = RemoteFilesystemFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity, FspError> {
        let path = Self::normalize_path(file_name);
        debug!("get_security_by_name: {}", path);

        let entries = self.entries.read().unwrap();
        let attributes = if let Some(entry) = entries.get(&path) {
            entry.attributes
        } else if path == "\\" {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        };

        if let Some(buf) = security_descriptor {
            debug!("security_descriptor: {}", buf.len());
            let sd = &self.security_descriptor;
            debug!("sd: {}", sd.len());
            if buf.len() < sd.len() {
                warn!("security_descriptor too small");
                return Err(FspError::from(STATUS_BUFFER_TOO_SMALL));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(sd.as_ptr(), buf.as_mut_ptr() as *mut u8, sd.len());
            }
        }

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: self.security_descriptor.len() as u64,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext, FspError> {
        let path = Self::normalize_path(file_name);
        debug!("open: {}", path);

        let pid = unsafe { FspFileSystemOperationProcessIdF() };

        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.get(&path) {
            let fi = file_info.as_mut();
            entry.fill_file_info(fi);
            fi.index_number = 0;
            fi.hard_links = 0;

            debug!("open: file_info: {:?}", fi);

            Ok(RemoteFilesystemFileContext {
                path,
                is_dir: entry.is_dir,
                pid: match pid {
                    0 => None,
                    pid => Some(pid),
                },
            })
        } else {
            debug!("open: not found");
            Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn close(&self, _context: Self::FileContext) {}

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        if let Some(ctx) = context {
            debug!("flush: {}", ctx.path);
            let entries = self.entries.read().unwrap();
            if let Some(entry) = entries.get(&ctx.path) {
                entry.fill_file_info(file_info);
            }
        } else {
            debug!("flush: volume flush");
        }

        // For in-memory filesystem, flush is always successful
        // For S3 backend, data is already uploaded in write()
        Ok(())
    }

    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        mut file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext, FspError> {
        let path = Self::normalize_path(file_name);
        debug!("create: {}", path);

        let pid = unsafe { FspFileSystemOperationProcessIdF() };

        // Determine if this is a directory by attributes.
        let is_dir = (file_attributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
        if file_attributes == 0 {
            file_attributes = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY.0
            } else {
                FILE_ATTRIBUTE_NORMAL.0
            };
        }

        let parent = Self::parent_path(&path).unwrap_or_else(|| "\\".to_string());
        let mut entries = self.entries.write().unwrap();

        if !entries.contains_key(&parent) {
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        }

        let now = current_filetime();
        let entry = entries.entry(path.clone()).or_insert(MemEntry {
            is_dir,
            data: Vec::new(),
            attributes: file_attributes,
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        });

        entry.is_dir = is_dir;
        entry.attributes = file_attributes;
        if !is_dir {
            entry.data.clear();
        }
        // Update timestamps on create/overwrite
        entry.last_access_time = now;
        entry.last_write_time = now;
        entry.change_time = now;

        let fi = file_info.as_mut();
        entry.fill_file_info(fi);
        fi.index_number = 0;
        fi.hard_links = 0;

        Ok(RemoteFilesystemFileContext {
            path,
            is_dir: entry.is_dir,
            pid: match pid {
                0 => None,
                pid => Some(pid),
            },
        })
    }

    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        if FspCleanupFlags::FspCleanupDelete.is_flagged(flags) {
            let path = file_name
                .map(Self::normalize_path)
                .unwrap_or_else(|| context.path.clone());
            info!("cleanup delete: {}", path);

            let mut deleted_paths: Vec<String> = Vec::new();

            let mut entries = self.entries.write().unwrap();
            // Remove the entry and all children if it is a directory.
            let keys: Vec<String> = entries
                .keys()
                .filter(|k| k.as_str() == path || k.starts_with(&(path.clone() + "\\")))
                .cloned()
                .collect();
            for k in keys {
                // avoid deleting root
                if k != "\\" {
                    deleted_paths.push(k.clone());
                    entries.remove(&k);
                }
            }

            {
                if let Some(s3) = &self.s3 {
                    for path in deleted_paths {
                        if let Some(key) = s3.path_to_key(&path) {
                            s3.delete_object(key);
                        }
                    }
                }
            }
        }
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        out_file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        debug!("get_file_info: {}", context.path);

        out_file_info.index_number = 0;
        out_file_info.hard_links = 0;

        let entries = self.entries.read().unwrap();
        if let Some(entry) = entries.get(&context.path) {
            entry.fill_file_info(out_file_info);
            debug!("get_file_info: file_info: {:?}", out_file_info);
        } else {
            debug!("get_file_info: not found");
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        }

        Ok(())
    }

    // fn get_dir_info_by_name(
    //     &self,
    //     _context: &Self::FileContext,
    //     _file_name: &U16CStr,
    //     _out_dir_info: &mut DirInfo,
    // ) -> winfsp::Result<()> {
    //     eprintln!("get_dir_info_by_name");
    //     Ok(())
    // }

    // fn get_extended_attributes(
    //     &self,
    //     _context: &Self::FileContext,
    //     _buffer: &mut [u8],
    // ) -> winfsp::Result<u32> {
    //     eprintln!("get_extended_attributes");
    //     Ok(0)
    // }

    fn get_security(
        &self,
        _context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<u64, FspError> {
        debug!("get_security: {}", _context.path);

        if let Some(buf) = security_descriptor {
            let sd = &self.security_descriptor;
            if buf.len() < sd.len() {
                return Err(FspError::from(STATUS_BUFFER_TOO_SMALL));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(sd.as_ptr(), buf.as_mut_ptr() as *mut u8, sd.len());
            }
        }

        Ok(self.security_descriptor.len() as u64)
    }

    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: ModificationDescriptor,
    ) -> Result<(), FspError> {
        debug!("set_security (ignored)");
        // 为简化实现：忽略修改请求，但返回成功。
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        debug!(
            "set_basic_info: {} attrs={} ct={} lat={} lwt={} cht={}",
            context.path,
            file_attributes,
            creation_time,
            last_access_time,
            last_write_time,
            change_time
        );

        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(&context.path)
            .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

        // INVALID_FILE_ATTRIBUTES (0xFFFFFFFF) means "don't change"
        if file_attributes != u32::MAX {
            entry.attributes = file_attributes;
        }
        // 0 means "don't change" for timestamps
        if creation_time != 0 {
            entry.creation_time = creation_time;
        }
        if last_access_time != 0 {
            entry.last_access_time = last_access_time;
        }
        if last_write_time != 0 {
            entry.last_write_time = last_write_time;
        }
        if change_time != 0 {
            entry.change_time = change_time;
        }

        entry.fill_file_info(file_info);
        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> Result<(), FspError> {
        debug!("get_volume_info");
        // Report a simple fixed-size in-memory volume.
        let total_size = 1024 * 1024 * 1024u64; // 1 GiB
        out_volume_info.total_size = total_size;
        out_volume_info.free_size = total_size;
        out_volume_info.set_volume_label("RemoteFilesystem");
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        debug!("set_file_size: {} -> {}", context.path, new_size);

        if context.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(&context.path)
            .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

        let new_len = new_size as usize;
        entry.data.resize(new_len, 0);

        // Update timestamps on size change
        let now = current_filetime();
        entry.last_write_time = now;
        entry.change_time = now;

        entry.fill_file_info(file_info);
        Ok(())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<u32, FspError> {
        let process_info = if let Some(pid) = context.pid {
            let process_name = self.get_process_name(pid);
            format!("pid: {}, process: {}", pid, process_name)
        } else {
            "pid: unknown".to_string()
        };

        debug!("read: {} offset {}, {}", context.path, offset, process_info);

        if context.is_dir {
            warn!("read: is a directory, return error");
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let entries = self.entries.read().unwrap();
        let entry = entries
            .get(&context.path)
            .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

        let data = &entry.data;
        let offset = offset as usize;
        if offset >= data.len() {
            debug!("read: offset out of range");
            return Err(FspError::from(ERROR_HANDLE_EOF));
        }

        let len = buffer.len().min(data.len() - offset);
        buffer[..len].copy_from_slice(&data[offset..offset + len]);

        Ok(len as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32, FspError> {
        debug!(
            "write: {} offset {} len {}",
            context.path,
            offset,
            buffer.len()
        );

        if context.is_dir {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .get_mut(&context.path)
            .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

        let write_offset = if write_to_eof {
            entry.data.len()
        } else {
            offset as usize
        };

        if constrained_io {
            if write_offset >= entry.data.len() {
                return Ok(0);
            }
            let max_len = entry.data.len() - write_offset;
            let write_len = buffer.len().min(max_len);
            entry.data[write_offset..write_offset + write_len]
                .copy_from_slice(&buffer[..write_len]);

            // Update timestamps on write
            let now = current_filetime();
            entry.last_access_time = now;
            entry.last_write_time = now;
            entry.change_time = now;

            entry.fill_file_info(file_info);
            return Ok(write_len as u32);
        }

        let end = write_offset.saturating_add(buffer.len());
        if end > entry.data.len() {
            entry.data.resize(end, 0);
        }
        entry.data[write_offset..write_offset + buffer.len()].copy_from_slice(buffer);

        // Update timestamps on write
        let now = current_filetime();
        entry.last_access_time = now;
        entry.last_write_time = now;
        entry.change_time = now;

        if let Some(s3) = &self.s3 {
            if let Some(key) = s3.path_to_key(&context.path) {
                s3.upload_object(key, entry.data.clone());
            }
        }

        entry.fill_file_info(file_info);
        Ok(buffer.len() as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32, FspError> {
        debug!(
            "read_directory: {} marker {:?}",
            context.path,
            marker.inner()
        );

        if !context.is_dir {
            warn!("read_directory: not a directory, return error");
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        let mut all_entries: Vec<(String, bool, u64, u32)> = Vec::new();

        // Always include "." and ".."
        all_entries.push((".".to_string(), true, 0, FILE_ATTRIBUTE_DIRECTORY.0));
        all_entries.push(("..".to_string(), true, 0, FILE_ATTRIBUTE_DIRECTORY.0));

        let dir_path = &context.path;
        let entries = self.entries.read().unwrap();

        for (path, entry) in entries.iter() {
            if path == dir_path {
                continue;
            }
            if let Some(parent) = Self::parent_path(path) {
                if parent == *dir_path {
                    if let Some(name) = path.rsplit('\\').next() {
                        let size = if entry.is_dir {
                            0
                        } else {
                            entry.data.len() as u64
                        };
                        all_entries.push((name.to_string(), entry.is_dir, size, entry.attributes));
                    }
                }
            }
        }

        // Deterministic listing order.
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut cursor = 0;
        let mut found_marker = marker.is_none();

        for (name, is_dir, size, attrs) in all_entries {
            let name_owner = U16CString::from_str(&name)
                .map_err(|_| FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;
            let name_u16 = name_owner.as_ucstr();

            if !found_marker {
                if let Some(m) = marker.inner_as_cstr() {
                    if m == name_u16 {
                        found_marker = true;
                    }
                }
                continue;
            }

            let mut info = DirInfo::<255>::new();
            let finfo = info.file_info_mut();
            finfo.file_attributes = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY.0
            } else {
                attrs
            };
            if !is_dir {
                finfo.file_size = size;
                finfo.allocation_size = size;
            }

            info.set_name_cstr(name_u16)
                .map_err(|_| FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

            if !info.append_to_buffer(buffer, &mut cursor) {
                break;
            }
        }

        debug!("read_directory: cursor: {}", cursor);
        Ok(cursor)
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), FspError> {
        let old_path = Self::normalize_path(file_name);
        let new_path = Self::normalize_path(new_file_name);
        info!(
            "rename: {} -> {} (replace_if_exists={})",
            old_path, new_path, replace_if_exists
        );

        let mut entries = self.entries.write().unwrap();

        if !entries.contains_key(&old_path) {
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        }

        if entries.contains_key(&new_path) && !replace_if_exists {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        // Collect entries to move (the path itself and any children if a directory).
        let to_move_keys: Vec<String> = entries
            .keys()
            .filter(|k| k.as_str() == old_path || k.starts_with(&(old_path.clone() + "\\")))
            .cloned()
            .collect();

        let mut moved: Vec<(String, String, MemEntry)> = Vec::new();
        for k in &to_move_keys {
            if let Some(entry) = entries.remove(k) {
                let new_key_path = if k == &old_path {
                    new_path.clone()
                } else {
                    let suffix = &k[old_path.len()..];
                    format!("{}{}", new_path, suffix)
                };

                moved.push((k.clone(), new_key_path.clone(), entry.clone()));
            }
        }

        for (_old_key, new_key, entry) in &moved {
            entries.insert(new_key.clone(), entry.clone());
        }

        drop(entries);

        if let Some(s3) = &self.s3 {
            for (old_p, new_p, entry) in moved.iter() {
                if !entry.is_dir {
                    if let Some(new_key) = s3.path_to_key(new_p) {
                        s3.upload_object(new_key, entry.data.clone());
                    }
                    if let Some(old_key) = s3.path_to_key(old_p) {
                        s3.delete_object(old_key);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "pocket",
    author,
    version,
    about = "Remote filesystem with S3 backend"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Configure S3 backend and encrypted credentials
    ConfigS3(ConfigS3Args),
    /// Install pocket as a service with auto-start
    Install,
    /// Uninstall pocket service and remove auto-start
    Uninstall,
}

#[derive(Args, Debug)]
struct ConfigS3Args {
    /// S3 bucket name
    #[arg(long)]
    bucket: String,

    /// S3 region (optional)
    #[arg(long)]
    region: Option<String>,

    /// Optional S3 key prefix
    #[arg(long)]
    prefix: Option<String>,

    /// Optional custom S3 endpoint
    #[arg(long)]
    endpoint: Option<String>,

    /// Credential profile name (base name of encrypted file, without extension)
    #[arg(long, default_value = "default")]
    credentials: String,

    /// S3 access key id (will be encrypted and stored separately)
    #[arg(long)]
    access_key_id: String,

    /// S3 secret access key (will be encrypted and stored separately)
    #[arg(long)]
    secret_access_key: String,
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
    }

    // Stop any running instances
    stop_background_service()?;

    // Optionally remove the installed executable
    let installed_exe = install_dir().join("pocket.exe");
    if installed_exe.exists() {
        // We can't delete ourselves if we're running from the install location
        let current_exe = std::env::current_exe()?;
        if current_exe != installed_exe {
            if let Err(e) = std::fs::remove_file(&installed_exe) {
                warn!("Failed to remove installed executable: {}", e);
                println!("Note: Please manually delete: {}", installed_exe.display());
            } else {
                info!("Removed installed executable");
            }
        } else {
            println!("Note: Please manually delete: {}", installed_exe.display());
        }
    }

    println!("✓ Uninstallation completed!");
    println!("  Auto-start: Disabled");
    println!("  Service: Stopped");

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

fn run_main() -> Result<(), Box<dyn std::error::Error>> {
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

#[cfg(windows)]
fn is_console_attached() -> bool {
    use windows::Win32::System::Console::GetConsoleWindow;
    unsafe { !GetConsoleWindow().is_invalid() }
}

#[cfg(not(windows))]
fn is_console_attached() -> bool {
    true
}

fn main() {
    // 初始化 tracing 日志，输出到日志文件
    let _guard = {
        use std::fs;
        use std::{ffi::OsStr, path::Path};
        use tracing_appender::rolling;
        use tracing_subscriber::{EnvFilter, fmt};

        let log_path = log_file_path();
        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let dir = log_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = log_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("pocket.log"));

        let file_appender = rolling::never(dir, file_name);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        fmt()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        info!("Logging to {}", log_path.display());

        guard
    };

    let cli = Cli::parse();

    if let Some(command) = cli.command {
        if let Err(e) = match command {
            Command::ConfigS3(args) => handle_config_s3(args),
            Command::Install => handle_install(),
            Command::Uninstall => handle_uninstall(),
        } {
            error!("Error: {e}");
            let mut source = e.source();
            while let Some(err) = source {
                error!("  Caused by: {err}");
                source = err.source();
            }
            std::process::exit(1);
        }
        return;
    }

    if let Err(e) = run_main() {
        error!("Error: {e}");
        let mut source = e.source();
        while let Some(err) = source {
            error!("  Caused by: {err}");
            source = err.source();
        }
        // 退出时返回非零表示错误
        std::process::exit(1);
    }
}

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

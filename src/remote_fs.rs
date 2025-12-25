use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::Duration;

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
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HSTRING, PWSTR};
use winfsp::FspError;
use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor,
    OpenFileInfo, VolumeInfo, WideNameInfo,
};

use tracing::{debug, error, info, warn};
use winfsp_sys::FspFileSystemOperationProcessIdF;

use crate::config::{BackendKind, S3Mode, StorageConfig};
use crate::fs_types::MemEntry;
use crate::index_crdt::LoroIndex;
use crate::s3_backend::{
    BufferedIndexStore, BufferedObjectStore, S3IndexStore, S3ObjectStore, S3State, S3TaskSender,
};
use crate::storage::{InMemoryIndexStore, InMemoryObjectStore, IndexStore, ObjectStore};

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
pub struct RemoteFilesystemFileContext {
    path: String,
    is_dir: bool,
    pid: Option<u32>,
    buffer: Option<Arc<Mutex<FileBuffer>>>,
}

pub struct RemoteFilesystem {
    index: Arc<RwLock<LoroIndex>>,
    security_descriptor: Vec<u8>,
    object_store: Arc<dyn ObjectStore>,
    index_store: Option<Arc<dyn IndexStore>>,
    index_persister: Option<IndexPersister>,
    process_name_cache: RwLock<HashMap<u32, String>>,
    file_buffers: RwLock<HashMap<String, Arc<Mutex<FileBuffer>>>>,
}

#[derive(Debug)]
struct FileBuffer {
    data: Vec<u8>,
    dirty: bool,
    deleted: bool,
}

#[derive(Clone)]
struct IndexPersister {
    sender: mpsc::Sender<()>,
}

impl IndexPersister {
    fn new(
        index: Arc<RwLock<LoroIndex>>,
        store: Arc<dyn IndexStore>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (tx, rx) = mpsc::channel::<()>();
        let sender = tx.clone();

        std::thread::Builder::new()
            .name("pocket-index-bg".to_string())
            .spawn(move || {
                // 简单的合并节流：收到请求后等待一小段时间，合并更多请求，再做一次快照。
                let debounce = Duration::from_millis(200);
                while let Ok(()) = rx.recv() {
                    // 合并在 debounce 窗口内到达的后续请求。
                    loop {
                        match rx.recv_timeout(debounce) {
                            Ok(()) => {
                                // 继续合并
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                break;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                return;
                            }
                        }
                    }

                    let bytes = {
                        let idx = index.read().unwrap();
                        idx.to_bytes()
                    };
                    store.save(&bytes);
                }
            })?;

        Ok(IndexPersister { sender })
    }

    fn request_persist(&self) {
        let _ = self.sender.send(());
    }
}

impl RemoteFilesystem {
    pub fn new(
        storage: &StorageConfig,
        prefix: Option<String>,
        s3_mode: Option<S3Mode>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let custom_sd = Self::build_user_only_security_descriptor()?;
        if let Ok(custom_sddl) = Self::sd_to_sddl(&custom_sd) {
            debug!("Custom SD SDDL : {}", custom_sddl);
        } else {
            warn!("Failed to convert custom SD to SDDL");
        }

        let security_descriptor = custom_sd;
        let (object_store, index_store): (Arc<dyn ObjectStore>, Option<Arc<dyn IndexStore>>) =
            match storage.backend {
                BackendKind::Memory => {
                    info!("Using in-memory backend");
                    let obj = Arc::new(InMemoryObjectStore::new());
                    let idx = Arc::new(InMemoryIndexStore::new());
                    (obj, Some(idx))
                }
                BackendKind::S3 => {
                    let s3_cfg = match storage.s3 {
                        Some(ref s3_cfg) if !s3_cfg.bucket.is_empty() => s3_cfg,
                        _ => {
                            warn!(
                                "S3 backend selected but [storage.s3] configuration is missing or invalid; falling back to in-memory backend"
                            );
                            let obj = Arc::new(InMemoryObjectStore::new());
                            let idx = Arc::new(InMemoryIndexStore::new());
                            let now = current_filetime();
                            let index = LoroIndex::new_empty(now, FILE_ATTRIBUTE_DIRECTORY.0);
                            let index_arc = Arc::new(RwLock::new(index));
                            let index_persister =
                                IndexPersister::new(index_arc.clone(), idx.clone()).ok();
                            return Ok(RemoteFilesystem {
                                index: index_arc,
                                security_descriptor,
                                object_store: obj,
                                index_store: Some(idx),
                                index_persister,
                                process_name_cache: RwLock::new(HashMap::new()),
                                file_buffers: RwLock::new(HashMap::new()),
                            });
                        }
                    };

                    let s3_state = Arc::new(S3State::new(s3_cfg, prefix.clone())?);
                    let prefix_str = prefix.unwrap_or_default();
                    let mode = s3_mode.or(s3_cfg.mode).unwrap_or(S3Mode::Sync);

                    info!(
                        "S3 backend enabled, bucket={}, prefix={}, mode={:?}",
                        s3_cfg.bucket, prefix_str, mode
                    );

                    match mode {
                        S3Mode::Sync => {
                            let obj = Arc::new(S3ObjectStore::new(s3_state.clone()));
                            let idx = Arc::new(S3IndexStore::new(s3_state));
                            (obj, Some(idx))
                        }
                        S3Mode::Buffered => {
                            let task_sender = S3TaskSender::new(s3_state.clone());
                            let obj = Arc::new(BufferedObjectStore::new(
                                s3_state.clone(),
                                task_sender.clone(),
                            ));
                            let idx = Arc::new(BufferedIndexStore::new(s3_state, task_sender));
                            (obj, Some(idx))
                        }
                    }
                }
            };

        let now = current_filetime();

        let index = if let Some(ref store) = index_store {
            match store.load_latest() {
                Some(bytes) => match LoroIndex::from_bytes(&bytes) {
                    Ok(idx) => idx,
                    Err(err) => {
                        error!("Failed to load index from store, creating new: {err}");
                        LoroIndex::new_empty(now, FILE_ATTRIBUTE_DIRECTORY.0)
                    }
                },
                None => LoroIndex::new_empty(now, FILE_ATTRIBUTE_DIRECTORY.0),
            }
        } else {
            LoroIndex::new_empty(now, FILE_ATTRIBUTE_DIRECTORY.0)
        };

        let index_arc = Arc::new(RwLock::new(index));
        let index_persister = if let Some(store) = &index_store {
            match IndexPersister::new(index_arc.clone(), store.clone()) {
                Ok(p) => Some(p),
                Err(err) => {
                    error!(
                        "Failed to start index persister, falling back to sync snapshotting: {err}"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(RemoteFilesystem {
            index: index_arc,
            security_descriptor,
            object_store,
            index_store,
            index_persister,
            process_name_cache: RwLock::new(HashMap::new()),
            file_buffers: RwLock::new(HashMap::new()),
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

    fn should_buffer_file(path: &str, is_dir: bool) -> bool {
        debug!("should_buffer_file: path={} is_dir={}", path, is_dir);
        !is_dir
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
                object_id: None,
                size: 0,
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

    fn load_file_data(&self, entry: &MemEntry) -> Vec<u8> {
        if let Some(id) = entry.object_id {
            if let Some(data) = self.object_store.get(&id) {
                return data;
            }
        }
        Vec::new()
    }

    fn persist_index(&self) {
        if let Some(persister) = &self.index_persister {
            persister.request_persist();
        } else if let Some(store) = &self.index_store {
            let index = self.index.read().unwrap();
            let bytes = index.to_bytes();
            store.save(&bytes);
        }
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

        let index = self.index.read().unwrap();
        let entries = index.entries();
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

        let index = self.index.read().unwrap();
        if let Some(entry) = index.get(&path) {
            let fi = file_info.as_mut();
            entry.fill_file_info(fi);
            fi.index_number = 0;
            fi.hard_links = 0;

            debug!("open: file_info: {:?}", fi);

            let buffer = if Self::should_buffer_file(&path, entry.is_dir) {
                let mut buffers = self.file_buffers.write().unwrap();
                if let Some(buf) = buffers.get(&path) {
                    Some(buf.clone())
                } else {
                    let data = self.load_file_data(entry);
                    let buf = Arc::new(Mutex::new(FileBuffer {
                        data,
                        dirty: false,
                        deleted: false,
                    }));
                    buffers.insert(path.clone(), buf.clone());
                    Some(buf)
                }
            } else {
                None
            };

            Ok(RemoteFilesystemFileContext {
                path,
                is_dir: entry.is_dir,
                pid: match pid {
                    0 => None,
                    pid => Some(pid),
                },
                buffer,
            })
        } else {
            debug!("open: not found");
            Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn close(&self, context: Self::FileContext) {
        if context.is_dir {
            return;
        }

        if let Some(buf_mutex) = &context.buffer {
            let mut buf = match buf_mutex.lock() {
                Ok(b) => b,
                Err(_) => {
                    warn!("close: failed to lock file buffer for {}", context.path);
                    return;
                }
            };

            if !buf.dirty || buf.deleted {
                return;
            }

            let data = &buf.data;
            let mut index = self.index.write().unwrap();
            if let Some(entry) = index.get_mut(&context.path) {
                let now = current_filetime();
                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = data.len() as u64;

                if !data.is_empty() {
                    let id = self.object_store.put(data);
                    entry.object_id = Some(id);
                } else {
                    entry.object_id = None;
                }

                let updated = entry.clone();
                index.upsert_entry(&context.path, updated);
                drop(index);
                buf.dirty = false;
                self.persist_index();
            }
        }
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> Result<(), FspError> {
        if let Some(ctx) = context {
            debug!("flush: {}", ctx.path);
            let index = self.index.read().unwrap();
            if let Some(entry) = index.get(&ctx.path) {
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
        let mut index = self.index.write().unwrap();
        let entries = index.entries_mut();

        if !entries.contains_key(&parent) {
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        }

        let now = current_filetime();
        let entry = entries.entry(path.clone()).or_insert(MemEntry {
            is_dir,
            object_id: None,
            size: 0,
            attributes: file_attributes,
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        });

        entry.is_dir = is_dir;
        entry.attributes = file_attributes;
        if !is_dir {
            entry.object_id = None;
            entry.size = 0;
        }
        // Update timestamps on create/overwrite
        entry.last_access_time = now;
        entry.last_write_time = now;
        entry.change_time = now;

        let fi = file_info.as_mut();
        entry.fill_file_info(fi);
        fi.index_number = 0;
        fi.hard_links = 0;

        let resulting_is_dir = entry.is_dir;

        drop(index);
        self.persist_index();

        let buffer = if Self::should_buffer_file(&path, resulting_is_dir) && !resulting_is_dir {
            let mut buffers = self.file_buffers.write().unwrap();
            if let Some(buf) = buffers.get(&path) {
                Some(buf.clone())
            } else {
                let buf = Arc::new(Mutex::new(FileBuffer {
                    data: Vec::new(),
                    dirty: false,
                    deleted: false,
                }));
                buffers.insert(path.clone(), buf.clone());
                Some(buf)
            }
        } else {
            None
        };

        Ok(RemoteFilesystemFileContext {
            path,
            is_dir: resulting_is_dir,
            pid: match pid {
                0 => None,
                pid => Some(pid),
            },
            buffer,
        })
    }

    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        if FspCleanupFlags::FspCleanupDelete.is_flagged(flags) {
            if let Some(buf_mutex) = &context.buffer {
                if let Ok(mut buf) = buf_mutex.lock() {
                    buf.deleted = true;
                    buf.dirty = false;
                }
            }

            let path = file_name
                .map(Self::normalize_path)
                .unwrap_or_else(|| context.path.clone());
            info!("cleanup delete: {}", path);

            let mut index = self.index.write().unwrap();
            index.delete_path_recursive(&path);
            drop(index);
            self.persist_index();

            // 删除时清理共享缓冲。
            let mut buffers = self.file_buffers.write().unwrap();
            buffers.remove(&path);
            return;
        }

        // 非删除场景下，Cleanup 表示句柄关闭，此时需要将缓冲内容持久化，
        // 保证后续新的打开可以看到完整数据。
        if let Some(buf_mutex) = &context.buffer {
            let mut buf = match buf_mutex.lock() {
                Ok(b) => b,
                Err(_) => {
                    warn!("cleanup: failed to lock file buffer for {}", context.path);
                    return;
                }
            };

            if !buf.dirty || buf.deleted {
                return;
            }

            let data = &buf.data;
            let mut index = self.index.write().unwrap();
            if let Some(entry) = index.get_mut(&context.path) {
                let now = current_filetime();
                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = data.len() as u64;

                if !data.is_empty() {
                    let id = self.object_store.put(data);
                    entry.object_id = Some(id);
                } else {
                    entry.object_id = None;
                }

                let updated = entry.clone();
                index.upsert_entry(&context.path, updated);
                drop(index);
                buf.dirty = false;
                self.persist_index();
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

        let index = self.index.read().unwrap();
        if let Some(entry) = index.get(&context.path) {
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

        let mut index = self.index.write().unwrap();
        let updated = {
            let entry = index
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
            entry.clone()
        };

        index.upsert_entry(&context.path, updated);
        drop(index);
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

        if let Some(buf_mutex) = &context.buffer {
            let mut buf = buf_mutex
                .lock()
                .map_err(|_| FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;

            let data = &mut buf.data;
            let new_len = new_size as usize;
            if new_len < data.len() {
                data.truncate(new_len);
            } else if new_len > data.len() {
                data.resize(new_len, 0);
            }

            let now = current_filetime();
            let mut index = self.index.write().unwrap();
            let updated = {
                let entry = index
                    .get_mut(&context.path)
                    .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = new_size;

                entry.fill_file_info(file_info);
                entry.clone()
            };
            index.upsert_entry(&context.path, updated);
            drop(index);

            buf.dirty = true;
            // 对缓冲文件，实际落盘由 close() 负责，这里不必强制 snapshot。
            Ok(())
        } else {
            let mut index = self.index.write().unwrap();
            let updated = {
                let data = {
                    let entry = index
                        .get(&context.path)
                        .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;
                    self.load_file_data(entry)
                };
                let entry = index
                    .get_mut(&context.path)
                    .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

                let new_len = new_size as usize;
                let mut new_data = data;
                if new_len < new_data.len() {
                    new_data.truncate(new_len);
                } else if new_len > new_data.len() {
                    new_data.resize(new_len, 0);
                }

                // Update timestamps on size change
                let now = current_filetime();
                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = new_size;

                if !entry.is_dir {
                    if new_len == 0 {
                        entry.object_id = None;
                    } else {
                        let id = self.object_store.put(&new_data);
                        entry.object_id = Some(id);
                    }
                }

                entry.fill_file_info(file_info);
                entry.clone()
            };

            index.upsert_entry(&context.path, updated);
            drop(index);
            self.persist_index();
            Ok(())
        }
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

        if let Some(buf_mutex) = &context.buffer {
            let buf = buf_mutex
                .lock()
                .map_err(|_| FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;
            let data = &buf.data;
            let offset = offset as usize;
            if offset >= data.len() {
                debug!("read: offset out of range");
                return Err(FspError::from(ERROR_HANDLE_EOF));
            }

            let len = buffer.len().min(data.len() - offset);
            buffer[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len as u32)
        } else {
            let index = self.index.read().unwrap();
            let entry = index
                .get(&context.path)
                .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

            let data = self.load_file_data(entry);
            let offset = offset as usize;
            if offset >= data.len() {
                debug!("read: offset out of range");
                return Err(FspError::from(ERROR_HANDLE_EOF));
            }

            let len = buffer.len().min(data.len() - offset);
            buffer[..len].copy_from_slice(&data[offset..offset + len]);

            Ok(len as u32)
        }
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

        if let Some(buf_mutex) = &context.buffer {
            let mut buf = buf_mutex
                .lock()
                .map_err(|_| FspError::from(STATUS_INVALID_DEVICE_REQUEST))?;
            let data = &mut buf.data;

            let write_offset = if write_to_eof {
                data.len()
            } else {
                offset as usize
            };

            if constrained_io {
                if write_offset >= data.len() {
                    return Ok(0);
                }
                let max_len = data.len() - write_offset;
                let write_len = buffer.len().min(max_len);
                data[write_offset..write_offset + write_len].copy_from_slice(&buffer[..write_len]);

                let now = current_filetime();
                let mut index = self.index.write().unwrap();
                let updated = {
                    let entry = index
                        .get_mut(&context.path)
                        .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

                    entry.last_access_time = now;
                    entry.last_write_time = now;
                    entry.change_time = now;
                    entry.size = data.len() as u64;

                    entry.fill_file_info(file_info);
                    entry.clone()
                };
                index.upsert_entry(&context.path, updated);
                drop(index);

                buf.dirty = true;
                // 内容实际落盘由 close() 负责。
                return Ok(write_len as u32);
            }

            let end = write_offset.saturating_add(buffer.len());
            if end > data.len() {
                data.resize(end, 0);
            }
            data[write_offset..write_offset + buffer.len()].copy_from_slice(buffer);

            let now = current_filetime();
            let mut index = self.index.write().unwrap();
            let updated = {
                let entry = index
                    .get_mut(&context.path)
                    .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

                entry.last_access_time = now;
                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = data.len() as u64;

                entry.fill_file_info(file_info);
                entry.clone()
            };
            index.upsert_entry(&context.path, updated);
            drop(index);

            buf.dirty = true;
            // 内容实际落盘由 close() 负责。
            Ok(buffer.len() as u32)
        } else {
            let mut index = self.index.write().unwrap();
            let mut data = {
                let entry = index
                    .get(&context.path)
                    .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;
                self.load_file_data(entry)
            };
            let entry = index
                .get_mut(&context.path)
                .ok_or_else(|| FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))?;

            let write_offset = if write_to_eof {
                data.len()
            } else {
                offset as usize
            };

            if constrained_io {
                if write_offset >= data.len() {
                    return Ok(0);
                }
                let max_len = data.len() - write_offset;
                let write_len = buffer.len().min(max_len);
                data[write_offset..write_offset + write_len].copy_from_slice(&buffer[..write_len]);

                let now = current_filetime();
                entry.last_access_time = now;
                entry.last_write_time = now;
                entry.change_time = now;
                entry.size = data.len() as u64;

                if !data.is_empty() {
                    let id = self.object_store.put(&data);
                    entry.object_id = Some(id);
                } else {
                    entry.object_id = None;
                }

                entry.fill_file_info(file_info);
                let updated = entry.clone();
                index.upsert_entry(&context.path, updated);
                drop(index);
                self.persist_index();
                return Ok(write_len as u32);
            }

            let end = write_offset.saturating_add(buffer.len());
            if end > data.len() {
                data.resize(end, 0);
            }
            data[write_offset..write_offset + buffer.len()].copy_from_slice(buffer);

            let now = current_filetime();
            entry.last_access_time = now;
            entry.last_write_time = now;
            entry.change_time = now;
            entry.size = data.len() as u64;

            if !data.is_empty() {
                let id = self.object_store.put(&data);
                entry.object_id = Some(id);
            } else {
                entry.object_id = None;
            }

            entry.fill_file_info(file_info);
            let updated = entry.clone();
            index.upsert_entry(&context.path, updated);
            drop(index);
            self.persist_index();
            Ok(buffer.len() as u32)
        }
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

        let dir_path = &context.path;
        let index = self.index.read().unwrap();

        // Collect directory entries as a flat list: (name, MemEntry).
        let mut all_entries: Vec<(String, MemEntry)> = Vec::new();

        // "." entry uses the current directory's metadata if available.
        let dot_entry = if let Some(entry) = index.get(dir_path) {
            entry.clone()
        } else {
            let now = current_filetime();
            MemEntry {
                is_dir: true,
                object_id: None,
                size: 0,
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
            }
        };
        all_entries.push((".".to_string(), dot_entry));

        // ".." entry uses the parent directory's metadata if available.
        let parent_path = Self::parent_path(dir_path).unwrap_or_else(|| "\\".to_string());
        let dotdot_entry = if let Some(entry) = index.get(&parent_path) {
            entry.clone()
        } else {
            let now = current_filetime();
            MemEntry {
                is_dir: true,
                object_id: None,
                size: 0,
                attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
            }
        };
        all_entries.push(("..".to_string(), dotdot_entry));

        for (path, entry) in index.entries().iter() {
            if path == dir_path {
                continue;
            }
            if let Some(parent) = Self::parent_path(path) {
                if parent == *dir_path {
                    if let Some(name) = path.rsplit('\\').next() {
                        all_entries.push((name.to_string(), entry.clone()));
                    }
                }
            }
        }

        // Deterministic listing order.
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut cursor = 0;
        let mut found_marker = marker.is_none();

        for (name, entry) in all_entries {
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
            entry.fill_file_info(finfo);

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

        let mut index = self.index.write().unwrap();
        let entries_exist = index.entries().contains_key(&old_path);

        if !entries_exist {
            return Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND));
        }

        if index.entries().contains_key(&new_path) && !replace_if_exists {
            return Err(FspError::from(STATUS_INVALID_DEVICE_REQUEST));
        }

        index.rename_prefix(&old_path, &new_path);
        drop(index);
        self.persist_index();

        Ok(())
    }
}

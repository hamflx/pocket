# 把你的配置文件随身打包带走

> 告别配置同步烦恼：用 Rust 将任意目录透明挂载到云端

## 痛点：配置文件的迁移噩梦

作为程序员，你是否有过这样的经历：

- 换了台新电脑，发现 SSH 密钥、GPG 密钥、各种 dotfiles 又要重新配置一遍
- 公司电脑和家里电脑之间，配置文件永远不同步
- Shell 历史记录只存在本地，换台机器就找不到之前敲过的命令
- 精心调教的 Nushell 配置（包括 zoxide、fnm 等工具的集成），每台机器都要重新配一遍
- 想备份 `~/.ssh` 目录，却又担心上传到云端不安全
- Git 管理 dotfiles？敏感文件不敢提交，非敏感文件又懒得维护

今天，我想分享一个另辟蹊径的解决方案——**Pocket**，一个基于 WinFsp 的虚拟文件系统，让你的配置文件真正"随身携带"。

## 设计理念：透明化的云存储

Pocket 的核心设计理念非常简单：

```
本地目录 ←→ 虚拟文件系统 ←→ S3 对象存储
```

当你把 `~/.ssh` 挂载到 Pocket 上时：

1. **对应用完全透明**：SSH 客户端、Git 等工具完全感知不到任何区别
2. **实时云端同步**：所有文件变更自动同步到 S3
3. **加密存储**：凭证使用 Windows DPAPI 加密，数据安全有保障
4. **多设备同步**：在任何设备上运行 Pocket，配置文件即刻可用

## 核心技术架构

### 1. WinFsp：用户态文件系统的基石

Pocket 基于 [WinFsp](https://winfsp.dev/) 构建，这是 Windows 平台上类似 FUSE 的用户态文件系统框架。通过实现 `FileSystemContext` trait，我们可以完全自定义文件系统的行为：

```rust
impl FileSystemContext for RemoteFilesystem {
    type FileContext = RemoteFilesystemFileContext;

    fn open(&self, file_name: &U16CStr, ...) -> Result<Self::FileContext, FspError> {
        let path = Self::normalize_path(file_name);
        let index = self.index.read().unwrap();
        
        if let Some(entry) = index.get(&path) {
            // 从索引中获取文件元数据
            let buffer = if Self::should_buffer_file(&path, entry.is_dir) {
                let data = self.load_file_data(entry);
                Some(self.file_buffers.get_or_create(&path, || FileBuffer {
                    data,
                    dirty: false,
                    deleted: false,
                }))
            } else {
                None
            };
            
            Ok(RemoteFilesystemFileContext { path, is_dir: entry.is_dir, ... })
        } else {
            Err(FspError::from(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32, FspError> {
        // 从本地缓冲或远程存储读取数据
    }

    fn write(&self, context: &Self::FileContext, buffer: &[u8], offset: u64, ...) -> Result<u32, FspError> {
        // 写入本地缓冲，异步同步到云端
    }
}
```

### 2. 可插拔的存储后端

Pocket 抽象出了两个核心 trait，实现了存储后端的完全可插拔：

```rust
pub trait ObjectStore: Send + Sync {
    fn get(&self, id: &ObjectId) -> Option<Vec<u8>>;
    fn put(&self, data: &[u8]) -> ObjectId;
}

pub trait IndexStore: Send + Sync {
    fn load_latest(&self) -> Option<Vec<u8>>;
    fn save(&self, data: &[u8]);
}
```

基于这两个 trait，我们实现了：

| 后端类型 | ObjectStore | IndexStore | 适用场景 |
|---------|-------------|------------|----------|
| Memory | `InMemoryObjectStore` | `InMemoryIndexStore` | 开发测试 |
| S3 Sync | `S3ObjectStore` | `S3IndexStore` | 小文件、强一致性 |
| S3 Buffered | `BufferedObjectStore` | `BufferedIndexStore` | 大文件、高性能 |

### 3. 内容寻址存储

Pocket 采用内容寻址（Content-Addressable Storage）的设计，文件内容通过 SHA-256 哈希值作为唯一标识：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        ObjectId(bytes)
    }
}
```

这种设计带来几个好处：

- **自动去重**：相同内容只存储一份
- **完整性校验**：读取时可验证数据完整性
- **简化版本管理**：不同版本的文件自然分离

在 S3 中的存储结构如下：

```
bucket/
├── data/
│   ├── a1b2c3d4...  # 文件内容，以 SHA-256 为 key
│   └── e5f6g7h8...
└── index/
    ├── head         # 指向最新索引快照
    └── objects/
        └── i9j0k1l2...  # 索引快照
```

### 4. CRDT 索引：面向分布式的设计

这是 Pocket 最有意思的设计决策之一——使用 [Loro](https://loro.dev/) CRDT 库管理文件索引：

```rust
pub struct LoroIndex {
    entries: HashMap<String, MemEntry>,
    doc: LoroDoc,
}

impl LoroIndex {
    pub fn upsert_entry(&mut self, path: &str, entry: MemEntry) {
        self.entries.insert(path.to_string(), entry.clone());
        self.sync_single_entry(path, &entry);
    }

    fn sync_single_entry(&self, path: &str, entry: &MemEntry) {
        let entries_map = self.doc.get_map("entries");
        let entry_map = entries_map.get_or_create_container(path, LoroMap::new())?;
        Self::write_entry_to_map(&entry_map, entry)?;
    }
}
```

为什么选择 CRDT？

1. **多设备并发安全**：即使两台设备同时修改不同文件，索引也能正确合并
2. **无冲突同步**：不需要复杂的锁机制或冲突解决策略
3. **增量更新**：只同步变化的部分，减少网络开销

每个文件的元数据以嵌套 Map 的形式存储：

```rust
#[derive(Debug, Clone)]
pub struct MemEntry {
    pub is_dir: bool,
    pub object_id: Option<ObjectId>,
    pub size: u64,
    pub attributes: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
}
```

### 5. 凭证安全：DPAPI 加密

将 S3 凭证明文存储在配置文件中？显然不安全。Pocket 使用 Windows Data Protection API (DPAPI) 进行加密：

```rust
#[cfg(windows)]
fn protect_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();

        CryptProtectData(
            &mut in_blob,
            PCWSTR::null(),
            Some(ptr::null()),
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )?;

        // 返回加密后的数据
        Ok(slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec())
    }
}
```

DPAPI 的特点：

- 加密数据绑定到当前 Windows 用户
- 其他用户或其他机器无法解密
- 不需要管理额外的密钥

配置 S3 凭证的命令：

```bash
pocket config-s3 \
  --bucket your-bucket \
  --endpoint https://oss-cn-hangzhou.aliyuncs.com \
  --credentials default \
  --access-key-id YOUR_ACCESS_KEY \
  --secret-access-key YOUR_SECRET_KEY
```

凭证会被加密存储到 `%APPDATA%\hamflx\pocket\credentials\default.bin`。

### 6. 后台服务与开机自启

作为一个日常使用的工具，Pocket 支持安装为后台服务：

```rust
#[cfg(windows)]
fn handle_install() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 复制可执行文件到安装目录
    let installed_exe = install_dir().join("pocket.exe");
    fs::copy(&current_exe, &installed_exe)?;

    // 2. 注册 Windows 启动项
    let key = CURRENT_USER.create("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    key.set_string("Pocket", &format!("\"{}\"", installed_exe.display()))?;

    // 3. 以无窗口模式启动服务
    Command::new(&installed_exe)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;

    Ok(())
}
```

一条命令完成安装：

```bash
pocket install
```

## 性能优化：异步与并发

### 后台 S3 写入

为了不阻塞文件操作，Pocket 实现了异步的 S3 写入机制：

```rust
pub struct S3TaskSender {
    inner: Arc<Mutex<mpsc::Sender<S3BgTask>>>,
}

pub enum S3BgTask {
    PutObject { key: String, data: Vec<u8> },
    DeleteObject { key: String },
    SaveIndex { data: Vec<u8> },
    Shutdown,
}
```

后台工作线程池（默认 10 个并发）负责实际的 S3 操作：

```rust
fn run_s3_background_worker(state: Arc<S3State>, rx: mpsc::Receiver<S3BgTask>) {
    const S3_WORKER_CONCURRENCY: usize = 10;
    
    // 共享任务队列，worker 线程竞争获取任务
    let task_queue: Arc<(Mutex<VecDeque<S3BgTask>>, Condvar)> = ...;
    
    // 启动 worker 线程池
    for i in 0..S3_WORKER_CONCURRENCY {
        std::thread::spawn(move || {
            loop {
                let task = /* 从队列获取任务 */;
                match task {
                    S3BgTask::PutObject { key, data } => {
                        worker_state.upload_object(key, data);
                    }
                    // ...
                }
            }
        });
    }
}
```

### 索引写入防抖

频繁的索引更新会导致大量 S3 写入，Pocket 使用 debounce 机制合并请求：

```rust
fn new(index: Arc<RwLock<LoroIndex>>, store: Arc<dyn IndexStore>) -> Self {
    std::thread::spawn(move || {
        let debounce = Duration::from_millis(200);
        
        while let Ok(()) = rx.recv() {
            let start = Instant::now();
            // 在 200ms 窗口内合并所有请求
            loop {
                if start.elapsed() >= debounce {
                    break;
                }
                match rx.recv_timeout(debounce - start.elapsed()) {
                    Ok(()) => continue,  // 继续合并
                    Err(Timeout) => break,
                    Err(Disconnected) => return,
                }
            }
            
            // 只写入一次最新状态
            let bytes = index.read().unwrap().to_bytes();
            store.save(&bytes);
        }
    });
}
```

## 快速上手

### 安装

1. 安装 [WinFsp](https://winfsp.dev/)
2. 下载或编译 Pocket

```bash
cargo build --release
```

### 配置

创建 `%APPDATA%\hamflx\pocket\config.toml`：

```toml
# 定义 S3 存储后端
[storages.default]
backend = "s3"

[storages.default.s3]
bucket = "your-bucket-name"
region = "cn-hangzhou"
endpoint = "https://oss-cn-hangzhou.aliyuncs.com"
credentials = "default"

# 挂载 ~/.ssh 目录
[[mounts]]
name = "ssh"
mount_path = "~/.ssh"
storage = "default"
prefix = "ssh/"

# 挂载 ~/.gnupg 目录
[[mounts]]
name = "gnupg"
mount_path = "~/.gnupg"
storage = "default"
prefix = "gnupg/"
mode = "buffered"

# 🚀 我的最爱：Nushell 配置目录
# 包含 config.nu、env.nu、历史记录，以及 zoxide/fnm 等工具的配置
[[mounts]]
name = "nushell"
mount_path = "$APPDATA/nushell"
storage = "default"
prefix = "nushell/"
mode = "buffered"
```

挂载 Nushell 配置目录后，你将获得：

- **历史记录同步**：在任何设备上都能找到之前执行过的命令
- **配置文件同步**：`config.nu`、`env.nu` 一处修改，处处生效
- **插件配置同步**：zoxide 的跳转记录、fnm 的 Node 版本管理配置等，无缝漫游

### 运行

```bash
# 配置 S3 凭证（加密存储）
pocket config-s3 --bucket ... --access-key-id ... --secret-access-key ...

# 前台运行（测试）
pocket

# 安装为后台服务（自启动）
pocket install
```

## 总结与展望

Pocket 用 ~1500 行 Rust 代码实现了一个实用的云端虚拟文件系统，核心技术栈包括：

- **WinFsp**：Windows 用户态文件系统框架
- **Loro CRDT**：分布式友好的索引管理
- **AWS SDK for Rust**：S3 对象存储
- **Windows DPAPI**：安全的凭证管理

当前的实现仍有改进空间：

1. **跨平台支持**：基于 FUSE 实现 Linux/macOS 版本
2. **端到端加密**：文件内容加密后再上传
3. **冲突检测**：当前依赖 CRDT 自动合并，可以添加冲突提示
4. **增量同步**：对大文件实现分块上传

如果你也受够了配置文件同步的烦恼，不妨试试这个方案。把你的 dotfiles "打包带走"，从此换电脑不再痛苦！

---

*项目地址：[GitHub - pocket](https://github.com/hamflx/pocket)*

*技术栈：Rust, WinFsp, Loro CRDT, AWS S3*

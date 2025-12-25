use std::sync::{mpsc, Arc, Mutex};

use aws_config;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, warn};

use crate::config::S3Config;
use crate::credentials::load_encrypted_credentials;
use crate::fs_types::ObjectId;
use crate::storage::{IndexStore, ObjectStore, InMemoryObjectStore};

#[derive(Debug)]
pub enum S3BgTask {
    PutObject { key: String, data: Vec<u8> },
    DeleteObject { key: String },
    SaveIndex { data: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct S3TaskSender {
    inner: Arc<Mutex<mpsc::Sender<S3BgTask>>>,
}

impl S3TaskSender {
    pub fn new(state: Arc<S3State>) -> Self {
        let (tx, rx) = mpsc::channel::<S3BgTask>();
        let inner = Arc::new(Mutex::new(tx));

        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("pocket-s3-bg".to_string())
            .spawn(move || run_s3_background_worker(worker_state, rx))
            .expect("failed to spawn S3 background worker");

        S3TaskSender { inner }
    }

    pub fn send(&self, task: S3BgTask) {
        match self.inner.lock() {
            Ok(tx) => {
                if let Err(err) = tx.send(task) {
                    error!("Failed to enqueue S3 background task: {err}");
                }
            }
            Err(err) => {
                error!("Failed to lock S3 task sender: {err}");
            }
        }
    }
}

fn run_s3_background_worker(state: Arc<S3State>, rx: mpsc::Receiver<S3BgTask>) {
    use std::sync::mpsc::TryRecvError;

    info!("S3 background worker started");

    while let Ok(task) = rx.recv() {
        match task {
            S3BgTask::PutObject { key, data } => {
                debug!("S3 bg: put object {key}");
                state.upload_object(key, data);
            }
            S3BgTask::DeleteObject { key } => {
                debug!("S3 bg: delete object {key}");
                state.delete_object(key);
            }
            S3BgTask::SaveIndex { data } => {
                // 合并连续的索引保存请求，只保留最新的那一份。
                let mut latest = data;
                loop {
                    match rx.try_recv() {
                        Ok(S3BgTask::SaveIndex { data }) => {
                            latest = data;
                        }
                        Ok(S3BgTask::PutObject { key, data }) => {
                            debug!("S3 bg: put object {key}");
                            state.upload_object(key, data);
                        }
                        Ok(S3BgTask::DeleteObject { key }) => {
                            debug!("S3 bg: delete object {key}");
                            state.delete_object(key);
                        }
                        Err(TryRecvError::Empty) => {
                            break;
                        }
                        Err(TryRecvError::Disconnected) => {
                            warn!("S3 background worker channel disconnected while coalescing index");
                            break;
                        }
                    }
                }

                let id = ObjectId::from_data(&latest);
                let index_key = state.key_for_index_object(&id);
                state.upload_object(index_key, latest);

                let head_key = state.key_for_index_head();
                let head_contents = id.to_hex().into_bytes();
                state.upload_object(head_key, head_contents);
            }
        }
    }

    info!("S3 background worker exiting");
}

#[derive(Debug)]
pub struct S3State {
    client: S3Client,
    bucket: String,
    key_prefix: String,
    runtime: Arc<Runtime>,
}

impl S3State {
    pub fn new(cfg: &S3Config, prefix: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
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

    pub fn key_for_data(&self, id: &ObjectId) -> String {
        format!("{}data/{}", self.key_prefix, id.to_hex())
    }

    pub fn key_for_index_head(&self) -> String {
        format!("{}index/head", self.key_prefix)
    }

    pub fn key_for_index_object(&self, id: &ObjectId) -> String {
        format!("{}index/objects/{}", self.key_prefix, id.to_hex())
    }

    pub fn get_object_bytes(&self, key: String) -> Option<Vec<u8>> {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let rt = self.runtime.clone();

        rt.block_on(async move {
            match client.get_object().bucket(&bucket).key(&key).send().await {
                Ok(output) => match output.body.collect().await {
                    Ok(aggregated) => Some(aggregated.into_bytes().to_vec()),
                    Err(err) => {
                        error!("S3 get_object body error for {}: {err}", key);
                        None
                    }
                },
                Err(err) => {
                    error!("S3 get_object error for {}: {err}", key);
                    None
                }
            }
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

    pub fn path_to_key(&self, path: &str) -> Option<String> {
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

    pub fn upload_object(&self, key: String, data: Vec<u8>) {
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

    pub fn delete_object(&self, key: String) {
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let rt = self.runtime.clone();

        rt.block_on(async move {
            if let Err(err) = client.delete_object().bucket(bucket).key(key).send().await {
                error!("S3 delete_object error: {err}");
            }
        });
    }

    pub fn key_to_path(&self, key: &str) -> Option<String> {
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

    pub fn load_all_objects(&self) -> Vec<(String, Vec<u8>)> {
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

#[derive(Debug)]
pub struct S3ObjectStore {
    state: Arc<S3State>,
}

impl S3ObjectStore {
    pub fn new(state: Arc<S3State>) -> Self {
        S3ObjectStore { state }
    }
}

impl ObjectStore for S3ObjectStore {
    fn get(&self, id: &ObjectId) -> Option<Vec<u8>> {
        let key = self.state.key_for_data(id);
        self.state.get_object_bytes(key)
    }

    fn put(&self, data: &[u8]) -> ObjectId {
        let id = ObjectId::from_data(data);
        let key = self.state.key_for_data(&id);
        self.state.upload_object(key, data.to_vec());
        id
    }
}

#[derive(Debug)]
pub struct S3IndexStore {
    state: Arc<S3State>,
}

impl S3IndexStore {
    pub fn new(state: Arc<S3State>) -> Self {
        S3IndexStore { state }
    }
}

impl IndexStore for S3IndexStore {
    fn load_latest(&self) -> Option<Vec<u8>> {
        let head_key = self.state.key_for_index_head();
        let head_bytes = self.state.get_object_bytes(head_key)?;
        let head_str = String::from_utf8(head_bytes).ok()?;
        let head_str = head_str.trim();
        let id = ObjectId::from_hex(head_str)?;
        let index_key = self.state.key_for_index_object(&id);
        self.state.get_object_bytes(index_key)
    }

    fn save(&self, data: &[u8]) {
        let id = ObjectId::from_data(data);
        let index_key = self.state.key_for_index_object(&id);
        self.state.upload_object(index_key, data.to_vec());

        let head_key = self.state.key_for_index_head();
        let head_contents = id.to_hex().into_bytes();
        self.state.upload_object(head_key, head_contents);
    }
}

#[derive(Debug)]
pub struct BufferedObjectStore {
    local: InMemoryObjectStore,
    state: Arc<S3State>,
    task_sender: S3TaskSender,
}

impl BufferedObjectStore {
    pub fn new(state: Arc<S3State>, task_sender: S3TaskSender) -> Self {
        BufferedObjectStore {
            local: InMemoryObjectStore::new(),
            state,
            task_sender,
        }
    }
}

impl ObjectStore for BufferedObjectStore {
    fn get(&self, id: &ObjectId) -> Option<Vec<u8>> {
        // 先查本地缓存
        if let Some(data) = self.local.get(id) {
            return Some(data);
        }

        // 未命中则同步从 S3 读取一次并缓存
        let key = self.state.key_for_data(id);
        if let Some(bytes) = self.state.get_object_bytes(key) {
            let generated_id = self.local.put(&bytes);
            if &generated_id != id {
                warn!(
                    "BufferedObjectStore: ObjectId mismatch after caching (expected={}, actual={})",
                    id, generated_id
                );
            }
            Some(bytes)
        } else {
            None
        }
    }

    fn put(&self, data: &[u8]) -> ObjectId {
        let id = self.local.put(data);
        let key = self.state.key_for_data(&id);
        self.task_sender
            .send(S3BgTask::PutObject { key, data: data.to_vec() });
        id
    }
}

#[derive(Debug)]
pub struct BufferedIndexStore {
    state: Arc<S3State>,
    task_sender: S3TaskSender,
}

impl BufferedIndexStore {
    pub fn new(state: Arc<S3State>, task_sender: S3TaskSender) -> Self {
        BufferedIndexStore { state, task_sender }
    }
}

impl IndexStore for BufferedIndexStore {
    fn load_latest(&self) -> Option<Vec<u8>> {
        // 与 S3IndexStore 相同的加载逻辑：从 head 读取最新快照。
        let head_key = self.state.key_for_index_head();
        let head_bytes = self.state.get_object_bytes(head_key)?;
        let head_str = String::from_utf8(head_bytes).ok()?;
        let head_str = head_str.trim();
        let id = ObjectId::from_hex(head_str)?;
        let index_key = self.state.key_for_index_object(&id);
        self.state.get_object_bytes(index_key)
    }

    fn save(&self, data: &[u8]) {
        // 仅将保存请求排入后台队列，实际写入在后台 worker 中合并处理。
        self.task_sender
            .send(S3BgTask::SaveIndex { data: data.to_vec() });
    }
}

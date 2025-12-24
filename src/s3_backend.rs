use std::sync::Arc;

use aws_config;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::primitives::ByteStream;
use tokio::runtime::Runtime;
use tracing::{error, info, warn};

use crate::config::S3Config;
use crate::credentials::load_encrypted_credentials;
use crate::fs_types::ObjectId;
use crate::storage::{IndexStore, ObjectStore};

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


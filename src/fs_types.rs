use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use winfsp::filesystem::FileInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(ObjectId(arr))
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl MemEntry {
    /// Fill a FileInfo struct with this entry's metadata.
    pub fn fill_file_info(&self, file_info: &mut FileInfo) {
        file_info.file_attributes = self.attributes;
        if self.is_dir {
            file_info.file_size = 0;
            file_info.allocation_size = 0;
        } else {
            let size = self.size;
            file_info.file_size = size;
            file_info.allocation_size = size;
        }
        file_info.creation_time = self.creation_time;
        file_info.last_access_time = self.last_access_time;
        file_info.last_write_time = self.last_write_time;
        file_info.change_time = self.change_time;
    }
}


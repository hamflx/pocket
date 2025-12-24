use std::collections::HashMap;
use std::sync::RwLock;

use crate::fs_types::ObjectId;

pub trait ObjectStore: Send + Sync {
    fn get(&self, id: &ObjectId) -> Option<Vec<u8>>;
    fn put(&self, data: &[u8]) -> ObjectId;
}

pub trait IndexStore: Send + Sync {
    fn load_latest(&self) -> Option<Vec<u8>>;
    fn save(&self, data: &[u8]);
}

#[derive(Debug)]
pub struct InMemoryObjectStore {
    objects: RwLock<HashMap<ObjectId, Vec<u8>>>,
}

impl InMemoryObjectStore {
    pub fn new() -> Self {
        InMemoryObjectStore {
            objects: RwLock::new(HashMap::new()),
        }
    }
}

impl ObjectStore for InMemoryObjectStore {
    fn get(&self, id: &ObjectId) -> Option<Vec<u8>> {
        let objects = self.objects.read().unwrap();
        objects.get(id).cloned()
    }

    fn put(&self, data: &[u8]) -> ObjectId {
        let id = ObjectId::from_data(data);
        let mut objects = self.objects.write().unwrap();
        objects.insert(id, data.to_vec());
        id
    }
}

#[derive(Debug)]
pub struct InMemoryIndexStore {
    data: RwLock<Option<Vec<u8>>>,
}

impl InMemoryIndexStore {
    pub fn new() -> Self {
        InMemoryIndexStore {
            data: RwLock::new(None),
        }
    }
}

impl IndexStore for InMemoryIndexStore {
    fn load_latest(&self) -> Option<Vec<u8>> {
        let data = self.data.read().unwrap();
        data.clone()
    }

    fn save(&self, data: &[u8]) {
        let mut slot = self.data.write().unwrap();
        *slot = Some(data.to_vec());
    }
}


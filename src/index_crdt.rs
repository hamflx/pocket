use std::collections::HashMap;

use crate::fs_types::ObjectId;
use crate::MemEntry;
use loro::{ExportMode, LoroDoc, LoroMap, LoroValue};
use tracing::{error, warn};

/// LoroIndex 封装了基于路径的索引视图以及底层 CRDT 文档。
/// 运行时使用 HashMap 做快速视图，同时维护一个 LoroDoc，在每次索引修改时同步。
///
/// 新设计：
/// - 不再将整个 HashMap 序列化为一段 JSON 文本覆盖写入 Text 容器；
/// - 使用一个 root `Map` 容器 `"entries"`，key 是路径，value 是一个嵌套的 `Map` 容器，字段对齐 `MemEntry`；
/// - 每次索引更新只对应若干 Map insert/delete 操作，避免巨大的单次 content_len 导致 loro 计数溢出。
#[derive(Debug)]
pub struct LoroIndex {
    entries: HashMap<String, MemEntry>,
    doc: LoroDoc,
}

impl LoroIndex {
    /// 创建一个空索引，并初始化根目录。
    pub fn new_empty(now: u64, root_attributes: u32) -> Self {
        let mut entries = HashMap::new();
        let root = MemEntry {
            is_dir: true,
            object_id: None,
            size: 0,
            attributes: root_attributes,
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
        };
        entries.insert("\\".to_string(), root.clone());

        let doc = LoroDoc::new();
        let index = LoroIndex { entries, doc };
        index.sync_root_entry();
        index
    }

    /// 从持久化字节恢复索引。
    ///
    /// 仅支持新的 CRDT 结构：
    /// - 根容器 `"entries"` 为一个 Map；
    /// - 其中每个 value 为一个 Map 容器，字段对齐 `MemEntry`。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let doc = LoroDoc::from_snapshot(bytes)?;
        let entries_map = doc.get_map("entries");

        let mut entries: HashMap<String, MemEntry> = HashMap::new();

        // 仅解析 `"entries"` Map 中的嵌套 Map 容器。
        entries_map.for_each(|key, v| match v {
            loro::ValueOrContainer::Container(container) => {
                match container.into_map() {
                    Ok(entry_map) => {
                        match Self::mem_entry_from_map(&entry_map) {
                            Some(entry) => {
                                entries.insert(key.to_string(), entry);
                            }
                            None => {
                                warn!("Failed to decode MemEntry map for key {key}");
                            }
                        }
                    }
                    Err(c) => {
                        warn!(
                            "Unexpected non-map container type in Loro index map for key {key}: {:?}",
                            c
                        );
                    }
                }
            }
            loro::ValueOrContainer::Value(value) => {
                warn!(
                    "Unexpected value (non-container) in Loro index map for key {key}: {:?}",
                    value
                );
            }
        });

        if entries.is_empty() {
            // 没有任何条目视为损坏，让调用方回退到 new_empty。
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Loro index snapshot has no entries",
            )
            .into());
        }

        Ok(LoroIndex { entries, doc })
    }

    /// 将当前索引状态序列化为字节，写入底层存储。
    /// 使用 loro-rs 的快照导出整个文档。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.doc
            .export(ExportMode::Snapshot)
            .expect("export LoroDoc snapshot for index")
    }

    pub fn get(&self, path: &str) -> Option<&MemEntry> {
        self.entries.get(path)
    }

    /// 是否存在指定路径。
    pub fn contains_path(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    /// 只读遍历所有索引项。
    pub fn iter(&self) -> impl Iterator<Item = (&String, &MemEntry)> {
        self.entries.iter()
    }

    /// 插入或更新单个条目，同时更新 CRDT Map。
    pub fn upsert_entry(&mut self, path: &str, entry: MemEntry) {
        let entry_clone = entry.clone();
        self.entries.insert(path.to_string(), entry);
        self.sync_single_entry(path, &entry_clone);
    }

    /// 在内部安全地更新现有条目，并同步到 CRDT。
    /// 如果路径不存在，返回 false。
    pub fn update_entry<F>(&mut self, path: &str, f: F) -> bool
    where
        F: FnOnce(&mut MemEntry),
    {
        if let Some(entry) = self.entries.get_mut(path) {
            f(entry);
            let snapshot = entry.clone();
            self.sync_single_entry(path, &snapshot);
            true
        } else {
            false
        }
    }

    /// 递归删除指定路径及其子路径，对应地从 CRDT Map 中删除。
    pub fn delete_path_recursive(&mut self, path: &str) {
        let mut to_delete = Vec::new();
        for k in self.entries.keys() {
            if k == path || k.starts_with(&(path.to_string() + "\\")) {
                if k != "\\" {
                    to_delete.push(k.clone());
                }
            }
        }

        let map = self.doc.get_map("entries");
        for k in &to_delete {
            if let Err(err) = map.delete(k) {
                error!("Failed to delete key {k} from Loro index map: {err}");
            }
        }

        for k in to_delete {
            self.entries.remove(&k);
        }
    }

    /// 重命名前缀：将 old_prefix 开头的所有路径移动到 new_prefix。
    pub fn rename_prefix(&mut self, old_prefix: &str, new_prefix: &str) {
        let mut moved = Vec::new();
        for (k, v) in self.entries.iter() {
            if k == old_prefix || k.starts_with(&(old_prefix.to_string() + "\\")) {
                let suffix = &k[old_prefix.len()..];
                let new_key = format!("{}{}", new_prefix, suffix);
                moved.push((k.clone(), new_key, v.clone()));
            }
        }

        let map = self.doc.get_map("entries");
        for (old_k, new_k, entry) in moved {
            if let Err(err) = map.delete(&old_k) {
                error!("Failed to delete old key {old_k} from Loro index map during rename: {err}");
            }

            self.entries.remove(&old_k);
            self.entries.insert(new_k.clone(), entry.clone());

            // 为新路径写入对应的嵌套 Map。
            self.sync_single_entry(&new_k, &entry);
        }
    }

    /// 将根目录条目同步到 CRDT 文档中。
    fn sync_root_entry(&self) {
        if let Some(root) = self.entries.get("\\") {
            self.sync_single_entry("\\", root);
        }
    }

    /// 将单个 entry 同步写入 Loro `"entries"` Map。
    fn sync_single_entry(&self, path: &str, entry: &MemEntry) {
        let entries_map = self.doc.get_map("entries");
        let entry_map = match entries_map.get_or_create_container(path, LoroMap::new()) {
            Ok(m) => m,
            Err(err) => {
                error!("Failed to get_or_create entry map for {path}: {err}");
                return;
            }
        };

        if let Err(err) = Self::write_entry_to_map(&entry_map, entry) {
            error!("Failed to write MemEntry fields for {path}: {err}");
        }
    }

    /// 从 LoroMap 读取一个 MemEntry。
    fn mem_entry_from_map(map: &LoroMap) -> Option<MemEntry> {
        fn read_bool(map: &LoroMap, key: &str) -> Option<bool> {
            let v = map.get(key)?;
            let v = v.into_value().ok()?;
            match v {
                LoroValue::Bool(b) => Some(b),
                _ => None,
            }
        }

        fn read_i64(map: &LoroMap, key: &str) -> Option<i64> {
            let v = map.get(key)?;
            let v = v.into_value().ok()?;
            match v {
                LoroValue::I64(x) => Some(x),
                _ => None,
            }
        }

        fn read_u64(map: &LoroMap, key: &str) -> Option<u64> {
            read_i64(map, key).map(|v| v as u64)
        }

        fn read_string(map: &LoroMap, key: &str) -> Option<String> {
            let v = map.get(key)?;
            let v = v.into_value().ok()?;
            match v {
                LoroValue::String(s) => Some(s.unwrap()),
                _ => None,
            }
        }

        let is_dir = read_bool(map, "is_dir")?;
        let size = read_u64(map, "size")?;
        let attributes = read_u64(map, "attributes")? as u32;
        let creation_time = read_u64(map, "creation_time")?;
        let last_access_time = read_u64(map, "last_access_time")?;
        let last_write_time = read_u64(map, "last_write_time")?;
        let change_time = read_u64(map, "change_time")?;

        let object_id = match read_string(map, "object_id") {
            Some(s) if !s.is_empty() => ObjectId::from_hex(&s),
            _ => None,
        };

        Some(MemEntry {
            is_dir,
            object_id,
            size,
            attributes,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
        })
    }

    /// 将一个 MemEntry 写入到嵌套 Map 中。
    fn write_entry_to_map(map: &LoroMap, entry: &MemEntry) -> loro::LoroResult<()> {
        map.insert("is_dir", entry.is_dir)?;
        map.insert("size", entry.size as i64)?;
        map.insert("attributes", entry.attributes as i64)?;
        map.insert("creation_time", entry.creation_time as i64)?;
        map.insert("last_access_time", entry.last_access_time as i64)?;
        map.insert("last_write_time", entry.last_write_time as i64)?;
        map.insert("change_time", entry.change_time as i64)?;

        if let Some(id) = entry.object_id {
            map.insert("object_id", id.to_hex())?;
        } else {
            map.insert("object_id", LoroValue::Null)?;
        }

        Ok(())
    }
}

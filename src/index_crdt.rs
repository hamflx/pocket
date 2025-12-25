use std::collections::HashMap;

use crate::MemEntry;
use loro::{ExportMode, LoroDoc};
use serde_json;

/// LoroIndex 封装了基于路径的索引视图以及底层 CRDT 文档。
/// 运行时使用 HashMap 做快速视图，同时维护一个 LoroDoc，在每次索引修改时同步。
#[derive(Debug)]
pub struct LoroIndex {
    entries: HashMap<String, MemEntry>,
    doc: LoroDoc,
}

impl LoroIndex {
    /// 创建一个空索引，并初始化根目录。
    pub fn new_empty(now: u64, root_attributes: u32) -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            "\\".to_string(),
            MemEntry {
                is_dir: true,
                object_id: None,
                size: 0,
                attributes: root_attributes,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
            },
        );

        let doc = LoroDoc::new();
        let index = LoroIndex { entries, doc };
        index.sync_doc_from_entries();
        index
    }

    /// 从持久化字节恢复索引。
    /// 字节应当是通过 `LoroDoc::export(ExportMode::Snapshot)` 导出的快照。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let doc = LoroDoc::from_snapshot(bytes)?;
        let text = doc.get_text("index");
        let json_str = text.to_string();
        let entries = if json_str.trim().is_empty() {
            HashMap::new()
        } else {
            serde_json::from_str(&json_str)?
        };

        Ok(LoroIndex { entries, doc })
    }

    /// 将当前索引状态序列化为字节，写入底层存储。
    /// 使用 loro-rs 的快照导出整个文档。
    pub fn to_bytes(&self) -> Vec<u8> {
        self.doc
            .export(ExportMode::Snapshot)
            .expect("export LoroDoc snapshot for index")
    }

    pub fn entries(&self) -> &HashMap<String, MemEntry> {
        &self.entries
    }

    pub fn entries_mut(&mut self) -> &mut HashMap<String, MemEntry> {
        &mut self.entries
    }

    pub fn get(&self, path: &str) -> Option<&MemEntry> {
        self.entries.get(path)
    }

    pub fn get_mut(&mut self, path: &str) -> Option<&mut MemEntry> {
        self.entries.get_mut(path)
    }

    pub fn upsert_entry(&mut self, path: &str, entry: MemEntry) {
        self.entries.insert(path.to_string(), entry);
        self.sync_doc_from_entries();
    }

    pub fn delete_path_recursive(&mut self, path: &str) {
        let mut to_delete = Vec::new();
        for k in self.entries.keys() {
            if k == path || k.starts_with(&(path.to_string() + "\\")) {
                if k != "\\" {
                    to_delete.push(k.clone());
                }
            }
        }

        for k in to_delete {
            self.entries.remove(&k);
        }

        self.sync_doc_from_entries();
    }

    pub fn rename_prefix(&mut self, old_prefix: &str, new_prefix: &str) {
        let mut moved = Vec::new();
        for (k, v) in self.entries.iter() {
            if k == old_prefix || k.starts_with(&(old_prefix.to_string() + "\\")) {
                let suffix = &k[old_prefix.len()..];
                let new_key = format!("{}{}", new_prefix, suffix);
                moved.push((k.clone(), new_key, v.clone()));
            }
        }

        for (old_k, new_k, entry) in moved {
            self.entries.remove(&old_k);
            self.entries.insert(new_k, entry);
        }

        self.sync_doc_from_entries();
    }

    /// 将当前 entries 的内容覆盖写回到 Loro 文档中的 "index" 文本容器。
    fn sync_doc_from_entries(&self) {
        let text = self.doc.get_text("index");

        // 清空旧内容
        let len = text.len_unicode();
        if len > 0 {
            // 忽略错误，尽量保持一致
            let _ = text.delete(0, len);
        }

        if self.entries.is_empty() {
            return;
        }

        let json = serde_json::to_string(&self.entries)
            .expect("serialize index entries to JSON string");
        if !json.is_empty() {
            let _ = text.insert(0, &json);
        }
    }
}

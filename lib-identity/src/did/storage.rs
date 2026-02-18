// packages/lib-identity/src/did/storage.rs
// DID document storage backends (Phase 1 baseline: memory + filesystem)

use super::DidDocument;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

enum DidStore {
    Memory {
        docs: HashMap<String, DidDocument>,
    },
    FileSystem {
        dir: PathBuf,
        cache: HashMap<String, (DidDocument, u64)>,
        cache_ttl_secs: u64,
    },
}

pub fn store_did_document(document: DidDocument) -> Result<(), String> {
    let store = did_store();
    let mut store = store.write().map_err(|_| "DID store poisoned".to_string())?;
    store.store(document)
}

pub fn resolve_did_document(did: &str) -> Result<DidDocument, String> {
    let store = did_store();
    let mut store = store.write().map_err(|_| "DID store poisoned".to_string())?;
    store.resolve(did)
}

pub fn set_did_store_dir(dir: &str) -> Result<(), String> {
    let store = did_store();
    let mut store = store.write().map_err(|_| "DID store poisoned".to_string())?;
    let dir_path = PathBuf::from(dir);
    fs::create_dir_all(&dir_path).map_err(|e| format!("Failed to create DID store dir: {}", e))?;
    *store = DidStore::FileSystem {
        dir: dir_path,
        cache: HashMap::new(),
        cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
    };
    Ok(())
}

pub fn set_did_store_memory() -> Result<(), String> {
    let store = did_store();
    let mut store = store.write().map_err(|_| "DID store poisoned".to_string())?;
    *store = DidStore::Memory {
        docs: HashMap::new(),
    };
    Ok(())
}

impl DidStore {
    fn store(&mut self, document: DidDocument) -> Result<(), String> {
        match self {
            DidStore::Memory { docs } => {
                docs.insert(document.id.clone(), document);
                Ok(())
            }
            DidStore::FileSystem { dir, cache, .. } => {
                let did = document.id.clone();
                let path = did_doc_path(dir, &did);
                write_json_atomic(&path, &document)?;
                cache.insert(did, (document, current_unix_timestamp()?));
                Ok(())
            }
        }
    }

    fn resolve(&mut self, did: &str) -> Result<DidDocument, String> {
        match self {
            DidStore::Memory { docs } => docs
                .get(did)
                .cloned()
                .ok_or_else(|| format!("DID not found: {}", did)),
            DidStore::FileSystem {
                dir,
                cache,
                cache_ttl_secs,
            } => {
                if let Some((cached, cached_at)) = cache.get(did) {
                    let now = current_unix_timestamp()?;
                    if now.saturating_sub(*cached_at) <= *cache_ttl_secs {
                        return Ok(cached.clone());
                    }
                }

                let path = did_doc_path(dir, did);
                let doc = read_json(&path)?;
                cache.insert(did.to_string(), (doc.clone(), current_unix_timestamp()?));
                Ok(doc)
            }
        }
    }
}

fn did_doc_path(dir: &Path, did: &str) -> PathBuf {
    let safe = did.replace(':', "_");
    dir.join(format!("{}.json", safe))
}

fn write_json_atomic(path: &Path, doc: &DidDocument) -> Result<(), String> {
    let tmp_path = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(doc)
        .map_err(|e| format!("Failed to serialize DID document: {}", e))?;
    fs::write(&tmp_path, data).map_err(|e| format!("Failed to write DID document: {}", e))?;
    fs::rename(&tmp_path, path).map_err(|e| format!("Failed to finalize DID document: {}", e))?;
    Ok(())
}

fn read_json(path: &Path) -> Result<DidDocument, String> {
    let bytes = fs::read(path).map_err(|e| format!("Failed to read DID document: {}", e))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to parse DID document: {}", e))?;
    serde_json::from_value(value).map_err(|e| format!("Invalid DID document: {}", e))
}

fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "System time before Unix epoch".to_string())
}

fn did_store() -> &'static RwLock<DidStore> {
    static DID_STORE: OnceLock<RwLock<DidStore>> = OnceLock::new();
    DID_STORE.get_or_init(|| {
        RwLock::new(DidStore::Memory {
            docs: HashMap::new(),
        })
    })
}


//! Web4 deploy manifest: canonical, signed, and verifiable.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployMode {
    Spa,
    Static,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mime_type: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployManifest {
    pub version: u8,
    pub domain: String,
    pub mode: DeployMode,
    pub files: Vec<FileEntry>,
    pub root_hash: [u8; 32],
    pub total_size: u64,
    pub deployed_at: u64,
    pub author_did: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployManifestUnsigned {
    pub version: u8,
    pub domain: String,
    pub mode: DeployMode,
    pub files: Vec<FileEntry>,
    pub root_hash: [u8; 32],
    pub total_size: u64,
    pub deployed_at: u64,
    pub author_did: String,
}

pub fn normalize_manifest_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(anyhow!("Path cannot be empty"));
    }

    let raw_path = Path::new(path);
    if raw_path.is_absolute() {
        return Err(anyhow!("Path must be relative"));
    }

    let mut parts = Vec::new();
    for component in raw_path.components() {
        match component {
            std::path::Component::Normal(p) => parts.push(p.to_string_lossy().to_string()),
            std::path::Component::CurDir => {}
            _ => return Err(anyhow!("Path contains invalid components")),
        }
    }

    if parts.is_empty() {
        return Err(anyhow!("Path must contain at least one component"));
    }

    Ok(parts.join("/"))
}

pub fn canonicalize_file_entries(mut files: Vec<FileEntry>) -> Result<Vec<FileEntry>> {
    let mut seen = HashSet::new();
    for entry in &mut files {
        let normalized = normalize_manifest_path(&entry.path)?;
        if !seen.insert(normalized.clone()) {
            return Err(anyhow!("Duplicate path in manifest: {}", normalized));
        }
        entry.path = normalized;
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

pub fn ensure_canonical_file_list(files: &[FileEntry]) -> Result<()> {
    let mut seen = HashSet::new();
    let mut prev = None::<&str>;
    for entry in files {
        let normalized = normalize_manifest_path(&entry.path)?;
        if normalized != entry.path {
            return Err(anyhow!("Non-canonical path in manifest: {}", entry.path));
        }
        if !seen.insert(&entry.path) {
            return Err(anyhow!("Duplicate path in manifest: {}", entry.path));
        }
        if let Some(prev_path) = prev {
            if prev_path > entry.path.as_str() {
                return Err(anyhow!("Manifest file list is not sorted"));
            }
        }
        prev = Some(entry.path.as_str());
    }

    Ok(())
}

pub fn compute_root_hash(files: &[FileEntry]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for entry in files {
        hasher.update(entry.path.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(entry.hash.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(entry.mime_type.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&entry.size.to_le_bytes());
        hasher.update(&[0u8]);
    }
    *hasher.finalize().as_bytes()
}

pub fn manifest_unsigned_bytes(manifest: &DeployManifest) -> Result<Vec<u8>> {
    let unsigned = DeployManifestUnsigned {
        version: manifest.version,
        domain: manifest.domain.clone(),
        mode: manifest.mode,
        files: manifest.files.clone(),
        root_hash: manifest.root_hash,
        total_size: manifest.total_size,
        deployed_at: manifest.deployed_at,
        author_did: manifest.author_did.clone(),
    };
    Ok(serde_json::to_vec(&unsigned)?)
}

pub fn manifest_unsigned_bytes_from_parts(
    version: u8,
    domain: String,
    mode: DeployMode,
    files: Vec<FileEntry>,
    root_hash: [u8; 32],
    total_size: u64,
    deployed_at: u64,
    author_did: String,
) -> Result<Vec<u8>> {
    let unsigned = DeployManifestUnsigned {
        version,
        domain,
        mode,
        files,
        root_hash,
        total_size,
        deployed_at,
        author_did,
    };
    Ok(serde_json::to_vec(&unsigned)?)
}

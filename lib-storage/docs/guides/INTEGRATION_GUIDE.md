<<<<<<< HEAD
# ZHTP Storage Integration Guide

This comprehensive integration guide shows how to integrate ZHTP Unified Storage System into various types of applications, from simple web apps to complex distributed systems.

##  Integration Overview

The ZHTP Storage System can be integrated into:
- **Web Applications**: Browser-based apps with backend storage
- **Desktop Applications**: Native applications with local and distributed storage
- **Server Applications**: Backend services requiring distributed storage
- **Mobile Applications**: Through FFI bindings (future development)
- **Microservices**: Distributed architectures with shared storage

##  Web Application Integration

### Backend API Server Integration

```rust
// main.rs - Web server with ZHTP storage
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use lib_storage::*;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    user_sessions: Arc<RwLock<HashMap<String, ZhtpIdentity>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize ZHTP storage
    let config = UnifiedStorageConfig::default();
    let storage = UnifiedStorageSystem::new(config).await?;
    
    let app_state = AppState {
        storage: Arc::new(RwLock::new(storage)),
        user_sessions: Arc::new(RwLock::new(HashMap::new())),
    };
    
    // Create API routes
    let app = Router::new()
        .route("/api/upload", post(upload_file))
        .route("/api/download/:hash", get(download_file))
        .route("/api/search", get(search_files))
        .route("/api/user/:user_id/files", get(get_user_files))
        .route("/api/stats", get(get_system_stats))
        .with_state(app_state);
    
    // Start server
    println!(" ZHTP Storage API Server starting on http://localhost:3000");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

#[derive(Deserialize)]
struct UploadRequest {
    filename: String,
    content: String, // Base64 encoded
    description: Option<String>,
    tags: Option<Vec<String>>,
    public: Option<bool>,
}

#[derive(Serialize)]
struct UploadResponse {
    success: bool,
    content_hash: Option<String>,
    message: String,
}

async fn upload_file(
    State(state): State<AppState>,
    Json(request): Json<UploadRequest>
) -> Result<Json<UploadResponse>, StatusCode> {
    
    // Decode content
    let content = match base64::decode(&request.content) {
        Ok(data) => data,
        Err(_) => return Ok(Json(UploadResponse {
            success: false,
            content_hash: None,
            message: "Invalid base64 content".to_string(),
        })),
    };
    
    // Create a default user identity (in production, authenticate user)
    let user_identity = create_default_user_identity();
    
    // Create upload request
    let upload_req = lib_storage::UploadRequest {
        content,
        filename: request.filename.clone(),
        mime_type: detect_mime_type(&request.filename),
        description: request.description.unwrap_or_default(),
        tags: request.tags.unwrap_or_default(),
        encrypt: false,
        compress: true,
        access_control: AccessControlSettings {
            public_read: request.public.unwrap_or(false),
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 30,
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
        },
    };
    
    // Upload to ZHTP storage
    let mut storage = state.storage.write().await;
    match storage.upload_content(upload_req, user_identity).await {
        Ok(content_hash) => {
            Ok(Json(UploadResponse {
                success: true,
                content_hash: Some(hex::encode(content_hash.as_bytes())),
                message: format!("File {} uploaded successfully", request.filename),
            }))
        }
        Err(e) => {
            Ok(Json(UploadResponse {
                success: false,
                content_hash: None,
                message: format!("Upload failed: {}", e),
            }))
        }
    }
}

async fn download_file(
    State(state): State<AppState>,
    Path(hash): Path<String>
) -> Result<Vec<u8>, StatusCode> {
    
    // Parse content hash
    let content_hash = match hex::decode(&hash) {
        Ok(bytes) => Hash::from_bytes(&bytes),
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    
    // Create download request
    let user_identity = create_default_user_identity();
    let download_req = DownloadRequest {
        content_hash,
        requester: user_identity,
        access_proof: None,
    };
    
    // Download from ZHTP storage
    let mut storage = state.storage.write().await;
    match storage.download_content(download_req).await {
        Ok(content) => Ok(content),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    tags: Option<String>,
    content_type: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct SearchResponse {
    results: Vec<FileInfo>,
    total: usize,
}

#[derive(Serialize)]
struct FileInfo {
    hash: String,
    filename: String,
    size: u64,
    content_type: String,
    description: String,
    tags: Vec<String>,
    created_at: u64,
}

async fn search_files(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>
) -> Result<Json<SearchResponse>, StatusCode> {
    
    let user_identity = create_default_user_identity();
    
    let search_query = SearchQuery {
        keywords: params.q.map(|q| vec![q]).unwrap_or_default(),
        content_type: params.content_type,
        tags: params.tags.map(|t| t.split(',').map(|s| s.to_string()).collect()).unwrap_or_default(),
        owner: None,
        date_range: None,
        size_range: None,
        limit: params.limit.unwrap_or(10),
    };
    
    let storage = state.storage.read().await;
    match storage.search_content(search_query, user_identity).await {
        Ok(results) => {
            let file_infos: Vec<FileInfo> = results.into_iter().map(|metadata| {
                FileInfo {
                    hash: hex::encode(metadata.hash.as_bytes()),
                    filename: metadata.filename,
                    size: metadata.size,
                    content_type: metadata.content_type,
                    description: metadata.description,
                    tags: metadata.tags,
                    created_at: metadata.created_at,
                }
            }).collect();
            
            let total = file_infos.len();
            
            Ok(Json(SearchResponse {
                results: file_infos,
                total,
            }))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_system_stats(
    State(state): State<AppState>
) -> Result<Json<serde_json::Value>, StatusCode> {
    
    let mut storage = state.storage.write().await;
    match storage.get_statistics().await {
        Ok(stats) => {
            let response = serde_json::json!({
                "dht": {
                    "total_nodes": stats.dht_stats.total_nodes,
                    "network_health": stats.dht_stats.network_health,
                    "messages_sent": stats.dht_stats.total_messages_sent,
                    "messages_received": stats.dht_stats.total_messages_received,
                },
                "storage": {
                    "total_content": stats.storage_stats.total_content_count,
                    "total_uploads": stats.storage_stats.total_uploads,
                    "total_downloads": stats.storage_stats.total_downloads,
                    "storage_used": stats.storage_stats.total_storage_used,
                },
                "economic": {
                    "total_contracts": stats.economic_stats.total_contracts,
                    "value_locked": stats.economic_stats.total_value_locked,
                    "total_rewards": stats.economic_stats.total_rewards,
                }
            });
            
            Ok(Json(response))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Helper functions
fn detect_mime_type(filename: &str) -> String {
    match std::path::Path::new(filename).extension().and_then(|s| s.to_str()) {
        Some("txt") => "text/plain".to_string(),
        Some("json") => "application/json".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("png") => "image/png".to_string(),
        Some("mp4") => "video/mp4".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn create_default_user_identity() -> ZhtpIdentity {
    // In production, this would authenticate and return the actual user identity
    unimplemented!("Create using lib-identity with proper authentication")
}
```

### Frontend JavaScript Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>ZHTP Storage Web App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .upload-area { border: 2px dashed #ccc; padding: 20px; margin: 20px 0; }
        .file-list { margin: 20px 0; }
        .file-item { border: 1px solid #eee; padding: 10px; margin: 5px 0; }
        .stats { background: #f5f5f5; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1> ZHTP Storage Web Interface</h1>
    
    <!-- File Upload -->
    <div class="upload-area">
        <h3>Upload File</h3>
        <input type="file" id="fileInput" multiple>
        <input type="text" id="descriptionInput" placeholder="Description (optional)">
        <input type="text" id="tagsInput" placeholder="Tags (comma-separated)">
        <label>
            <input type="checkbox" id="publicInput"> Make Public
        </label>
        <button onclick="uploadFile()">Upload</button>
        <div id="uploadStatus"></div>
    </div>
    
    <!-- Search -->
    <div>
        <h3>Search Files</h3>
        <input type="text" id="searchInput" placeholder="Search keywords">
        <input type="text" id="searchTags" placeholder="Tags filter">
        <button onclick="searchFiles()">Search</button>
    </div>
    
    <!-- File List -->
    <div class="file-list" id="fileList">
        <h3>Files</h3>
        <div id="searchResults"></div>
    </div>
    
    <!-- System Stats -->
    <div class="stats" id="systemStats">
        <h3>System Statistics</h3>
        <div id="statsContent">Loading...</div>
    </div>

    <script>
        // Upload file function
        async function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const descriptionInput = document.getElementById('descriptionInput');
            const tagsInput = document.getElementById('tagsInput');
            const publicInput = document.getElementById('publicInput');
            const statusDiv = document.getElementById('uploadStatus');
            
            if (!fileInput.files.length) {
                statusDiv.innerHTML = '<p style="color: red;">Please select a file</p>';
                return;
            }
            
            const file = fileInput.files[0];
            const reader = new FileReader();
            
            reader.onload = async function(e) {
                const content = btoa(String.fromCharCode(...new Uint8Array(e.target.result)));
                
                const uploadData = {
                    filename: file.name,
                    content: content,
                    description: descriptionInput.value || null,
                    tags: tagsInput.value ? tagsInput.value.split(',').map(t => t.trim()) : null,
                    public: publicInput.checked
                };
                
                try {
                    statusDiv.innerHTML = '<p>Uploading...</p>';
                    
                    const response = await fetch('/api/upload', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(uploadData)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        statusDiv.innerHTML = `<p style="color: green;"> ${result.message}</p>
                                              <p>Content Hash: <code>${result.content_hash}</code></p>`;
                        
                        // Clear form
                        fileInput.value = '';
                        descriptionInput.value = '';
                        tagsInput.value = '';
                        publicInput.checked = false;
                        
                        // Refresh file list
                        searchFiles();
                    } else {
                        statusDiv.innerHTML = `<p style="color: red;"> ${result.message}</p>`;
                    }
                } catch (error) {
                    statusDiv.innerHTML = `<p style="color: red;">Upload error: ${error.message}</p>`;
                }
            };
            
            reader.readAsArrayBuffer(file);
        }
        
        // Search files function
        async function searchFiles() {
            const searchInput = document.getElementById('searchInput');
            const searchTags = document.getElementById('searchTags');
            const resultsDiv = document.getElementById('searchResults');
            
            try {
                const params = new URLSearchParams();
                if (searchInput.value) params.append('q', searchInput.value);
                if (searchTags.value) params.append('tags', searchTags.value);
                params.append('limit', '20');
                
                const response = await fetch(`/api/search?${params}`);
                const result = await response.json();
                
                resultsDiv.innerHTML = '';
                
                if (result.results.length === 0) {
                    resultsDiv.innerHTML = '<p>No files found</p>';
                    return;
                }
                
                result.results.forEach(file => {
                    const fileDiv = document.createElement('div');
                    fileDiv.className = 'file-item';
                    fileDiv.innerHTML = `
                        <h4>${file.filename}</h4>
                        <p><strong>Size:</strong> ${formatBytes(file.size)}</p>
                        <p><strong>Type:</strong> ${file.content_type}</p>
                        <p><strong>Description:</strong> ${file.description || 'No description'}</p>
                        <p><strong>Tags:</strong> ${file.tags.join(', ') || 'No tags'}</p>
                        <p><strong>Created:</strong> ${new Date(file.created_at * 1000).toLocaleString()}</p>
                        <p><strong>Hash:</strong> <code>${file.hash}</code></p>
                        <button onclick="downloadFile('${file.hash}', '${file.filename}')">Download</button>
                    `;
                    resultsDiv.appendChild(fileDiv);
                });
                
            } catch (error) {
                resultsDiv.innerHTML = `<p style="color: red;">Search error: ${error.message}</p>`;
            }
        }
        
        // Download file function
        async function downloadFile(hash, filename) {
            try {
                const response = await fetch(`/api/download/${hash}`);
                
                if (!response.ok) {
                    throw new Error('Download failed');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
            } catch (error) {
                alert(`Download error: ${error.message}`);
            }
        }
        
        // Load system statistics
        async function loadSystemStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                document.getElementById('statsContent').innerHTML = `
                    <h4> Network</h4>
                    <p>Nodes: ${stats.dht.total_nodes} | Health: ${(stats.dht.network_health * 100).toFixed(1)}%</p>
                    
                    <h4> Storage</h4>
                    <p>Files: ${stats.storage.total_content} | Uploads: ${stats.storage.total_uploads} | Downloads: ${stats.storage.total_downloads}</p>
                    <p>Used: ${formatBytes(stats.storage.storage_used)}</p>
                    
                    <h4> Economic</h4>
                    <p>Contracts: ${stats.economic.total_contracts} | Value Locked: ${stats.economic.value_locked} SOV</p>
                `;
                
            } catch (error) {
                document.getElementById('statsContent').innerHTML = `Error loading stats: ${error.message}`;
            }
        }
        
        // Helper function to format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            searchFiles(); // Load initial file list
            loadSystemStats(); // Load system statistics
            
            // Refresh stats every 30 seconds
            setInterval(loadSystemStats, 30000);
        });
    </script>
</body>
</html>
```

## 🖥️ Desktop Application Integration

### Native Desktop App with Tauri

```rust
// src-tauri/src/main.rs
use lib_storage::*;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::{command, State, Manager};

struct AppStorage {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
}

#[derive(Serialize, Deserialize)]
struct FileUploadRequest {
    path: String,
    description: String,
    tags: Vec<String>,
    encrypt: bool,
}

#[derive(Serialize)]
struct FileUploadResponse {
    success: bool,
    content_hash: Option<String>,
    message: String,
}

#[command]
async fn upload_file(
    storage_state: State<'_, AppStorage>,
    request: FileUploadRequest
) -> Result<FileUploadResponse, String> {
    
    // Read file from disk
    let content = match std::fs::read(&request.path) {
        Ok(data) => data,
        Err(e) => return Ok(FileUploadResponse {
            success: false,
            content_hash: None,
            message: format!("Failed to read file: {}", e),
        }),
    };
    
    // Extract filename
    let filename = std::path::Path::new(&request.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    
    // Create user identity (in production, load from secure storage)
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    // Create upload request
    let upload_req = UploadRequest {
        content,
        filename: filename.clone(),
        mime_type: detect_mime_type(&filename),
        description: request.description,
        tags: request.tags,
        encrypt: request.encrypt,
        compress: true,
        access_control: AccessControlSettings {
            public_read: false, // Private by default for desktop apps
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 365, // 1 year default
            quality_requirements: QualityRequirements {
                min_uptime: 0.95,
                max_response_time: 5000,
                min_replication: 3,
                data_integrity_level: 0.99,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 10000, // 10K SOV tokens
                max_cost_per_gb_day: 200,
                preferred_payment_schedule: PaymentSchedule::Monthly,
            },
        },
    };
    
    // Upload to ZHTP storage
    let mut storage = storage_state.storage.write().await;
    match storage.upload_content(upload_req, user_identity).await {
        Ok(content_hash) => Ok(FileUploadResponse {
            success: true,
            content_hash: Some(hex::encode(content_hash.as_bytes())),
            message: format!("File {} uploaded successfully", filename),
        }),
        Err(e) => Ok(FileUploadResponse {
            success: false,
            content_hash: None,
            message: format!("Upload failed: {}", e),
        }),
    }
}

#[command]
async fn download_file(
    storage_state: State<'_, AppStorage>,
    content_hash: String,
    save_path: String
) -> Result<String, String> {
    
    // Parse content hash
    let hash_bytes = hex::decode(&content_hash).map_err(|e| e.to_string())?;
    let content_hash = Hash::from_bytes(&hash_bytes);
    
    // Create user identity
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    // Create download request
    let download_req = DownloadRequest {
        content_hash,
        requester: user_identity,
        access_proof: None,
    };
    
    // Download from ZHTP storage
    let mut storage = storage_state.storage.write().await;
    let content = storage.download_content(download_req).await
        .map_err(|e| e.to_string())?;
    
    // Save to disk
    std::fs::write(&save_path, content).map_err(|e| e.to_string())?;
    
    Ok(format!("File saved to {}", save_path))
}

#[command]
async fn get_user_files(
    storage_state: State<'_, AppStorage>
) -> Result<Vec<serde_json::Value>, String> {
    
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    let search_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: Some(user_identity.clone()),
        date_range: None,
        size_range: None,
        limit: 100,
    };
    
    let storage = storage_state.storage.read().await;
    let results = storage.search_content(search_query, user_identity).await
        .map_err(|e| e.to_string())?;
    
    let files: Vec<serde_json::Value> = results.into_iter().map(|metadata| {
        serde_json::json!({
            "hash": hex::encode(metadata.hash.as_bytes()),
            "filename": metadata.filename,
            "size": metadata.size,
            "content_type": metadata.content_type,
            "description": metadata.description,
            "tags": metadata.tags,
            "created_at": metadata.created_at,
            "is_encrypted": metadata.is_encrypted,
        })
    }).collect();
    
    Ok(files)
}

#[command]
async fn get_storage_stats(
    storage_state: State<'_, AppStorage>
) -> Result<serde_json::Value, String> {
    
    let mut storage = storage_state.storage.write().await;
    let stats = storage.get_statistics().await.map_err(|e| e.to_string())?;
    
    Ok(serde_json::json!({
        "network": {
            "nodes": stats.dht_stats.total_nodes,
            "health": stats.dht_stats.network_health,
        },
        "storage": {
            "files": stats.storage_stats.total_content_count,
            "uploads": stats.storage_stats.total_uploads,
            "downloads": stats.storage_stats.total_downloads,
        },
        "economic": {
            "contracts": stats.economic_stats.total_contracts,
            "value_locked": stats.economic_stats.total_value_locked,
        }
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize ZHTP storage
    let config = create_desktop_storage_config();
    let storage = UnifiedStorageSystem::new(config).await?;
    
    let app_storage = AppStorage {
        storage: Arc::new(RwLock::new(storage)),
    };
    
    tauri::Builder::default()
        .manage(app_storage)
        .invoke_handler(tauri::generate_handler![
            upload_file,
            download_file,
            get_user_files,
            get_storage_stats
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
    
    Ok(())
}

fn create_desktop_storage_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: load_or_create_node_id(),
        addresses: vec!["127.0.0.1:33445".to_string()],
        economic_config: EconomicManagerConfig {
            default_duration_days: 365,
            base_price_per_gb_day: 100,
            enable_escrow: true,
            quality_premium_rate: 0.1,
            network_fee_rate: 0.05,
            escrow_fee_rate: 0.02,
        },
        storage_config: StorageConfig {
            max_storage_size: 50_000_000_000, // 50GB for desktop
            default_tier: StorageTier::Warm,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    }
}

fn create_desktop_user_identity() -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    // In production, load from secure storage or create new identity
    unimplemented!("Create using lib-identity with desktop secure storage")
}

fn load_or_create_node_id() -> Hash {
    // Load from app data directory or create new
    Hash::from_bytes(&rand::random::<[u8; 32]>())
}

fn detect_mime_type(filename: &str) -> String {
    // Implementation for MIME type detection
    match std::path::Path::new(filename).extension().and_then(|s| s.to_str()) {
        Some("txt") => "text/plain".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("png") => "image/png".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}
```

### Desktop Frontend (React/TypeScript)

```typescript
// src/App.tsx
import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open, save } from '@tauri-apps/api/dialog';
import './App.css';

interface FileInfo {
  hash: string;
  filename: string;
  size: number;
  content_type: string;
  description: string;
  tags: string[];
  created_at: number;
  is_encrypted: boolean;
}

interface StorageStats {
  network: {
    nodes: number;
    health: number;
  };
  storage: {
    files: number;
    uploads: number;
    downloads: number;
  };
  economic: {
    contracts: number;
    value_locked: number;
  };
}

function App() {
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string>('');

  useEffect(() => {
    loadUserFiles();
    loadStats();
    
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadUserFiles();
      loadStats();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const loadUserFiles = async () => {
    try {
      const userFiles = await invoke<FileInfo[]>('get_user_files');
      setFiles(userFiles);
    } catch (error) {
      console.error('Failed to load files:', error);
    }
  };

  const loadStats = async () => {
    try {
      const storageStats = await invoke<StorageStats>('get_storage_stats');
      setStats(storageStats);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const handleUpload = async () => {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: 'All Files',
            extensions: ['*']
          }
        ]
      });

      if (!selected) return;

      const description = prompt('Enter file description (optional):') || '';
      const tagsInput = prompt('Enter tags (comma-separated):') || '';
      const tags = tagsInput.split(',').map(t => t.trim()).filter(t => t);
      const encrypt = confirm('Encrypt this file?');

      setUploadStatus('Uploading...');

      const result = await invoke<{success: boolean, content_hash?: string, message: string}>('upload_file', {
        request: {
          path: selected as string,
          description,
          tags,
          encrypt
        }
      });

      if (result.success) {
        setUploadStatus(` ${result.message}`);
        loadUserFiles(); // Refresh file list
      } else {
        setUploadStatus(` ${result.message}`);
      }

      setTimeout(() => setUploadStatus(''), 5000);

    } catch (error) {
      setUploadStatus(` Upload failed: ${error}`);
      setTimeout(() => setUploadStatus(''), 5000);
    }
  };

  const handleDownload = async (file: FileInfo) => {
    try {
      const savePath = await save({
        defaultPath: file.filename,
        filters: [
          {
            name: 'All Files',
            extensions: ['*']
          }
        ]
      });

      if (!savePath) return;

      const result = await invoke<string>('download_file', {
        contentHash: file.hash,
        savePath
      });

      alert(result);

    } catch (error) {
      alert(`Download failed: ${error}`);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="App">
      <header>
        <h1> ZHTP Storage Desktop</h1>
      </header>

      {/* Upload Section */}
      <section className="upload-section">
        <h2>Upload File</h2>
        <button onClick={handleUpload}>Select and Upload File</button>
        {uploadStatus && <p className="status">{uploadStatus}</p>}
      </section>

      {/* Statistics */}
      {stats && (
        <section className="stats-section">
          <h2> System Statistics</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <h3> Network</h3>
              <p>Nodes: {stats.network.nodes}</p>
              <p>Health: {(stats.network.health * 100).toFixed(1)}%</p>
            </div>
            <div className="stat-card">
              <h3> Storage</h3>
              <p>Files: {stats.storage.files}</p>
              <p>Uploads: {stats.storage.uploads}</p>
              <p>Downloads: {stats.storage.downloads}</p>
            </div>
            <div className="stat-card">
              <h3> Economic</h3>
              <p>Contracts: {stats.economic.contracts}</p>
              <p>Value Locked: {stats.economic.value_locked} SOV</p>
            </div>
          </div>
        </section>
      )}

      {/* File List */}
      <section className="files-section">
        <h2>📁 Your Files ({files.length})</h2>
        <div className="file-list">
          {files.map((file) => (
            <div key={file.hash} className="file-item">
              <div className="file-info">
                <h3>{file.filename}</h3>
                <p><strong>Size:</strong> {formatBytes(file.size)}</p>
                <p><strong>Type:</strong> {file.content_type}</p>
                <p><strong>Description:</strong> {file.description || 'No description'}</p>
                <p><strong>Tags:</strong> {file.tags.join(', ') || 'No tags'}</p>
                <p><strong>Created:</strong> {new Date(file.created_at * 1000).toLocaleString()}</p>
                <p><strong>Encrypted:</strong> {file.is_encrypted ? ' Yes' : '🔓 No'}</p>
                <p><strong>Hash:</strong> <code>{file.hash}</code></p>
              </div>
              <div className="file-actions">
                <button onClick={() => handleDownload(file)}>
                   Download
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default App;
```

##  Microservices Integration

### Docker Container Configuration

```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zhtp-storage-service /usr/local/bin/
COPY --from=builder /app/config /usr/local/etc/zhtp-storage/

EXPOSE 33445 8080

CMD ["zhtp-storage-service"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  zhtp-storage-node-1:
    build: .
    ports:
      - "33445:33445"
      - "8080:8080"
    volumes:
      - ./data/node1:/var/lib/zhtp-storage
      - ./config/node1:/etc/zhtp-storage
    environment:
      - ZHTP_NODE_ID=node1
      - ZHTP_NETWORK_PORT=33445
      - ZHTP_API_PORT=8080
      - ZHTP_MAX_STORAGE=10GB
    networks:
      - zhtp-network

  zhtp-storage-node-2:
    build: .
    ports:
      - "33446:33445"
      - "8081:8080"
    volumes:
      - ./data/node2:/var/lib/zhtp-storage
      - ./config/node2:/etc/zhtp-storage
    environment:
      - ZHTP_NODE_ID=node2
      - ZHTP_NETWORK_PORT=33445
      - ZHTP_API_PORT=8080
      - ZHTP_MAX_STORAGE=10GB
      - ZHTP_BOOTSTRAP=zhtp-storage-node-1:33445
    networks:
      - zhtp-network
    depends_on:
      - zhtp-storage-node-1

  zhtp-api-gateway:
    build: ./api-gateway
    ports:
      - "3000:3000"
    environment:
      - ZHTP_NODES=zhtp-storage-node-1:8080,zhtp-storage-node-2:8080
    networks:
      - zhtp-network
    depends_on:
      - zhtp-storage-node-1
      - zhtp-storage-node-2

networks:
  zhtp-network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zhtp-storage-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zhtp-storage
  template:
    metadata:
      labels:
        app: zhtp-storage
    spec:
      containers:
      - name: zhtp-storage
        image: zhtp/storage:latest
        ports:
        - containerPort: 33445
          name: dht-port
        - containerPort: 8080
          name: api-port
        env:
        - name: ZHTP_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: ZHTP_MAX_STORAGE
          value: "50GB"
        volumeMounts:
        - name: storage-data
          mountPath: /var/lib/zhtp-storage
        - name: config
          mountPath: /etc/zhtp-storage
      volumes:
      - name: storage-data
        persistentVolumeClaim:
          claimName: zhtp-storage-pvc
      - name: config
        configMap:
          name: zhtp-storage-config

---
apiVersion: v1
kind: Service
metadata:
  name: zhtp-storage-service
spec:
  selector:
    app: zhtp-storage
  ports:
  - name: dht
    port: 33445
    targetPort: 33445
  - name: api
    port: 8080
    targetPort: 8080
  type: LoadBalancer

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: zhtp-storage-config
data:
  config.toml: |
    [storage]
    max_storage_size = "50GB"
    default_tier = "Warm"
    enable_compression = true
    enable_encryption = true
    
    [economic]
    base_price_per_gb_day = 100
    enable_escrow = true
    
    [network]
    bind_port = 33445
    api_port = 8080
```

## 📚 Integration Best Practices

### Error Handling and Resilience

```rust
use tokio::time::{timeout, Duration};
use anyhow::{Result, Context};

pub struct ResilientStorageClient {
    storage: UnifiedStorageSystem,
    retry_config: RetryConfig,
}

pub struct RetryConfig {
    max_retries: usize,
    base_delay: Duration,
    max_delay: Duration,
}

impl ResilientStorageClient {
    pub async fn upload_with_retry(&mut self, request: UploadRequest, identity: ZhtpIdentity) -> Result<ContentHash> {
        let mut attempt = 0;
        let mut delay = self.retry_config.base_delay;
        
        loop {
            match timeout(Duration::from_secs(30), self.storage.upload_content(request.clone(), identity.clone())).await {
                Ok(Ok(hash)) => return Ok(hash),
                Ok(Err(e)) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(e.context("Max retries exceeded for upload"));
                    }
                    
                    eprintln!("Upload attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, self.retry_config.max_delay);
                }
                Err(_) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(anyhow::anyhow!("Upload timeout after {} attempts", attempt));
                    }
                    
                    eprintln!("Upload attempt {} timed out, retrying in {:?}", attempt, delay);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, self.retry_config.max_delay);
                }
            }
        }
    }
}
```

### Health Monitoring and Metrics

```rust
use prometheus::{Counter, Gauge, Histogram, register_counter, register_gauge, register_histogram};

pub struct StorageMetrics {
    uploads_total: Counter,
    downloads_total: Counter, 
    upload_duration: Histogram,
    download_duration: Histogram,
    storage_usage: Gauge,
    network_health: Gauge,
}

impl StorageMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uploads_total: register_counter!("zhtp_uploads_total", "Total number of uploads")?,
            downloads_total: register_counter!("zhtp_downloads_total", "Total number of downloads")?,
            upload_duration: register_histogram!("zhtp_upload_duration_seconds", "Upload duration")?,
            download_duration: register_histogram!("zhtp_download_duration_seconds", "Download duration")?,
            storage_usage: register_gauge!("zhtp_storage_usage_bytes", "Storage usage in bytes")?,
            network_health: register_gauge!("zhtp_network_health", "Network health score")?,
        })
    }
    
    pub fn record_upload(&self, duration: Duration) {
        self.uploads_total.inc();
        self.upload_duration.observe(duration.as_secs_f64());
    }
    
    pub fn update_storage_usage(&self, bytes: u64) {
        self.storage_usage.set(bytes as f64);
    }
}
```

---

=======
# ZHTP Storage Integration Guide

This comprehensive integration guide shows how to integrate ZHTP Unified Storage System into various types of applications, from simple web apps to complex distributed systems.

##  Integration Overview

The ZHTP Storage System can be integrated into:
- **Web Applications**: Browser-based apps with backend storage
- **Desktop Applications**: Native applications with local and distributed storage
- **Server Applications**: Backend services requiring distributed storage
- **Mobile Applications**: Through FFI bindings (future development)
- **Microservices**: Distributed architectures with shared storage

##  Web Application Integration

### Backend API Server Integration

```rust
// main.rs - Web server with ZHTP storage
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use lib_storage::*;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    user_sessions: Arc<RwLock<HashMap<String, ZhtpIdentity>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize ZHTP storage
    let config = UnifiedStorageConfig::default();
    let storage = UnifiedStorageSystem::new(config).await?;
    
    let app_state = AppState {
        storage: Arc::new(RwLock::new(storage)),
        user_sessions: Arc::new(RwLock::new(HashMap::new())),
    };
    
    // Create API routes
    let app = Router::new()
        .route("/api/upload", post(upload_file))
        .route("/api/download/:hash", get(download_file))
        .route("/api/search", get(search_files))
        .route("/api/user/:user_id/files", get(get_user_files))
        .route("/api/stats", get(get_system_stats))
        .with_state(app_state);
    
    // Start server
    println!(" ZHTP Storage API Server starting on http://localhost:3000");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

#[derive(Deserialize)]
struct UploadRequest {
    filename: String,
    content: String, // Base64 encoded
    description: Option<String>,
    tags: Option<Vec<String>>,
    public: Option<bool>,
}

#[derive(Serialize)]
struct UploadResponse {
    success: bool,
    content_hash: Option<String>,
    message: String,
}

async fn upload_file(
    State(state): State<AppState>,
    Json(request): Json<UploadRequest>
) -> Result<Json<UploadResponse>, StatusCode> {
    
    // Decode content
    let content = match base64::decode(&request.content) {
        Ok(data) => data,
        Err(_) => return Ok(Json(UploadResponse {
            success: false,
            content_hash: None,
            message: "Invalid base64 content".to_string(),
        })),
    };
    
    // Create a default user identity (in production, authenticate user)
    let user_identity = create_default_user_identity();
    
    // Create upload request
    let upload_req = lib_storage::UploadRequest {
        content,
        filename: request.filename.clone(),
        mime_type: detect_mime_type(&request.filename),
        description: request.description.unwrap_or_default(),
        tags: request.tags.unwrap_or_default(),
        encrypt: false,
        compress: true,
        access_control: AccessControlSettings {
            public_read: request.public.unwrap_or(false),
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 30,
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
        },
    };
    
    // Upload to ZHTP storage
    let mut storage = state.storage.write().await;
    match storage.upload_content(upload_req, user_identity).await {
        Ok(content_hash) => {
            Ok(Json(UploadResponse {
                success: true,
                content_hash: Some(hex::encode(content_hash.as_bytes())),
                message: format!("File {} uploaded successfully", request.filename),
            }))
        }
        Err(e) => {
            Ok(Json(UploadResponse {
                success: false,
                content_hash: None,
                message: format!("Upload failed: {}", e),
            }))
        }
    }
}

async fn download_file(
    State(state): State<AppState>,
    Path(hash): Path<String>
) -> Result<Vec<u8>, StatusCode> {
    
    // Parse content hash
    let content_hash = match hex::decode(&hash) {
        Ok(bytes) => Hash::from_bytes(&bytes),
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    
    // Create download request
    let user_identity = create_default_user_identity();
    let download_req = DownloadRequest {
        content_hash,
        requester: user_identity,
        access_proof: None,
    };
    
    // Download from ZHTP storage
    let mut storage = state.storage.write().await;
    match storage.download_content(download_req).await {
        Ok(content) => Ok(content),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    tags: Option<String>,
    content_type: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct SearchResponse {
    results: Vec<FileInfo>,
    total: usize,
}

#[derive(Serialize)]
struct FileInfo {
    hash: String,
    filename: String,
    size: u64,
    content_type: String,
    description: String,
    tags: Vec<String>,
    created_at: u64,
}

async fn search_files(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>
) -> Result<Json<SearchResponse>, StatusCode> {
    
    let user_identity = create_default_user_identity();
    
    let search_query = SearchQuery {
        keywords: params.q.map(|q| vec![q]).unwrap_or_default(),
        content_type: params.content_type,
        tags: params.tags.map(|t| t.split(',').map(|s| s.to_string()).collect()).unwrap_or_default(),
        owner: None,
        date_range: None,
        size_range: None,
        limit: params.limit.unwrap_or(10),
    };
    
    let storage = state.storage.read().await;
    match storage.search_content(search_query, user_identity).await {
        Ok(results) => {
            let file_infos: Vec<FileInfo> = results.into_iter().map(|metadata| {
                FileInfo {
                    hash: hex::encode(metadata.hash.as_bytes()),
                    filename: metadata.filename,
                    size: metadata.size,
                    content_type: metadata.content_type,
                    description: metadata.description,
                    tags: metadata.tags,
                    created_at: metadata.created_at,
                }
            }).collect();
            
            let total = file_infos.len();
            
            Ok(Json(SearchResponse {
                results: file_infos,
                total,
            }))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_system_stats(
    State(state): State<AppState>
) -> Result<Json<serde_json::Value>, StatusCode> {
    
    let mut storage = state.storage.write().await;
    match storage.get_statistics().await {
        Ok(stats) => {
            let response = serde_json::json!({
                "dht": {
                    "total_nodes": stats.dht_stats.total_nodes,
                    "network_health": stats.dht_stats.network_health,
                    "messages_sent": stats.dht_stats.total_messages_sent,
                    "messages_received": stats.dht_stats.total_messages_received,
                },
                "storage": {
                    "total_content": stats.storage_stats.total_content_count,
                    "total_uploads": stats.storage_stats.total_uploads,
                    "total_downloads": stats.storage_stats.total_downloads,
                    "storage_used": stats.storage_stats.total_storage_used,
                },
                "economic": {
                    "total_contracts": stats.economic_stats.total_contracts,
                    "value_locked": stats.economic_stats.total_value_locked,
                    "total_rewards": stats.economic_stats.total_rewards,
                }
            });
            
            Ok(Json(response))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Helper functions
fn detect_mime_type(filename: &str) -> String {
    match std::path::Path::new(filename).extension().and_then(|s| s.to_str()) {
        Some("txt") => "text/plain".to_string(),
        Some("json") => "application/json".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("png") => "image/png".to_string(),
        Some("mp4") => "video/mp4".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn create_default_user_identity() -> ZhtpIdentity {
    // In production, this would authenticate and return the actual user identity
    unimplemented!("Create using lib-identity with proper authentication")
}
```

### Frontend JavaScript Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>ZHTP Storage Web App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .upload-area { border: 2px dashed #ccc; padding: 20px; margin: 20px 0; }
        .file-list { margin: 20px 0; }
        .file-item { border: 1px solid #eee; padding: 10px; margin: 5px 0; }
        .stats { background: #f5f5f5; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1> ZHTP Storage Web Interface</h1>
    
    <!-- File Upload -->
    <div class="upload-area">
        <h3>Upload File</h3>
        <input type="file" id="fileInput" multiple>
        <input type="text" id="descriptionInput" placeholder="Description (optional)">
        <input type="text" id="tagsInput" placeholder="Tags (comma-separated)">
        <label>
            <input type="checkbox" id="publicInput"> Make Public
        </label>
        <button onclick="uploadFile()">Upload</button>
        <div id="uploadStatus"></div>
    </div>
    
    <!-- Search -->
    <div>
        <h3>Search Files</h3>
        <input type="text" id="searchInput" placeholder="Search keywords">
        <input type="text" id="searchTags" placeholder="Tags filter">
        <button onclick="searchFiles()">Search</button>
    </div>
    
    <!-- File List -->
    <div class="file-list" id="fileList">
        <h3>Files</h3>
        <div id="searchResults"></div>
    </div>
    
    <!-- System Stats -->
    <div class="stats" id="systemStats">
        <h3>System Statistics</h3>
        <div id="statsContent">Loading...</div>
    </div>

    <script>
        // Upload file function
        async function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const descriptionInput = document.getElementById('descriptionInput');
            const tagsInput = document.getElementById('tagsInput');
            const publicInput = document.getElementById('publicInput');
            const statusDiv = document.getElementById('uploadStatus');
            
            if (!fileInput.files.length) {
                statusDiv.innerHTML = '<p style="color: red;">Please select a file</p>';
                return;
            }
            
            const file = fileInput.files[0];
            const reader = new FileReader();
            
            reader.onload = async function(e) {
                const content = btoa(String.fromCharCode(...new Uint8Array(e.target.result)));
                
                const uploadData = {
                    filename: file.name,
                    content: content,
                    description: descriptionInput.value || null,
                    tags: tagsInput.value ? tagsInput.value.split(',').map(t => t.trim()) : null,
                    public: publicInput.checked
                };
                
                try {
                    statusDiv.innerHTML = '<p>Uploading...</p>';
                    
                    const response = await fetch('/api/upload', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(uploadData)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        statusDiv.innerHTML = `<p style="color: green;"> ${result.message}</p>
                                              <p>Content Hash: <code>${result.content_hash}</code></p>`;
                        
                        // Clear form
                        fileInput.value = '';
                        descriptionInput.value = '';
                        tagsInput.value = '';
                        publicInput.checked = false;
                        
                        // Refresh file list
                        searchFiles();
                    } else {
                        statusDiv.innerHTML = `<p style="color: red;"> ${result.message}</p>`;
                    }
                } catch (error) {
                    statusDiv.innerHTML = `<p style="color: red;">Upload error: ${error.message}</p>`;
                }
            };
            
            reader.readAsArrayBuffer(file);
        }
        
        // Search files function
        async function searchFiles() {
            const searchInput = document.getElementById('searchInput');
            const searchTags = document.getElementById('searchTags');
            const resultsDiv = document.getElementById('searchResults');
            
            try {
                const params = new URLSearchParams();
                if (searchInput.value) params.append('q', searchInput.value);
                if (searchTags.value) params.append('tags', searchTags.value);
                params.append('limit', '20');
                
                const response = await fetch(`/api/search?${params}`);
                const result = await response.json();
                
                resultsDiv.innerHTML = '';
                
                if (result.results.length === 0) {
                    resultsDiv.innerHTML = '<p>No files found</p>';
                    return;
                }
                
                result.results.forEach(file => {
                    const fileDiv = document.createElement('div');
                    fileDiv.className = 'file-item';
                    fileDiv.innerHTML = `
                        <h4>${file.filename}</h4>
                        <p><strong>Size:</strong> ${formatBytes(file.size)}</p>
                        <p><strong>Type:</strong> ${file.content_type}</p>
                        <p><strong>Description:</strong> ${file.description || 'No description'}</p>
                        <p><strong>Tags:</strong> ${file.tags.join(', ') || 'No tags'}</p>
                        <p><strong>Created:</strong> ${new Date(file.created_at * 1000).toLocaleString()}</p>
                        <p><strong>Hash:</strong> <code>${file.hash}</code></p>
                        <button onclick="downloadFile('${file.hash}', '${file.filename}')">Download</button>
                    `;
                    resultsDiv.appendChild(fileDiv);
                });
                
            } catch (error) {
                resultsDiv.innerHTML = `<p style="color: red;">Search error: ${error.message}</p>`;
            }
        }
        
        // Download file function
        async function downloadFile(hash, filename) {
            try {
                const response = await fetch(`/api/download/${hash}`);
                
                if (!response.ok) {
                    throw new Error('Download failed');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
            } catch (error) {
                alert(`Download error: ${error.message}`);
            }
        }
        
        // Load system statistics
        async function loadSystemStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                document.getElementById('statsContent').innerHTML = `
                    <h4> Network</h4>
                    <p>Nodes: ${stats.dht.total_nodes} | Health: ${(stats.dht.network_health * 100).toFixed(1)}%</p>
                    
                    <h4> Storage</h4>
                    <p>Files: ${stats.storage.total_content} | Uploads: ${stats.storage.total_uploads} | Downloads: ${stats.storage.total_downloads}</p>
                    <p>Used: ${formatBytes(stats.storage.storage_used)}</p>
                    
                    <h4> Economic</h4>
                    <p>Contracts: ${stats.economic.total_contracts} | Value Locked: ${stats.economic.value_locked} SOV</p>
                `;
                
            } catch (error) {
                document.getElementById('statsContent').innerHTML = `Error loading stats: ${error.message}`;
            }
        }
        
        // Helper function to format bytes
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            searchFiles(); // Load initial file list
            loadSystemStats(); // Load system statistics
            
            // Refresh stats every 30 seconds
            setInterval(loadSystemStats, 30000);
        });
    </script>
</body>
</html>
```

## 🖥️ Desktop Application Integration

### Native Desktop App with Tauri

```rust
// src-tauri/src/main.rs
use lib_storage::*;
use lib_identity::ZhtpIdentity;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tauri::{command, State, Manager};

struct AppStorage {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
}

#[derive(Serialize, Deserialize)]
struct FileUploadRequest {
    path: String,
    description: String,
    tags: Vec<String>,
    encrypt: bool,
}

#[derive(Serialize)]
struct FileUploadResponse {
    success: bool,
    content_hash: Option<String>,
    message: String,
}

#[command]
async fn upload_file(
    storage_state: State<'_, AppStorage>,
    request: FileUploadRequest
) -> Result<FileUploadResponse, String> {
    
    // Read file from disk
    let content = match std::fs::read(&request.path) {
        Ok(data) => data,
        Err(e) => return Ok(FileUploadResponse {
            success: false,
            content_hash: None,
            message: format!("Failed to read file: {}", e),
        }),
    };
    
    // Extract filename
    let filename = std::path::Path::new(&request.path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    
    // Create user identity (in production, load from secure storage)
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    // Create upload request
    let upload_req = UploadRequest {
        content,
        filename: filename.clone(),
        mime_type: detect_mime_type(&filename),
        description: request.description,
        tags: request.tags,
        encrypt: request.encrypt,
        compress: true,
        access_control: AccessControlSettings {
            public_read: false, // Private by default for desktop apps
            read_permissions: vec![],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 365, // 1 year default
            quality_requirements: QualityRequirements {
                min_uptime: 0.95,
                max_response_time: 5000,
                min_replication: 3,
                data_integrity_level: 0.99,
            },
            budget_constraints: BudgetConstraints {
                max_total_cost: 10000, // 10K SOV tokens
                max_cost_per_gb_day: 200,
                preferred_payment_schedule: PaymentSchedule::Monthly,
            },
        },
    };
    
    // Upload to ZHTP storage
    let mut storage = storage_state.storage.write().await;
    match storage.upload_content(upload_req, user_identity).await {
        Ok(content_hash) => Ok(FileUploadResponse {
            success: true,
            content_hash: Some(hex::encode(content_hash.as_bytes())),
            message: format!("File {} uploaded successfully", filename),
        }),
        Err(e) => Ok(FileUploadResponse {
            success: false,
            content_hash: None,
            message: format!("Upload failed: {}", e),
        }),
    }
}

#[command]
async fn download_file(
    storage_state: State<'_, AppStorage>,
    content_hash: String,
    save_path: String
) -> Result<String, String> {
    
    // Parse content hash
    let hash_bytes = hex::decode(&content_hash).map_err(|e| e.to_string())?;
    let content_hash = Hash::from_bytes(&hash_bytes);
    
    // Create user identity
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    // Create download request
    let download_req = DownloadRequest {
        content_hash,
        requester: user_identity,
        access_proof: None,
    };
    
    // Download from ZHTP storage
    let mut storage = storage_state.storage.write().await;
    let content = storage.download_content(download_req).await
        .map_err(|e| e.to_string())?;
    
    // Save to disk
    std::fs::write(&save_path, content).map_err(|e| e.to_string())?;
    
    Ok(format!("File saved to {}", save_path))
}

#[command]
async fn get_user_files(
    storage_state: State<'_, AppStorage>
) -> Result<Vec<serde_json::Value>, String> {
    
    let user_identity = create_desktop_user_identity().map_err(|e| e.to_string())?;
    
    let search_query = SearchQuery {
        keywords: vec![],
        content_type: None,
        tags: vec![],
        owner: Some(user_identity.clone()),
        date_range: None,
        size_range: None,
        limit: 100,
    };
    
    let storage = storage_state.storage.read().await;
    let results = storage.search_content(search_query, user_identity).await
        .map_err(|e| e.to_string())?;
    
    let files: Vec<serde_json::Value> = results.into_iter().map(|metadata| {
        serde_json::json!({
            "hash": hex::encode(metadata.hash.as_bytes()),
            "filename": metadata.filename,
            "size": metadata.size,
            "content_type": metadata.content_type,
            "description": metadata.description,
            "tags": metadata.tags,
            "created_at": metadata.created_at,
            "is_encrypted": metadata.is_encrypted,
        })
    }).collect();
    
    Ok(files)
}

#[command]
async fn get_storage_stats(
    storage_state: State<'_, AppStorage>
) -> Result<serde_json::Value, String> {
    
    let mut storage = storage_state.storage.write().await;
    let stats = storage.get_statistics().await.map_err(|e| e.to_string())?;
    
    Ok(serde_json::json!({
        "network": {
            "nodes": stats.dht_stats.total_nodes,
            "health": stats.dht_stats.network_health,
        },
        "storage": {
            "files": stats.storage_stats.total_content_count,
            "uploads": stats.storage_stats.total_uploads,
            "downloads": stats.storage_stats.total_downloads,
        },
        "economic": {
            "contracts": stats.economic_stats.total_contracts,
            "value_locked": stats.economic_stats.total_value_locked,
        }
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize ZHTP storage
    let config = create_desktop_storage_config();
    let storage = UnifiedStorageSystem::new(config).await?;
    
    let app_storage = AppStorage {
        storage: Arc::new(RwLock::new(storage)),
    };
    
    tauri::Builder::default()
        .manage(app_storage)
        .invoke_handler(tauri::generate_handler![
            upload_file,
            download_file,
            get_user_files,
            get_storage_stats
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
    
    Ok(())
}

fn create_desktop_storage_config() -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id: load_or_create_node_id(),
        addresses: vec!["127.0.0.1:33445".to_string()],
        economic_config: EconomicManagerConfig {
            default_duration_days: 365,
            base_price_per_gb_day: 100,
            enable_escrow: true,
            quality_premium_rate: 0.1,
            network_fee_rate: 0.05,
            escrow_fee_rate: 0.02,
        },
        storage_config: StorageConfig {
            max_storage_size: 50_000_000_000, // 50GB for desktop
            default_tier: StorageTier::Warm,
            enable_compression: true,
            enable_encryption: true,
        },
        erasure_config: ErasureConfig {
            data_shards: 4,
            parity_shards: 2,
        },
    }
}

fn create_desktop_user_identity() -> Result<ZhtpIdentity, Box<dyn std::error::Error>> {
    // In production, load from secure storage or create new identity
    unimplemented!("Create using lib-identity with desktop secure storage")
}

fn load_or_create_node_id() -> Hash {
    // Load from app data directory or create new
    Hash::from_bytes(&rand::random::<[u8; 32]>())
}

fn detect_mime_type(filename: &str) -> String {
    // Implementation for MIME type detection
    match std::path::Path::new(filename).extension().and_then(|s| s.to_str()) {
        Some("txt") => "text/plain".to_string(),
        Some("pdf") => "application/pdf".to_string(),
        Some("jpg") | Some("jpeg") => "image/jpeg".to_string(),
        Some("png") => "image/png".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}
```

### Desktop Frontend (React/TypeScript)

```typescript
// src/App.tsx
import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open, save } from '@tauri-apps/api/dialog';
import './App.css';

interface FileInfo {
  hash: string;
  filename: string;
  size: number;
  content_type: string;
  description: string;
  tags: string[];
  created_at: number;
  is_encrypted: boolean;
}

interface StorageStats {
  network: {
    nodes: number;
    health: number;
  };
  storage: {
    files: number;
    uploads: number;
    downloads: number;
  };
  economic: {
    contracts: number;
    value_locked: number;
  };
}

function App() {
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string>('');

  useEffect(() => {
    loadUserFiles();
    loadStats();
    
    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadUserFiles();
      loadStats();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const loadUserFiles = async () => {
    try {
      const userFiles = await invoke<FileInfo[]>('get_user_files');
      setFiles(userFiles);
    } catch (error) {
      console.error('Failed to load files:', error);
    }
  };

  const loadStats = async () => {
    try {
      const storageStats = await invoke<StorageStats>('get_storage_stats');
      setStats(storageStats);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const handleUpload = async () => {
    try {
      const selected = await open({
        multiple: false,
        filters: [
          {
            name: 'All Files',
            extensions: ['*']
          }
        ]
      });

      if (!selected) return;

      const description = prompt('Enter file description (optional):') || '';
      const tagsInput = prompt('Enter tags (comma-separated):') || '';
      const tags = tagsInput.split(',').map(t => t.trim()).filter(t => t);
      const encrypt = confirm('Encrypt this file?');

      setUploadStatus('Uploading...');

      const result = await invoke<{success: boolean, content_hash?: string, message: string}>('upload_file', {
        request: {
          path: selected as string,
          description,
          tags,
          encrypt
        }
      });

      if (result.success) {
        setUploadStatus(` ${result.message}`);
        loadUserFiles(); // Refresh file list
      } else {
        setUploadStatus(` ${result.message}`);
      }

      setTimeout(() => setUploadStatus(''), 5000);

    } catch (error) {
      setUploadStatus(` Upload failed: ${error}`);
      setTimeout(() => setUploadStatus(''), 5000);
    }
  };

  const handleDownload = async (file: FileInfo) => {
    try {
      const savePath = await save({
        defaultPath: file.filename,
        filters: [
          {
            name: 'All Files',
            extensions: ['*']
          }
        ]
      });

      if (!savePath) return;

      const result = await invoke<string>('download_file', {
        contentHash: file.hash,
        savePath
      });

      alert(result);

    } catch (error) {
      alert(`Download failed: ${error}`);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="App">
      <header>
        <h1> ZHTP Storage Desktop</h1>
      </header>

      {/* Upload Section */}
      <section className="upload-section">
        <h2>Upload File</h2>
        <button onClick={handleUpload}>Select and Upload File</button>
        {uploadStatus && <p className="status">{uploadStatus}</p>}
      </section>

      {/* Statistics */}
      {stats && (
        <section className="stats-section">
          <h2> System Statistics</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <h3> Network</h3>
              <p>Nodes: {stats.network.nodes}</p>
              <p>Health: {(stats.network.health * 100).toFixed(1)}%</p>
            </div>
            <div className="stat-card">
              <h3> Storage</h3>
              <p>Files: {stats.storage.files}</p>
              <p>Uploads: {stats.storage.uploads}</p>
              <p>Downloads: {stats.storage.downloads}</p>
            </div>
            <div className="stat-card">
              <h3> Economic</h3>
              <p>Contracts: {stats.economic.contracts}</p>
              <p>Value Locked: {stats.economic.value_locked} SOV</p>
            </div>
          </div>
        </section>
      )}

      {/* File List */}
      <section className="files-section">
        <h2>📁 Your Files ({files.length})</h2>
        <div className="file-list">
          {files.map((file) => (
            <div key={file.hash} className="file-item">
              <div className="file-info">
                <h3>{file.filename}</h3>
                <p><strong>Size:</strong> {formatBytes(file.size)}</p>
                <p><strong>Type:</strong> {file.content_type}</p>
                <p><strong>Description:</strong> {file.description || 'No description'}</p>
                <p><strong>Tags:</strong> {file.tags.join(', ') || 'No tags'}</p>
                <p><strong>Created:</strong> {new Date(file.created_at * 1000).toLocaleString()}</p>
                <p><strong>Encrypted:</strong> {file.is_encrypted ? ' Yes' : '🔓 No'}</p>
                <p><strong>Hash:</strong> <code>{file.hash}</code></p>
              </div>
              <div className="file-actions">
                <button onClick={() => handleDownload(file)}>
                   Download
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default App;
```

##  Microservices Integration

### Docker Container Configuration

```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zhtp-storage-service /usr/local/bin/
COPY --from=builder /app/config /usr/local/etc/zhtp-storage/

EXPOSE 33445 8080

CMD ["zhtp-storage-service"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  zhtp-storage-node-1:
    build: .
    ports:
      - "33445:33445"
      - "8080:8080"
    volumes:
      - ./data/node1:/var/lib/zhtp-storage
      - ./config/node1:/etc/zhtp-storage
    environment:
      - ZHTP_NODE_ID=node1
      - ZHTP_NETWORK_PORT=33445
      - ZHTP_API_PORT=8080
      - ZHTP_MAX_STORAGE=10GB
    networks:
      - zhtp-network

  zhtp-storage-node-2:
    build: .
    ports:
      - "33446:33445"
      - "8081:8080"
    volumes:
      - ./data/node2:/var/lib/zhtp-storage
      - ./config/node2:/etc/zhtp-storage
    environment:
      - ZHTP_NODE_ID=node2
      - ZHTP_NETWORK_PORT=33445
      - ZHTP_API_PORT=8080
      - ZHTP_MAX_STORAGE=10GB
      - ZHTP_BOOTSTRAP=zhtp-storage-node-1:33445
    networks:
      - zhtp-network
    depends_on:
      - zhtp-storage-node-1

  zhtp-api-gateway:
    build: ./api-gateway
    ports:
      - "3000:3000"
    environment:
      - ZHTP_NODES=zhtp-storage-node-1:8080,zhtp-storage-node-2:8080
    networks:
      - zhtp-network
    depends_on:
      - zhtp-storage-node-1
      - zhtp-storage-node-2

networks:
  zhtp-network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zhtp-storage-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zhtp-storage
  template:
    metadata:
      labels:
        app: zhtp-storage
    spec:
      containers:
      - name: zhtp-storage
        image: zhtp/storage:latest
        ports:
        - containerPort: 33445
          name: dht-port
        - containerPort: 8080
          name: api-port
        env:
        - name: ZHTP_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: ZHTP_MAX_STORAGE
          value: "50GB"
        volumeMounts:
        - name: storage-data
          mountPath: /var/lib/zhtp-storage
        - name: config
          mountPath: /etc/zhtp-storage
      volumes:
      - name: storage-data
        persistentVolumeClaim:
          claimName: zhtp-storage-pvc
      - name: config
        configMap:
          name: zhtp-storage-config

---
apiVersion: v1
kind: Service
metadata:
  name: zhtp-storage-service
spec:
  selector:
    app: zhtp-storage
  ports:
  - name: dht
    port: 33445
    targetPort: 33445
  - name: api
    port: 8080
    targetPort: 8080
  type: LoadBalancer

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: zhtp-storage-config
data:
  config.toml: |
    [storage]
    max_storage_size = "50GB"
    default_tier = "Warm"
    enable_compression = true
    enable_encryption = true
    
    [economic]
    base_price_per_gb_day = 100
    enable_escrow = true
    
    [network]
    bind_port = 33445
    api_port = 8080
```

## 📚 Integration Best Practices

### Error Handling and Resilience

```rust
use tokio::time::{timeout, Duration};
use anyhow::{Result, Context};

pub struct ResilientStorageClient {
    storage: UnifiedStorageSystem,
    retry_config: RetryConfig,
}

pub struct RetryConfig {
    max_retries: usize,
    base_delay: Duration,
    max_delay: Duration,
}

impl ResilientStorageClient {
    pub async fn upload_with_retry(&mut self, request: UploadRequest, identity: ZhtpIdentity) -> Result<ContentHash> {
        let mut attempt = 0;
        let mut delay = self.retry_config.base_delay;
        
        loop {
            match timeout(Duration::from_secs(30), self.storage.upload_content(request.clone(), identity.clone())).await {
                Ok(Ok(hash)) => return Ok(hash),
                Ok(Err(e)) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(e.context("Max retries exceeded for upload"));
                    }
                    
                    eprintln!("Upload attempt {} failed: {}, retrying in {:?}", attempt, e, delay);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, self.retry_config.max_delay);
                }
                Err(_) => {
                    attempt += 1;
                    if attempt >= self.retry_config.max_retries {
                        return Err(anyhow::anyhow!("Upload timeout after {} attempts", attempt));
                    }
                    
                    eprintln!("Upload attempt {} timed out, retrying in {:?}", attempt, delay);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, self.retry_config.max_delay);
                }
            }
        }
    }
}
```

### Health Monitoring and Metrics

```rust
use prometheus::{Counter, Gauge, Histogram, register_counter, register_gauge, register_histogram};

pub struct StorageMetrics {
    uploads_total: Counter,
    downloads_total: Counter, 
    upload_duration: Histogram,
    download_duration: Histogram,
    storage_usage: Gauge,
    network_health: Gauge,
}

impl StorageMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uploads_total: register_counter!("zhtp_uploads_total", "Total number of uploads")?,
            downloads_total: register_counter!("zhtp_downloads_total", "Total number of downloads")?,
            upload_duration: register_histogram!("zhtp_upload_duration_seconds", "Upload duration")?,
            download_duration: register_histogram!("zhtp_download_duration_seconds", "Download duration")?,
            storage_usage: register_gauge!("zhtp_storage_usage_bytes", "Storage usage in bytes")?,
            network_health: register_gauge!("zhtp_network_health", "Network health score")?,
        })
    }
    
    pub fn record_upload(&self, duration: Duration) {
        self.uploads_total.inc();
        self.upload_duration.observe(duration.as_secs_f64());
    }
    
    pub fn update_storage_usage(&self, bytes: u64) {
        self.storage_usage.set(bytes as f64);
    }
}
```

---

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
This integration guide provides comprehensive examples for integrating ZHTP Storage into various application architectures. Choose the appropriate integration pattern based on your specific use case and technical requirements.
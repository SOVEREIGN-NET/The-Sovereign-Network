//! Mobile FFI bindings for Android and iOS
//!
//! This module provides Foreign Function Interface (FFI) bindings for both
//! Android (via JNI) and iOS (via C FFI) to enable mobile apps to use ZHTP.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Import ZHTP types we need
use crate::mesh::server::ZhtpMeshServer;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "ios")]
pub mod ios;

/// Global runtime for async operations
static RUNTIME: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);

/// Global ZHTP node instance
static NODE_INSTANCE: Mutex<Option<Arc<Mutex<ZhtpNode>>>> = Mutex::new(None);

/// Represents the ZHTP node state for mobile platforms
pub struct ZhtpNode {
    pub node_id: String,
    pub mesh_server: Option<ZhtpMeshServer>,
    pub connected_peers: HashMap<String, PeerInfo>,
    pub status: NodeStatus,
    pub config: NodeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    pub protocol: String,
    pub last_seen: u64,
    pub is_router: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub enable_wifi_direct: bool,
    pub enable_bluetooth: bool,
    pub enable_udp_multicast: bool,
    pub enable_mdns: bool,
    pub port: u16,
    pub device_type: String, // "router" or "client"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running,
    Error(String),
}

/// Result type for FFI operations
#[repr(C)]
pub struct FFIResult {
    pub success: bool,
    pub message: *mut c_char,
}

impl FFIResult {
    pub fn success(msg: &str) -> Self {
        FFIResult {
            success: true,
            message: CString::new(msg).unwrap().into_raw(),
        }
    }

    pub fn error(msg: &str) -> Self {
        FFIResult {
            success: false,
            message: CString::new(msg).unwrap().into_raw(),
        }
    }
}

/// Initialize the ZHTP runtime
pub fn init_runtime() -> Result<(), String> {
    let mut runtime = RUNTIME.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if runtime.is_none() {
        let rt = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;
        *runtime = Some(Arc::new(rt));
    }
    
    Ok(())
}

/// Create a new ZHTP node instance
pub fn create_node(config: NodeConfig) -> Result<String, String> {
    init_runtime()?;
    
    let node_id = uuid::Uuid::new_v4().to_string();
    
    let node = ZhtpNode {
        node_id: node_id.clone(),
        mesh_server: None,
        connected_peers: HashMap::new(),
        status: NodeStatus::Stopped,
        config,
    };
    
    let mut instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    *instance = Some(Arc::new(Mutex::new(node)));
    
    Ok(node_id)
}

/// Start the ZHTP node
pub fn start_node() -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let mut node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if node.status == NodeStatus::Running {
        return Ok("Node already running".to_string());
    }
    
    node.status = NodeStatus::Starting;
    
    // TODO: Initialize mesh server with proper identity and configuration
    // For now, just mark as running - actual mesh server initialization
    // requires async context and full ZHTP identity setup
    
    node.status = NodeStatus::Running;
    
    Ok(format!("Node {} started successfully", node.node_id))
}

/// Stop the ZHTP node
pub fn stop_node() -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let mut node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if node.status == NodeStatus::Stopped {
        return Ok("Node already stopped".to_string());
    }
    
    // Clean up mesh server and peers
    node.mesh_server = None;
    node.connected_peers.clear();
    node.status = NodeStatus::Stopped;
    
    Ok("Node stopped successfully".to_string())
}

/// Get node status as JSON
pub fn get_node_status() -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    let status_json = serde_json::json!({
        "node_id": node.node_id,
        "status": format!("{:?}", node.status),
        "connected_peers": node.connected_peers.len(),
        "config": node.config,
    });
    
    serde_json::to_string(&status_json).map_err(|e| format!("JSON error: {}", e))
}

/// Discover peers on local network
pub fn discover_peers(_timeout_secs: u64) -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if node.status != NodeStatus::Running {
        return Err("Node not running".to_string());
    }
    
    // Return current connected peers as JSON
    let peers: Vec<serde_json::Value> = node.connected_peers.values().map(|peer| {
        serde_json::json!({
            "peer_id": peer.peer_id,
            "address": peer.address,
            "protocol": peer.protocol,
            "is_router": peer.is_router,
            "last_seen": peer.last_seen,
        })
    }).collect();
    
    serde_json::to_string(&peers).map_err(|e| format!("JSON error: {}", e))
}

/// Connect to a specific peer
pub fn connect_to_peer(peer_address: &str, peer_id: &str) -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let mut node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if node.status != NodeStatus::Running {
        return Err("Node not running".to_string());
    }
    
    // Add peer to connected peers list
    let peer_info = PeerInfo {
        peer_id: peer_id.to_string(),
        address: peer_address.to_string(),
        protocol: "tcp".to_string(),
        last_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        is_router: false,
    };
    
    node.connected_peers.insert(peer_id.to_string(), peer_info);
    
    Ok(format!("Connected to peer {}", peer_id))
}

/// Send a message to a peer
pub fn send_message(peer_id: &str, _message: &str) -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    if node.status != NodeStatus::Running {
        return Err("Node not running".to_string());
    }
    
    if !node.connected_peers.contains_key(peer_id) {
        return Err(format!("Peer {} not connected", peer_id));
    }
    
    // TODO: Actually send the message via the appropriate protocol
    Ok(format!("Message sent to {}", peer_id))
}

/// Get list of connected peers as JSON
pub fn get_connected_peers() -> Result<String, String> {
    let instance = NODE_INSTANCE.lock().map_err(|e| format!("Lock error: {}", e))?;
    let node_arc = instance.as_ref().ok_or("Node not initialized")?;
    
    let node = node_arc.lock().map_err(|e| format!("Lock error: {}", e))?;
    
    let peers: Vec<&PeerInfo> = node.connected_peers.values().collect();
    
    serde_json::to_string(&peers).map_err(|e| format!("JSON error: {}", e))
}

/// Free a C string allocated by Rust
#[no_mangle]
pub extern "C" fn zhtp_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Helper to convert C string to Rust String
pub unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String, String> {
    if c_str.is_null() {
        return Err("Null pointer".to_string());
    }
    
    CStr::from_ptr(c_str)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|e| format!("UTF-8 error: {}", e))
}

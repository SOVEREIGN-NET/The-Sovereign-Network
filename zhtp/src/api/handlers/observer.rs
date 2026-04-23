//! Observer API handlers for ZHTP
//!
//! Provides endpoints for consensus observer metrics and network health summaries.
//! Issue #1788: Expose observer metrics via API endpoints
//!
//! OBSERVER-ADMISSION-4: Identity-backed admission status added
//! - admission_status field now reflects blockchain registry state
//! - sponsor_did and proof_level queried from observer registry

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::runtime::{ComponentHealth as RuntimeComponentHealth, ComponentId, ComponentStatus, RuntimeOrchestrator};

const CONTENT_TYPE_JSON: &str = "application/json";

/// Per-height metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct HeightMetricsResponse {
    pub status: String,
    pub height: u64,
    pub round_count: u32,
    pub commit_latency_ms: Option<u64>,
    pub classification: String,
    pub phases: Vec<PhaseMetric>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseMetric {
    pub phase_type: String,
    pub duration_ms: u64,
    pub completed: bool,
}

/// Network health summary response
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkHealthResponse {
    pub status: String,
    pub stall_rate: f64,
    pub average_rounds_per_height: f64,
    pub partition_indicators: PartitionIndicators,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartitionIndicators {
    pub recent_heights_with_no_commits: u32,
    pub peer_connectivity_ratio: f64,
    pub sync_freshness_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObserverStatusResponse {
    pub status: String,
    pub node_role: String,
    pub lifecycle_state: String,
    pub blockchain_component: String,
    pub network_component: String,
    pub local_height: u64,
    pub connected_peers: u32,
    pub mesh_connected: bool,
    pub mesh_connectivity_percent: f64,
    pub can_mine: bool,
    pub can_validate: bool,
    pub stores_full_blockchain: bool,
    // OBSERVER-ADMISSION-4: Identity-backed admission fields
    pub admission_status: String,
    pub sponsor_did: Option<String>,
    pub proof_level: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConnectionsResponse {
    pub status: String,
    pub connected_peers: Vec<PeerInfo>,
    pub mesh_connected: bool,
    pub mesh_connectivity_percent: f64,
    pub peer_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    pub is_bootstrap: bool,
    pub latency_ms: Option<u64>,
    pub last_seen_secs_ago: Option<u64>,
}

pub struct ObserverHandlers {
    pub runtime: Arc<RuntimeOrchestrator>,
    pub observer_registry: Arc<dyn ObserverRegistryReader>,
}

pub trait ObserverRegistryReader: Send + Sync {
    fn get_observer_admission(&self, did: &str) -> Option<ObserverAdmissionRecord>;
    fn get_node_did(&self) -> Option<String>;
}

#[derive(Debug, Clone)]
pub struct ObserverAdmissionRecord {
    pub status: String,
    pub sponsor_did: String,
    pub proof_level: u32,
    pub registered_at: u64,
}

/// GET /api/v1/observer/status
/// Returns identity-backed observer status including admission state
async fn handle_get_observer_status(
    &self,
    _request: ZhtpRequest,
) -> ZhtpResult<ZhtpResponse> {
    info!("API: Getting observer status with admission state");

    let (node_role, lifecycle_state, blockchain_component, network_component, local_height,
         connected_peers, mesh_connected, mesh_connectivity_percent, can_mine, can_validate,
         stores_full_blockchain, admission_status, sponsor_did, proof_level)
        = self.observer_runtime_snapshot().await
        .map_err(|e| {
            error!("Failed to get observer status: {}", e);
            ZhtpResponse::error(&format!("Internal error: {}", e), ZhtpStatus::INTERNAL_ERROR)
        })?;

    let status_response = ObserverStatusResponse {
        status: "success".to_string(),
        node_role,
        lifecycle_state,
        blockchain_component,
        network_component,
        local_height,
        connected_peers,
        mesh_connected,
        mesh_connectivity_percent,
        can_mine,
        can_validate,
        stores_full_blockchain,
        admission_status,
        sponsor_did,
        proof_level,
    };

    let json_response = serde_json::to_string(&status_response)
        .map_err(|e| ZhtpResponse::error(&format!("Serialization error: {}", e), ZhtpStatus::INTERNAL_ERROR))?;

    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        CONTENT_TYPE_JSON.to_string(),
        None,
    ))
}

/// Fetches current runtime state plus identity-backed admission status
/// OBSERVER-ADMISSION-4: Now queries blockchain registry for admission state
async fn observer_runtime_snapshot(
    &self,
) -> anyhow::Result<(
    crate::runtime::NodeRole,
    String,
    String,
    String,
    u64,
    u32,
    bool,
    f64,
    bool,
    bool,
    bool,
    // OBSERVER-ADMISSION-4: New admission fields
    String,          // admission_status
    Option<String>,  // sponsor_did
    Option<u32>,     // proof_level
)> {
    // Get runtime snapshot
    let (node_role, blockchain_status, network_status, local_height, connected_peers,
         mesh_connected, mesh_connectivity_percent, can_mine, can_validate,
         stores_full_blockchain) = self.runtime.snapshot().await?;

    // Determine lifecycle state based on runtime + admission
    let lifecycle_state = determine_lifecycle_state(&node_role, &blockchain_status, &network_status);

    // OBSERVER-ADMISSION-4: Query blockchain registry for admission status
    let admission_status: String;
    let sponsor_did: Option<String>;
    let proof_level: Option<u32>;

    if let Some(node_did) = self.observer_registry.get_node_did() {
        if let Some(record) = self.observer_registry.get_observer_admission(&node_did) {
            admission_status = record.status.clone();
            sponsor_did = Some(record.sponsor_did);
            proof_level = Some(record.proof_level);
        } else {
            // DID exists but not in registry = unauthorized
            admission_status = "unauthorized".to_string();
            sponsor_did = None;
            proof_level = None;
        }
    } else {
        // No DID means not registered at all
        admission_status = "unregistered".to_string();
        sponsor_did = None;
        proof_level = None;
    }

    // Override lifecycle_state if admission is not active
    // A node is only "Serving" if both runtime is operational AND admission is active
    let lifecycle_state = if lifecycle_state == "Serving" && admission_status != "active" {
        match admission_status.as_str() {
            "pending" => "Pending Admission",
            "suspended" => "Suspended",
            "revoked" => "Revoked",
            "unauthorized" => "Unauthorized",
            "unregistered" => "Unregistered",
            _ => &lifecycle_state,
        }
    } else {
        lifecycle_state
    };

    Ok((
        node_role,
        lifecycle_state,
        blockchain_status,
        network_status,
        local_height,
        connected_peers,
        mesh_connected,
        mesh_connectivity_percent,
        can_mine,
        can_validate,
        stores_full_blockchain,
        admission_status,
        sponsor_did,
        proof_level,
    ))
}

fn determine_lifecycle_state(
    node_role: &crate::runtime::NodeRole,
    blockchain_status: &str,
    network_status: &str,
) -> String {
    use crate::runtime::NodeRole;

    match node_role {
        NodeRole::Miner if blockchain_status == "operational" => "Mining".to_string(),
        NodeRole::Validator if blockchain_status == "operational" => "Validating".to_string(),
        NodeRole::Observer => {
            if blockchain_status == "operational" && network_status == "connected" {
                "Serving".to_string()
            } else {
                "Degraded".to_string()
            }
        }
        _ => "Unknown".to_string(),
    }
}

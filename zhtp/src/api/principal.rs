//! Shared principal extraction for ZHTP API handlers.

use lib_access_control::{Role, SecurityPrincipal};
use lib_protocols::types::ZhtpRequest;
use lib_types::NodeType;

/// Extract a `SecurityPrincipal` from an incoming `ZhtpRequest`.
///
/// This is the canonical integration point used across all API handlers.
/// In future phases it will inspect bearer tokens, delegation certificates,
/// and UHP auth context. For now it uses simple headers to distinguish
/// public, node, and session callers.
pub fn extract_principal_from_request(request: &ZhtpRequest) -> SecurityPrincipal {
    // Node-to-node calls may declare their node type.
    if let Some(node_type_str) = request.headers.get("x-node-type") {
        let node_type = NodeType::from_config(Some(&node_type_str));
        return SecurityPrincipal::new("did:zhtp:node", Role::Node, node_type);
    }

    // Authenticated sessions (placeholder: any bearer token is treated as
    // a citizen session until full session-to-principal mapping is wired).
    if let Some(auth) = request.headers.get("authorization") {
        if auth.to_lowercase().starts_with("bearer ") {
            return SecurityPrincipal::new(
                "did:zhtp:session",
                Role::Citizen,
                NodeType::FullNode,
            );
        }
    }

    // Default: unauthenticated public caller.
    SecurityPrincipal::public()
}

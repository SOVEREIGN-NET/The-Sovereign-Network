//! Privilege markers and authorization
//!
//! Defines privilege levels and authorization requirements for contract methods,
//! enabling Treasury Kernel to enforce access control.

use serde::{Deserialize, Serialize};

/// Privilege level for contract operations
///
/// Defines what authorization is required to call a contract method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegeLevel {
    /// Public: Anyone can call
    Public = 0,

    /// Citizen: Only citizens can call
    Citizen = 1,

    /// Registered: Requires specific registration
    Registered = 2,

    /// Governance: Requires governance approval
    Governance = 3,

    /// Kernel: Only Treasury Kernel can execute
    Kernel = 4,
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivilegeLevel::Public => write!(f, "public"),
            PrivilegeLevel::Citizen => write!(f, "citizen"),
            PrivilegeLevel::Registered => write!(f, "registered"),
            PrivilegeLevel::Governance => write!(f, "governance"),
            PrivilegeLevel::Kernel => write!(f, "kernel"),
        }
    }
}

impl PrivilegeLevel {
    /// Check if this privilege level satisfies a required level
    pub fn satisfies(&self, required: PrivilegeLevel) -> bool {
        *self >= required
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            PrivilegeLevel::Public => "No authorization required",
            PrivilegeLevel::Citizen => "Requires citizen role",
            PrivilegeLevel::Registered => "Requires registration",
            PrivilegeLevel::Governance => "Requires governance approval",
            PrivilegeLevel::Kernel => "Only Treasury Kernel can execute",
        }
    }
}

/// Privilege marker for ABI methods
///
/// Marks which privilege level is required for authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeMarker {
    /// Required privilege level
    pub level: PrivilegeLevel,

    /// Additional notes about privilege requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl PrivilegeMarker {
    /// Create a public method marker
    pub fn public() -> Self {
        Self {
            level: PrivilegeLevel::Public,
            notes: None,
        }
    }

    /// Create a kernel-only method marker
    pub fn kernel_only() -> Self {
        Self {
            level: PrivilegeLevel::Kernel,
            notes: Some("Only Treasury Kernel can execute this method".to_string()),
        }
    }

    /// Create a governance-gated method marker
    pub fn governance_gated() -> Self {
        Self {
            level: PrivilegeLevel::Governance,
            notes: Some("Requires governance approval to execute".to_string()),
        }
    }

    /// Create a citizen-only method marker
    pub fn citizen_only() -> Self {
        Self {
            level: PrivilegeLevel::Citizen,
            notes: Some("Only citizens can execute this method".to_string()),
        }
    }

    /// Check if a given privilege level can execute this method
    pub fn can_execute(&self, caller_privilege: PrivilegeLevel) -> bool {
        caller_privilege.satisfies(self.level)
    }
}

impl Default for PrivilegeMarker {
    fn default() -> Self {
        Self::public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_satisfaction() {
        assert!(PrivilegeLevel::Kernel.satisfies(PrivilegeLevel::Public));
        assert!(PrivilegeLevel::Kernel.satisfies(PrivilegeLevel::Governance));
        assert!(!PrivilegeLevel::Citizen.satisfies(PrivilegeLevel::Governance));
    }

    #[test]
    fn test_privilege_marker_execution() {
        let marker = PrivilegeMarker::kernel_only();
        assert!(!marker.can_execute(PrivilegeLevel::Public));
        assert!(marker.can_execute(PrivilegeLevel::Kernel));
    }

    #[test]
    fn test_privilege_display() {
        assert_eq!(PrivilegeLevel::Kernel.to_string(), "kernel");
        assert_eq!(PrivilegeLevel::Public.to_string(), "public");
    }
}

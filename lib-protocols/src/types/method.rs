//! ZHTP Request Methods
//! 
//! HTTP-compatible request methods with Web4 extensions for zero-knowledge proofs
//! and blockchain interactions.

use serde::{Deserialize, Serialize};

/// ZHTP request methods with Web4 extensions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ZhtpMethod {
    /// Get resource - retrieve content or data
    Get,
    /// Create resource - submit new content or data
    Post,
    /// Update resource - replace existing content
    Put,
    /// Patch resource - partial update of existing content
    Patch,
    /// Delete resource - remove content or data
    Delete,
    /// Get metadata only - retrieve headers without body
    Head,
    /// Get available methods - discover server capabilities
    Options,
    /// Verify resource proof - validate zero-knowledge proofs and signatures
    Verify,
    /// Connect to resource - establish persistent connection
    Connect,
    /// Trace request path - debug routing and mesh network
    Trace,
}

impl ZhtpMethod {
    /// Get the string representation of the method
    pub fn as_str(&self) -> &'static str {
        match self {
            ZhtpMethod::Get => "GET",
            ZhtpMethod::Post => "POST",
            ZhtpMethod::Put => "PUT",
            ZhtpMethod::Patch => "PATCH",
            ZhtpMethod::Delete => "DELETE",
            ZhtpMethod::Head => "HEAD",
            ZhtpMethod::Options => "OPTIONS",
            ZhtpMethod::Verify => "VERIFY",
            ZhtpMethod::Connect => "CONNECT",
            ZhtpMethod::Trace => "TRACE",
        }
    }

    /// Parse method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(ZhtpMethod::Get),
            "POST" => Some(ZhtpMethod::Post),
            "PUT" => Some(ZhtpMethod::Put),
            "PATCH" => Some(ZhtpMethod::Patch),
            "DELETE" => Some(ZhtpMethod::Delete),
            "HEAD" => Some(ZhtpMethod::Head),
            "OPTIONS" => Some(ZhtpMethod::Options),
            "VERIFY" => Some(ZhtpMethod::Verify),
            "CONNECT" => Some(ZhtpMethod::Connect),
            "TRACE" => Some(ZhtpMethod::Trace),
            _ => None,
        }
    }

    /// Check if method is safe (doesn't modify state)
    pub fn is_safe(&self) -> bool {
        matches!(self, 
            ZhtpMethod::Get | 
            ZhtpMethod::Head | 
            ZhtpMethod::Options | 
            ZhtpMethod::Verify | 
            ZhtpMethod::Trace
        )
    }

    /// Check if method is idempotent (multiple identical requests have same effect)
    pub fn is_idempotent(&self) -> bool {
        matches!(self,
            ZhtpMethod::Get |
            ZhtpMethod::Put |
            ZhtpMethod::Delete |
            ZhtpMethod::Head |
            ZhtpMethod::Options |
            ZhtpMethod::Verify |
            ZhtpMethod::Trace
        )
    }

    /// Check if method typically has a request body
    pub fn has_body(&self) -> bool {
        matches!(self,
            ZhtpMethod::Post |
            ZhtpMethod::Put |
            ZhtpMethod::Patch
        )
    }

    /// Check if method is a Web4 extension (not in standard HTTP)
    pub fn is_web4_extension(&self) -> bool {
        matches!(self, ZhtpMethod::Verify)
    }

    /// Get the expected response body behavior
    pub fn response_has_body(&self) -> bool {
        !matches!(self, ZhtpMethod::Head)
    }

    /// Check if method requires special permissions
    pub fn requires_special_permissions(&self) -> bool {
        matches!(self,
            ZhtpMethod::Post |
            ZhtpMethod::Put |
            ZhtpMethod::Patch |
            ZhtpMethod::Delete |
            ZhtpMethod::Verify
        )
    }

    /// Get the typical DAO fee multiplier for this method
    pub fn dao_fee_multiplier(&self) -> f64 {
        match self {
            ZhtpMethod::Get | ZhtpMethod::Head | ZhtpMethod::Options => 1.0,
            ZhtpMethod::Post => 2.0, // Higher fee for content creation
            ZhtpMethod::Put | ZhtpMethod::Patch => 1.5, // Medium fee for updates
            ZhtpMethod::Delete => 1.2, // Slightly higher for deletions
            ZhtpMethod::Verify => 0.8, // Lower fee for verification
            ZhtpMethod::Connect => 1.1, // Slightly higher for connections
            ZhtpMethod::Trace => 0.5, // Lower fee for debugging
        }
    }

    /// Get the expected economic impact level
    pub fn economic_impact(&self) -> EconomicImpact {
        match self {
            ZhtpMethod::Get | ZhtpMethod::Head | ZhtpMethod::Options | ZhtpMethod::Trace => {
                EconomicImpact::Low
            }
            ZhtpMethod::Verify | ZhtpMethod::Connect => {
                EconomicImpact::Medium
            }
            ZhtpMethod::Patch | ZhtpMethod::Delete => {
                EconomicImpact::High
            }
            ZhtpMethod::Post | ZhtpMethod::Put => {
                EconomicImpact::VeryHigh
            }
        }
    }

    /// Get all available methods
    pub fn all() -> Vec<ZhtpMethod> {
        vec![
            ZhtpMethod::Get,
            ZhtpMethod::Post,
            ZhtpMethod::Put,
            ZhtpMethod::Patch,
            ZhtpMethod::Delete,
            ZhtpMethod::Head,
            ZhtpMethod::Options,
            ZhtpMethod::Verify,
            ZhtpMethod::Connect,
            ZhtpMethod::Trace,
        ]
    }

    /// Get safe methods only
    pub fn safe_methods() -> Vec<ZhtpMethod> {
        vec![
            ZhtpMethod::Get,
            ZhtpMethod::Head,
            ZhtpMethod::Options,
            ZhtpMethod::Verify,
            ZhtpMethod::Trace,
        ]
    }

    /// Get unsafe methods (those that modify state)
    pub fn unsafe_methods() -> Vec<ZhtpMethod> {
        vec![
            ZhtpMethod::Post,
            ZhtpMethod::Put,
            ZhtpMethod::Patch,
            ZhtpMethod::Delete,
            ZhtpMethod::Connect,
        ]
    }
}

/// Economic impact level of request methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicImpact {
    /// Low impact - minimal network resources
    Low,
    /// Medium impact - moderate network resources
    Medium,
    /// High impact - significant network resources
    High,
    /// Very high impact - substantial network resources
    VeryHigh,
}

impl EconomicImpact {
    /// Get the numeric impact factor
    pub fn factor(&self) -> f64 {
        match self {
            EconomicImpact::Low => 0.5,
            EconomicImpact::Medium => 1.0,
            EconomicImpact::High => 2.0,
            EconomicImpact::VeryHigh => 3.0,
        }
    }

    /// Get description of the impact level
    pub fn description(&self) -> &'static str {
        match self {
            EconomicImpact::Low => "Low resource usage",
            EconomicImpact::Medium => "Moderate resource usage",
            EconomicImpact::High => "High resource usage",
            EconomicImpact::VeryHigh => "Very high resource usage",
        }
    }
}

impl std::fmt::Display for ZhtpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ZhtpMethod {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or("Invalid ZHTP method")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_string_conversion() {
        assert_eq!(ZhtpMethod::Get.as_str(), "GET");
        assert_eq!(ZhtpMethod::Verify.as_str(), "VERIFY");
        assert_eq!(ZhtpMethod::from_str("POST"), Some(ZhtpMethod::Post));
        assert_eq!(ZhtpMethod::from_str("INVALID"), None);
    }

    #[test]
    fn test_method_properties() {
        assert!(ZhtpMethod::Get.is_safe());
        assert!(!ZhtpMethod::Post.is_safe());
        
        assert!(ZhtpMethod::Put.is_idempotent());
        assert!(!ZhtpMethod::Post.is_idempotent());
        
        assert!(ZhtpMethod::Post.has_body());
        assert!(!ZhtpMethod::Get.has_body());
        
        assert!(ZhtpMethod::Verify.is_web4_extension());
        assert!(!ZhtpMethod::Get.is_web4_extension());
    }

    #[test]
    fn test_economic_impact() {
        assert_eq!(ZhtpMethod::Get.economic_impact(), EconomicImpact::Low);
        assert_eq!(ZhtpMethod::Post.economic_impact(), EconomicImpact::VeryHigh);
        assert_eq!(ZhtpMethod::Verify.economic_impact(), EconomicImpact::Medium);
    }

    #[test]
    fn test_dao_fee_multipliers() {
        assert_eq!(ZhtpMethod::Get.dao_fee_multiplier(), 1.0);
        assert_eq!(ZhtpMethod::Post.dao_fee_multiplier(), 2.0);
        assert_eq!(ZhtpMethod::Verify.dao_fee_multiplier(), 0.8);
    }

    #[test]
    fn test_method_collections() {
        let all_methods = ZhtpMethod::all();
        assert_eq!(all_methods.len(), 10);
        assert!(all_methods.contains(&ZhtpMethod::Verify));

        let safe_methods = ZhtpMethod::safe_methods();
        assert!(safe_methods.iter().all(|m| m.is_safe()));

        let unsafe_methods = ZhtpMethod::unsafe_methods();
        assert!(unsafe_methods.iter().all(|m| !m.is_safe()));
    }

    #[test]
    fn test_economic_impact_properties() {
        assert_eq!(EconomicImpact::Low.factor(), 0.5);
        assert_eq!(EconomicImpact::VeryHigh.factor(), 3.0);
        assert_eq!(EconomicImpact::Medium.description(), "Moderate resource usage");
    }

    #[test]
    fn test_display_and_fromstr() {
        assert_eq!(ZhtpMethod::Get.to_string(), "GET");
        assert_eq!("POST".parse::<ZhtpMethod>().unwrap(), ZhtpMethod::Post);
        assert!("INVALID".parse::<ZhtpMethod>().is_err());
    }
}

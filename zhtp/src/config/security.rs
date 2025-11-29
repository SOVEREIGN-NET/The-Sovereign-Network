//! Security Configuration Management
//! 
//! Handles post-quantum cryptography settings, ZK proof parameters, 
//! and security levels across all packages

use serde::{Deserialize, Serialize};
use std::fmt;

/// Security levels for ZHTP node operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Basic security - suitable for development only
    Basic,
    /// Medium security - suitable for testing environments
    Medium,
    /// High security - suitable for production use
    High,
    /// Maximum security - highest possible security settings
    Maximum,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Basic => write!(f, "Basic"),
            SecurityLevel::Medium => write!(f, "Medium"),
            SecurityLevel::High => write!(f, "High"),
            SecurityLevel::Maximum => write!(f, "Maximum"),
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::High // Default to high security
    }
}

/// Post-quantum cryptography settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumConfig {
    pub enabled: bool,
    pub dilithium_level: DilithiumLevel,
    pub kyber_level: KyberLevel,
    pub hybrid_mode: bool, // Use both PQ and classical crypto
    pub migration_strategy: MigrationStrategy,
}

/// CRYSTALS-Dilithium security levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumLevel {
    Level2,  // 128-bit security
    Level3,  // 192-bit security  
    Level5,  // 256-bit security
}

/// CRYSTALS-Kyber security levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KyberLevel {
    Kyber512,  // 128-bit security
    Kyber768,  // 192-bit security
    Kyber1024, // 256-bit security
}

/// Migration strategy from classical to post-quantum cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationStrategy {
    /// Immediate switch to post-quantum only
    Immediate,
    /// Gradual migration with hybrid support
    Gradual,
    /// Classical cryptography only (not recommended)
    Classical,
}

/// Zero-knowledge proof security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSecurityConfig {
    pub proof_system: ProofSystem,
    pub circuit_security_level: u32,
    pub trusted_setup_required: bool,
    pub proof_verification_threads: usize,
    pub circuit_compilation_cache: bool,
}

/// Supported zero-knowledge proof systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofSystem {
    Plonky2,  // Primary system - no trusted setup required
    Groth16,  // Alternative - requires trusted setup
    STARK,    // Alternative - no trusted setup, larger proofs
}

impl SecurityLevel {
    /// Get post-quantum configuration for this security level
    pub fn get_post_quantum_config(&self) -> PostQuantumConfig {
        match self {
            SecurityLevel::Basic => PostQuantumConfig {
                enabled: false, // Classical crypto only for development
                dilithium_level: DilithiumLevel::Level2,
                kyber_level: KyberLevel::Kyber512,
                hybrid_mode: true,
                migration_strategy: MigrationStrategy::Classical,
            },
            SecurityLevel::Medium => PostQuantumConfig {
                enabled: true,
                dilithium_level: DilithiumLevel::Level2,
                kyber_level: KyberLevel::Kyber512,
                hybrid_mode: true,
                migration_strategy: MigrationStrategy::Gradual,
            },
            SecurityLevel::High => PostQuantumConfig {
                enabled: true,
                dilithium_level: DilithiumLevel::Level3,
                kyber_level: KyberLevel::Kyber768,
                hybrid_mode: true,
                migration_strategy: MigrationStrategy::Gradual,
            },
            SecurityLevel::Maximum => PostQuantumConfig {
                enabled: true,
                dilithium_level: DilithiumLevel::Level5,
                kyber_level: KyberLevel::Kyber1024,
                hybrid_mode: false, // Pure post-quantum
                migration_strategy: MigrationStrategy::Immediate,
            },
        }
    }
    
    /// Get zero-knowledge proof configuration for this security level
    pub fn get_zk_security_config(&self) -> ZkSecurityConfig {
        match self {
            SecurityLevel::Basic => ZkSecurityConfig {
                proof_system: ProofSystem::Plonky2,
                circuit_security_level: 128,
                trusted_setup_required: false,
                proof_verification_threads: 1,
                circuit_compilation_cache: true,
            },
            SecurityLevel::Medium => ZkSecurityConfig {
                proof_system: ProofSystem::Plonky2,
                circuit_security_level: 128,
                trusted_setup_required: false,
                proof_verification_threads: 2,
                circuit_compilation_cache: true,
            },
            SecurityLevel::High => ZkSecurityConfig {
                proof_system: ProofSystem::Plonky2,
                circuit_security_level: 192,
                trusted_setup_required: false,
                proof_verification_threads: 4,
                circuit_compilation_cache: true,
            },
            SecurityLevel::Maximum => ZkSecurityConfig {
                proof_system: ProofSystem::Plonky2,
                circuit_security_level: 256,
                trusted_setup_required: false,
                proof_verification_threads: 8,
                circuit_compilation_cache: false, // Always recompile for maximum security
            },
        }
    }
    
    /// Get memory security settings for this level
    pub fn get_memory_security_config(&self) -> MemorySecurityConfig {
        MemorySecurityConfig {
            secure_memory_wiping: matches!(self, SecurityLevel::High | SecurityLevel::Maximum),
            stack_protection: matches!(self, SecurityLevel::Medium | SecurityLevel::High | SecurityLevel::Maximum),
            heap_protection: matches!(self, SecurityLevel::High | SecurityLevel::Maximum),
            constant_time_operations: true, // Always enabled
            side_channel_protection: matches!(self, SecurityLevel::High | SecurityLevel::Maximum),
        }
    }
    
    /// Get network security settings for this level
    pub fn get_network_security_config(&self) -> NetworkSecurityConfig {
        NetworkSecurityConfig {
            tls_min_version: match self {
                SecurityLevel::Basic => TlsVersion::V1_2,
                _ => TlsVersion::V1_3,
            },
            perfect_forward_secrecy: matches!(self, SecurityLevel::High | SecurityLevel::Maximum),
            certificate_pinning: matches!(self, SecurityLevel::High | SecurityLevel::Maximum),
            encrypted_mesh_traffic: true, // Always encrypted
            post_quantum_tls: matches!(self, SecurityLevel::Maximum),
        }
    }
    
    /// Validate that security level is appropriate for environment
    pub fn validate_for_environment(&self, environment: &super::Environment) -> Result<(), String> {
        use super::Environment;
        
        match (self, environment) {
            (SecurityLevel::Basic, Environment::Mainnet) => {
                Err("Basic security level not allowed in mainnet environment".to_string())
            }
            (SecurityLevel::Basic, Environment::Testnet) => {
                tracing::warn!("Basic security level not recommended for testnet");
                Ok(())
            }
            (SecurityLevel::Medium, Environment::Mainnet) => {
                tracing::warn!("Medium security level not recommended for mainnet");
                Ok(())
            }
            _ => Ok(())
        }
    }
}

/// Memory protection and secure computation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySecurityConfig {
    pub secure_memory_wiping: bool,
    pub stack_protection: bool,
    pub heap_protection: bool,
    pub constant_time_operations: bool,
    pub side_channel_protection: bool,
}

/// Network-level security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    pub tls_min_version: TlsVersion,
    pub perfect_forward_secrecy: bool,
    pub certificate_pinning: bool,
    pub encrypted_mesh_traffic: bool,
    pub post_quantum_tls: bool,
}

/// Supported TLS versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

impl Default for PostQuantumConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dilithium_level: DilithiumLevel::Level3,
            kyber_level: KyberLevel::Kyber768,
            hybrid_mode: true,
            migration_strategy: MigrationStrategy::Gradual,
        }
    }
}

impl Default for ZkSecurityConfig {
    fn default() -> Self {
        Self {
            proof_system: ProofSystem::Plonky2,
            circuit_security_level: 192,
            trusted_setup_required: false,
            proof_verification_threads: 4,
            circuit_compilation_cache: true,
        }
    }
}

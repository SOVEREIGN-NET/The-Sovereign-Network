//! Private service modules for IdentityManager
//!
//! This module contains the internal service implementations used by IdentityManager.
//! Services are NOT part of the public API and should only be accessed through
//! IdentityManager's public methods.
//!
//! Service Architecture:
//! - IdentityRegistry: Storage and retrieval of identity data
//! - SigningService: Cryptographic operations (signing, proofs)
//! - RecoveryService: Identity recovery and recovery key management
//! - CredentialService: Credential management and verification

pub(super) mod identity_registry;
pub(super) mod signing_service;
pub(super) mod recovery_service;
pub(super) mod credential_service;

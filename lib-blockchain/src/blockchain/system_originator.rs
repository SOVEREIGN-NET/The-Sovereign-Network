//! Typed system-transaction originators (audit follow-up: compile-time exhaustiveness).

/// Subsystem identity for `add_system_transaction` injectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemOriginator {
    PouwMint,
    PouwReward,
    AdminSovMint,
    GenesisBootstrap,
    GenesisWallet,
    MigrationWallet,
    TreasuryKernel,
    TreasuryAllocation,
    TreasuryWalletBootstrap,
    AutoWalletRegistration,
    AutoIdentityRegistration,
    IdentityProvisioning,
    KyberKeyUpdate,
    CredentialClaim,
    CredentialRegister,
    CredentialPasswordUpdate,
    OpaqueCredentialRegister,
    SeedRecoveryIdentity,
    RecoveryFallbackWallet,
    Web4DomainRegister,
    Web4DomainUpdate,
    IpcExternal,
    DurabilityTest,
    TestOriginator,
    Other(&'static str),
}

impl SystemOriginator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PouwMint => "pouw_mint",
            Self::PouwReward => "pouw_reward",
            Self::AdminSovMint => "admin_sov_mint",
            Self::GenesisBootstrap => "genesis_bootstrap",
            Self::GenesisWallet => "genesis_wallet",
            Self::MigrationWallet => "migration_wallet",
            Self::TreasuryKernel => "treasury_kernel",
            Self::TreasuryAllocation => "treasury_allocation",
            Self::TreasuryWalletBootstrap => "treasury_wallet_bootstrap",
            Self::AutoWalletRegistration => "auto_wallet_registration",
            Self::AutoIdentityRegistration => "auto_identity_registration",
            Self::IdentityProvisioning => "identity_provisioning",
            Self::KyberKeyUpdate => "kyber_key_update",
            Self::CredentialClaim => "credential_claim",
            Self::CredentialRegister => "credential_register",
            Self::CredentialPasswordUpdate => "credential_password_update",
            Self::OpaqueCredentialRegister => "opaque_credential_register",
            Self::SeedRecoveryIdentity => "seed_recovery_identity",
            Self::RecoveryFallbackWallet => "recovery_fallback_wallet",
            Self::Web4DomainRegister => "web4_domain_register",
            Self::Web4DomainUpdate => "web4_domain_update",
            Self::IpcExternal => "ipc_external",
            Self::DurabilityTest => "durability_test",
            Self::TestOriginator => "test_originator",
            Self::Other(label) => label,
        }
    }

    pub fn is_treasury(self) -> bool {
        matches!(
            self,
            Self::AdminSovMint
                | Self::GenesisBootstrap
                | Self::GenesisWallet
                | Self::MigrationWallet
                | Self::TreasuryKernel
                | Self::TreasuryAllocation
                | Self::TreasuryWalletBootstrap
        )
    }

    pub fn allows_unsigned_domain_tx(self) -> bool {
        false
    }
}
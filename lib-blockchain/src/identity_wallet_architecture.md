# Identity & Wallet Architecture Design

## Overview
New architecture separating anonymous wallets from verified ZK-DIDs, with specialized DAO structures.

## Core Components

### 1. Wallet System (Traditional Blockchain)
```rust
pub struct Wallet {
    pub address: WalletAddress,     // 32-byte address (like Bitcoin)
    pub public_key: PublicKey,      // For transaction signing
    pub balance: u64,               // Token balance
    pub nonce: u64,                 // Transaction counter
    pub associated_node: NodeId,    // Connected ZHTP node
}

pub struct WalletAddress([u8; 32]);

impl Wallet {
    /// Create new anonymous wallet (no KYC required)
    pub fn new(node_id: NodeId) -> Self;
    
    /// Transfer funds to another wallet
    pub fn transfer(&self, to: WalletAddress, amount: u64) -> Transaction;
    
    /// Connect wallet to a ZK-DID (optional)
    pub fn associate_with_did(&mut self, did: ZkDid) -> Result<()>;
}
```

### 2. ZK-DID System (DNS Layer)
```rust
pub struct ZkDid {
    pub did: DidIdentifier,         // did:zhtp:abc123...
    pub owner_wallet: WalletAddress, // Primary wallet
    pub verification_level: KycLevel,
    pub associated_wallets: Vec<WalletAddress>,
    pub controlled_daos: Vec<DaoId>,
    pub dns_records: HashMap<String, DnsRecord>,
}

pub enum KycLevel {
    Basic,          // Age verification
    Enhanced,       // Government ID
    Corporate,      // Business verification
}

pub enum DnsRecord {
    Wallet(WalletAddress),
    Service(ServiceEndpoint),
    Dao(DaoId),
}

impl ZkDid {
    /// Create ZK-DID (KYC required)
    pub async fn create_with_kyc(kyc_proof: KycProof) -> Result<Self>;
    
    /// Resolve DNS-like queries
    pub fn resolve(&self, query: &str) -> Option<DnsRecord>;
    
    /// Transfer DAO ownership (for-profit only)
    pub fn transfer_dao(&mut self, dao_id: DaoId, to_did: ZkDid) -> Result<()>;
}
```

### 3. DAO Classification System
```rust
pub enum DaoType {
    ForProfit {
        owner_did: ZkDid,           // Can be transferred
        corporate_wallet: WalletAddress,
    },
    NonProfit {
        governance_wallet: WalletAddress,  // Public, no owner
        transparency_required: bool,
    },
}

pub struct Dao {
    pub dao_id: DaoId,
    pub dao_type: DaoType,
    pub wallet: WalletAddress,      // DAO's treasury wallet
    pub governance_token: Option<TokenId>,
    pub members: Vec<ZkDid>,
    pub proposals: Vec<Proposal>,
}

impl Dao {
    /// Create for-profit DAO (owned by ZK-DID)
    pub fn create_for_profit(owner_did: ZkDid) -> Result<Self>;
    
    /// Create non-profit DAO (public, no owner)
    pub fn create_non_profit(founding_members: Vec<ZkDid>) -> Result<Self>;
    
    /// Transfer for-profit DAO ownership
    pub fn transfer_ownership(&mut self, new_owner: ZkDid) -> Result<()>;
}
```

## Architecture Flow

### Wallet Creation (Anonymous)
1. User runs ZHTP node
2. Creates wallet address (no KYC)
3. Wallet connects to node
4. Can send/receive transactions anonymously

### ZK-DID Creation (KYC Required)
1. User submits KYC verification
2. Zero-knowledge proof generated
3. ZK-DID created and linked to wallet
4. DNS-like resolution enabled

### DAO Operations
```
For-Profit DAO:
ZK-DID → owns → DAO → controls → Wallet
     ↓
Can transfer entire chain to another ZK-DID

Non-Profit DAO:
Public Governance → DAO → controls → Wallet
                    ↓
Cannot be owned or transferred
```

## Privacy Model

### Wallet Level (Anonymous)
- Wallet addresses are pseudonymous
- Transactions use ring signatures
- No identity required

### ZK-DID Level (Verified but Private)
- Identity verified with zero-knowledge proofs
- DNS resolution without revealing identity
- Can control multiple wallets/DAOs

### DAO Level (Transparent)
- For-profit: Private control via ZK-DID
- Non-profit: Public governance, transparent operations

## Examples

### Individual User
```
User creates:
1. Wallet: addr_abc123... (anonymous)
2. ZK-DID: did:zhtp:user456 (KYC verified)

ZK-DID resolves:
- wallet.user.zhtp → addr_abc123...
- profile.user.zhtp → service_endpoint
```

### For-Profit Company
```
Company creates:
1. Corporate ZK-DID: did:zhtp:company789 (business KYC)
2. DAO: TechCorp DAO (owned by ZK-DID)
3. Wallet: addr_def456... (DAO treasury)

Can transfer:
- Entire DAO ownership to another ZK-DID
- Like selling a company
```

### Non-Profit Organization
```
Non-profit creates:
1. Public DAO: OpenSource Foundation
2. Wallet: addr_ghi789... (public treasury)
3. No owner ZK-DID (community governed)

Cannot:
- Be owned by any individual
- Be transferred or sold
```

## Benefits

### Privacy
- Wallets anonymous by default
- ZK-DIDs provide verified identity without revealing details
- Users control privacy level

### Flexibility
- Traditional blockchain wallet experience
- Optional identity layer
- DNS-like resolution for user-friendly addresses

### Governance
- Clear distinction between private/public organizations
- For-profit DAOs can be bought/sold
- Non-profits remain community-owned

### Compliance
- KYC only required for verified identity (ZK-DID)
- Anonymous wallets for privacy
- Corporate structures for business use
# Transaction Types

The ZHTP blockchain supports 20 transaction types organized into functional categories.

## Value Transfer

| Type | Description |
|------|-------------|
| `Transfer` | Standard value transfer between accounts |

## Identity Management

| Type | Description |
|------|-------------|
| `IdentityRegistration` | Register new identity on blockchain |
| `IdentityUpdate` | Modify identity metadata |
| `IdentityRevocation` | Revoke an identity |

## Wallet

| Type | Description |
|------|-------------|
| `WalletRegistration` | Create/register wallet on blockchain |

## Validator/Consensus

| Type | Description |
|------|-------------|
| `ValidatorRegistration` | Join validator set for consensus participation |
| `ValidatorUpdate` | Update validator information |
| `ValidatorUnregister` | Exit validator set |

## Smart Contracts

| Type | Description |
|------|-------------|
| `ContractDeployment` | Deploy smart contract |
| `ContractExecution` | Execute contract method |

## DAO Governance

| Type | Description |
|------|-------------|
| `DaoProposal` | Submit governance proposal |
| `DaoVote` | Vote on proposal |
| `DaoExecution` | Execute approved proposal (treasury spending) |
| `DifficultyUpdate` | Update difficulty parameters (via DAO governance) |

## Economic

| Type | Description |
|------|-------------|
| `UbiDistribution` | System-initiated UBI distribution |
| `UBIClaim` | Citizen-initiated UBI claim (pull-based) |
| `ProfitDeclaration` | Declare profit, enforces 20% tribute to nonprofit |

## Content/Sessions

| Type | Description |
|------|-------------|
| `ContentUpload` | Upload content transaction |
| `SessionCreation` | Create session for audit/tracking |
| `SessionTermination` | End session |

---

## Transaction Type Categories

The transaction types can be queried programmatically:

```rust
// Identity transactions
tx_type.is_identity_transaction()  // IdentityRegistration, IdentityUpdate, IdentityRevocation

// Contract transactions
tx_type.is_contract_transaction()  // ContractDeployment, ContractExecution

// Validator transactions
tx_type.is_validator_transaction() // ValidatorRegistration, ValidatorUpdate, ValidatorUnregister

// DAO transactions
tx_type.is_dao_transaction()       // DaoProposal, DaoVote, DaoExecution, DifficultyUpdate

// Transfer
tx_type.is_transfer()              // Transfer

// UBI claim
tx_type.is_ubi_claim()             // UBIClaim

// Profit declaration
tx_type.is_profit_declaration()    // ProfitDeclaration
```

## String Identifiers

Each transaction type has a string identifier for serialization:

| Type | String ID |
|------|-----------|
| Transfer | `transfer` |
| IdentityRegistration | `identity_registration` |
| IdentityUpdate | `identity_update` |
| IdentityRevocation | `identity_revocation` |
| ContractDeployment | `contract_deployment` |
| ContractExecution | `contract_execution` |
| SessionCreation | `session_creation` |
| SessionTermination | `session_termination` |
| ContentUpload | `content_upload` |
| UbiDistribution | `ubi_distribution` |
| WalletRegistration | `wallet_registration` |
| ValidatorRegistration | `validator_registration` |
| ValidatorUpdate | `validator_update` |
| ValidatorUnregister | `validator_unregister` |
| DaoProposal | `dao_proposal` |
| DaoVote | `dao_vote` |
| DaoExecution | `dao_execution` |
| DifficultyUpdate | `difficulty_update` |
| UBIClaim | `ubi_claim` |
| ProfitDeclaration | `profit_declaration` |

---

*Source: `lib-blockchain/src/types/transaction_type.rs`*

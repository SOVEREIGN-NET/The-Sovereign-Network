# Contract Deployment Transaction Schema (V1)

Canonical deployment transactions use `TransactionType::ContractDeployment` and must encode memo bytes as:

`ZHTP_DEPLOY_V1:` + `bincode(ContractDeploymentPayloadV1)`

## Payload

`ContractDeploymentPayloadV1` fields:

- `contract_type: String` (required)
- `code: Vec<u8>` (required, max 8192 bytes)
- `abi: Vec<u8>` (required, max 4096 bytes)
- `init_args: Vec<u8>` (optional, max 2048 bytes)
- `gas_limit: u64` (required, range `1..=MAX_TX_GAS`)
- `memory_limit_bytes: u32` (required, range `1..=16777216`)

Validation is enforced in `TransactionValidator::validate_contract_transaction`.

## Canonical Builder

Use `create_contract_deployment_transaction(...)` from `lib-blockchain::transaction::creation`, which validates and encodes memo payload via `ContractDeploymentPayloadV1::encode_memo()`.

## Example (Rust)

```rust
use lib_blockchain::transaction::{
    ContractDeploymentPayloadV1, create_contract_deployment_transaction
};

let payload = ContractDeploymentPayloadV1 {
    contract_type: "wasm".to_string(),
    code: vec![0x00, 0x61, 0x73, 0x6d],
    abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
    init_args: vec![],
    gas_limit: 100_000,
    memory_limit_bytes: 65_536,
};

let tx = create_contract_deployment_transaction(inputs, outputs, payload, fee, &private_key)?;
```

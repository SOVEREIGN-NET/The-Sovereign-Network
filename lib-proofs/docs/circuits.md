# ZK Circuit Implementation Guide

This guide covers the cryptographic circuits and constraints used in lib-proofs' zero-knowledge proof system.

## Circuit Architecture Overview

lib-proofs uses Plonky2 as the backend proof system, which provides efficient arithmetic circuits over finite fields. Our circuits are designed for:

- **High Performance**: Optimized for both proving and verification speed
- **Low Memory Usage**: Efficient circuit construction and witness generation
- **Composability**: Circuits can be combined and nested recursively
- **Security**: Based on proven cryptographic assumptions

## Core Circuit Types

### 1. Transaction Circuits

Transaction circuits prove knowledge of valid financial transactions without revealing sensitive information.

#### Circuit Structure
```rust
// Conceptual circuit layout (actual implementation in Plonky2)
pub struct TransactionCircuit {
    // Public inputs
    pub amount_commitment: FieldElement,
    pub balance_commitment: FieldElement,
    pub nullifier: FieldElement,
    pub merkle_root: FieldElement,
    
    // Private witnesses
    sender_balance: FieldElement,
    amount: FieldElement,
    fee: FieldElement,
    sender_secret: FieldElement,
    nullifier_seed: FieldElement,
    merkle_path: Vec<FieldElement>,
}
```

#### Constraints
1. **Balance Constraint**: `sender_balance >= amount + fee`
2. **Commitment Consistency**: Commitments match private values
3. **Nullifier Uniqueness**: Nullifier derived correctly from secret
4. **Merkle Path Verification**: Sender's balance is in the state tree

#### Circuit Implementation Pattern
```rust
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;

impl TransactionCircuit {
    pub fn build_circuit(builder: &mut CircuitBuilder<F, 2>) -> TransactionTargets {
        // Public inputs
        let amount_commitment = builder.add_public_input();
        let balance_commitment = builder.add_public_input();
        let nullifier = builder.add_public_input();
        let merkle_root = builder.add_public_input();
        
        // Private witnesses
        let sender_balance = builder.add_private_input();
        let amount = builder.add_private_input();
        let fee = builder.add_private_input();
        let sender_secret = builder.add_private_input();
        let nullifier_seed = builder.add_private_input();
        
        // Constraint 1: Balance sufficiency
        let total_spent = builder.add(amount, fee);
        let balance_check = builder.sub(sender_balance, total_spent);
        
        // This would be a range check constraint in practice
        // ensure balance_check >= 0
        
        // Constraint 2: Commitment consistency
        // amount_commitment = hash(amount, randomness)
        let amount_hash = builder.hash_n_to_1([amount, /* randomness */]);
        builder.connect(amount_commitment, amount_hash);
        
        // Constraint 3: Nullifier derivation
        // nullifier = hash(sender_secret, nullifier_seed)
        let nullifier_hash = builder.hash_n_to_1([sender_secret, nullifier_seed]);
        builder.connect(nullifier, nullifier_hash);
        
        // Constraint 4: Merkle path verification
        // This would implement a merkle tree inclusion proof
        
        TransactionTargets {
            amount_commitment,
            balance_commitment,
            nullifier,
            merkle_root,
            sender_balance,
            amount,
            fee,
            sender_secret,
            nullifier_seed,
        }
    }
}
```

### 2. Range Proof Circuits

Range proofs demonstrate that a secret value lies within a specified range without revealing the value.

#### Circuit Structure
```rust
pub struct RangeCircuit {
    // Public inputs
    pub commitment: FieldElement,
    pub range_min: FieldElement,
    pub range_max: FieldElement,
    
    // Private witnesses
    value: FieldElement,
    randomness: FieldElement,
}
```

#### Binary Decomposition Method
```rust
impl RangeCircuit {
    pub fn build_range_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        bit_width: usize,
    ) -> RangeTargets {
        let commitment = builder.add_public_input();
        let range_min = builder.add_public_input();
        let range_max = builder.add_public_input();
        
        let value = builder.add_private_input();
        let randomness = builder.add_private_input();
        
        // Decompose value into bits
        let mut bits = Vec::new();
        let mut current_value = value;
        
        for i in 0..bit_width {
            let bit = builder.add_private_input();
            bits.push(bit);
            
            // Constrain bit to be 0 or 1
            let bit_constraint = builder.mul(bit, builder.sub(builder.one(), bit));
            builder.assert_zero(bit_constraint);
            
            // Update current_value = current_value - bit * 2^i
            let power_of_two = builder.constant(F::from_canonical_u64(1u64 << i));
            let bit_contribution = builder.mul(bit, power_of_two);
            current_value = builder.sub(current_value, bit_contribution);
        }
        
        // Assert that decomposition is complete
        builder.assert_zero(current_value);
        
        // Range check: range_min <= value <= range_max
        let value_minus_min = builder.sub(value, range_min);
        let max_minus_value = builder.sub(range_max, value);
        
        // These would need range check gadgets
        // ensure_non_negative(value_minus_min);
        // ensure_non_negative(max_minus_value);
        
        // Commitment verification
        let computed_commitment = builder.hash_n_to_1([value, randomness]);
        builder.connect(commitment, computed_commitment);
        
        RangeTargets {
            commitment,
            range_min,
            range_max,
            value,
            randomness,
            bits,
        }
    }
}
```

### 3. Identity Verification Circuits

Identity circuits prove attributes about an identity without revealing the identity itself.

#### Circuit Structure
```rust
pub struct IdentityCircuit {
    // Public inputs
    pub identity_commitment: FieldElement,
    pub min_age: FieldElement,
    pub required_jurisdiction: FieldElement,
    pub credential_requirement: FieldElement,
    
    // Private witnesses
    age: FieldElement,
    jurisdiction: FieldElement,
    credential_hash: FieldElement,
    identity_secret: FieldElement,
    randomness: FieldElement,
}
```

#### Constraint Implementation
```rust
impl IdentityCircuit {
    pub fn build_identity_circuit(builder: &mut CircuitBuilder<F, 2>) -> IdentityTargets {
        // Public inputs
        let identity_commitment = builder.add_public_input();
        let min_age = builder.add_public_input();
        let required_jurisdiction = builder.add_public_input();
        let credential_requirement = builder.add_public_input();
        
        // Private witnesses
        let age = builder.add_private_input();
        let jurisdiction = builder.add_private_input();
        let credential_hash = builder.add_private_input();
        let identity_secret = builder.add_private_input();
        let randomness = builder.add_private_input();
        
        // Age constraint: age >= min_age
        let age_diff = builder.sub(age, min_age);
        // Range check to ensure age_diff >= 0
        
        // Jurisdiction constraint: jurisdiction == required_jurisdiction OR required_jurisdiction == 0
        let jurisdiction_match = builder.sub(jurisdiction, required_jurisdiction);
        let jurisdiction_selector = builder.is_equal(required_jurisdiction, builder.zero());
        let jurisdiction_constraint = builder.mul(jurisdiction_match, 
            builder.sub(builder.one(), jurisdiction_selector));
        builder.assert_zero(jurisdiction_constraint);
        
        // Credential constraint: credential_hash == credential_requirement OR credential_requirement == 0
        let credential_match = builder.sub(credential_hash, credential_requirement);
        let credential_selector = builder.is_equal(credential_requirement, builder.zero());
        let credential_constraint = builder.mul(credential_match,
            builder.sub(builder.one(), credential_selector));
        builder.assert_zero(credential_constraint);
        
        // Identity commitment verification
        let computed_commitment = builder.hash_n_to_1([
            age, jurisdiction, credential_hash, identity_secret, randomness
        ]);
        builder.connect(identity_commitment, computed_commitment);
        
        IdentityTargets {
            identity_commitment,
            min_age,
            required_jurisdiction,
            credential_requirement,
            age,
            jurisdiction,
            credential_hash,
            identity_secret,
            randomness,
        }
    }
}
```

### 4. Storage Access Circuits

Storage circuits prove authorized access to data without revealing access credentials.

#### Circuit Structure
```rust
pub struct StorageAccessCircuit {
    // Public inputs
    pub access_granted: FieldElement,
    pub resource_hash: FieldElement,
    pub required_permission: FieldElement,
    
    // Private witnesses
    access_key: FieldElement,
    user_secret: FieldElement,
    user_permission_level: FieldElement,
}
```

#### Permission Logic Circuit
```rust
impl StorageAccessCircuit {
    pub fn build_access_circuit(builder: &mut CircuitBuilder<F, 2>) -> StorageTargets {
        let access_granted = builder.add_public_input();
        let resource_hash = builder.add_public_input();
        let required_permission = builder.add_public_input();
        
        let access_key = builder.add_private_input();
        let user_secret = builder.add_private_input();
        let user_permission_level = builder.add_private_input();
        
        // Key derivation: access_key = hash(user_secret, resource_hash)
        let derived_key = builder.hash_n_to_1([user_secret, resource_hash]);
        builder.connect(access_key, derived_key);
        
        // Permission check: user_permission_level >= required_permission
        let permission_diff = builder.sub(user_permission_level, required_permission);
        // Range check to ensure permission_diff >= 0
        
        // Access decision: access_granted = (permission_diff >= 0) ? 1 : 0
        // This would use a comparison gadget in practice
        
        StorageTargets {
            access_granted,
            resource_hash,
            required_permission,
            access_key,
            user_secret,
            user_permission_level,
        }
    }
}
```

### 5. Routing Circuits

Routing circuits prove network routing capabilities without revealing network topology.

#### Circuit Structure
```rust
pub struct RoutingCircuit {
    // Public inputs
    pub source_node: FieldElement,
    pub destination_node: FieldElement,
    pub max_hops: FieldElement,
    pub min_bandwidth: FieldElement,
    pub routing_feasible: FieldElement,
    
    // Private witnesses
    hop_count: FieldElement,
    available_bandwidth: FieldElement,
    route_latency: FieldElement,
    routing_secret: FieldElement,
}
```

#### Network Constraint Implementation
```rust
impl RoutingCircuit {
    pub fn build_routing_circuit(builder: &mut CircuitBuilder<F, 2>) -> RoutingTargets {
        let source_node = builder.add_public_input();
        let destination_node = builder.add_public_input();
        let max_hops = builder.add_public_input();
        let min_bandwidth = builder.add_public_input();
        let routing_feasible = builder.add_public_input();
        
        let hop_count = builder.add_private_input();
        let available_bandwidth = builder.add_private_input();
        let route_latency = builder.add_private_input();
        let routing_secret = builder.add_private_input();
        
        // Hop count constraint: hop_count <= max_hops
        let hop_diff = builder.sub(max_hops, hop_count);
        // Range check: hop_diff >= 0
        
        // Bandwidth constraint: available_bandwidth >= min_bandwidth
        let bandwidth_diff = builder.sub(available_bandwidth, min_bandwidth);
        // Range check: bandwidth_diff >= 0
        
        // Route authentication: verify routing_secret is valid for this path
        let route_hash = builder.hash_n_to_1([
            source_node, destination_node, hop_count, routing_secret
        ]);
        // Additional constraints would verify route_hash against network state
        
        // Feasibility decision
        let hop_feasible = builder.is_zero(builder.sub(max_hops, hop_count));
        let bandwidth_feasible = builder.is_zero(builder.sub(available_bandwidth, min_bandwidth));
        let route_feasible = builder.and(hop_feasible, bandwidth_feasible);
        builder.connect(routing_feasible, route_feasible);
        
        RoutingTargets {
            source_node,
            destination_node,
            max_hops,
            min_bandwidth,
            routing_feasible,
            hop_count,
            available_bandwidth,
            route_latency,
            routing_secret,
        }
    }
}
```

### 6. Data Integrity Circuits

Data integrity circuits prove correct storage and handling of data without revealing the data content.

#### Circuit Structure
```rust
pub struct DataIntegrityCircuit {
    // Public inputs
    pub data_hash: FieldElement,
    pub max_chunks: FieldElement,
    pub max_size: FieldElement,
    pub integrity_verified: FieldElement,
    
    // Private witnesses
    chunk_count: FieldElement,
    total_size: FieldElement,
    checksum: FieldElement,
    storage_secret: FieldElement,
    timestamp: FieldElement,
}
```

#### Integrity Verification Circuit
```rust
impl DataIntegrityCircuit {
    pub fn build_integrity_circuit(builder: &mut CircuitBuilder<F, 2>) -> IntegrityTargets {
        let data_hash = builder.add_public_input();
        let max_chunks = builder.add_public_input();
        let max_size = builder.add_public_input();
        let integrity_verified = builder.add_public_input();
        
        let chunk_count = builder.add_private_input();
        let total_size = builder.add_private_input();
        let checksum = builder.add_private_input();
        let storage_secret = builder.add_private_input();
        let timestamp = builder.add_private_input();
        
        // Size constraints
        let size_diff = builder.sub(max_size, total_size);
        // Range check: size_diff >= 0
        
        let chunk_diff = builder.sub(max_chunks, chunk_count);
        // Range check: chunk_diff >= 0
        
        // Data integrity verification
        let integrity_hash = builder.hash_n_to_1([
            chunk_count, total_size, checksum, storage_secret, timestamp
        ]);
        builder.connect(data_hash, integrity_hash);
        
        // All constraints satisfied
        let size_valid = builder.is_zero(builder.sub(max_size, total_size));
        let chunk_valid = builder.is_zero(builder.sub(max_chunks, chunk_count));
        let integrity_valid = builder.and(size_valid, chunk_valid);
        builder.connect(integrity_verified, integrity_valid);
        
        IntegrityTargets {
            data_hash,
            max_chunks,
            max_size,
            integrity_verified,
            chunk_count,
            total_size,
            checksum,
            storage_secret,
            timestamp,
        }
    }
}
```

## Advanced Circuit Techniques

### Recursive Proof Composition

```rust
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

pub struct RecursiveCircuit {
    inner_proof_targets: Vec<Target>,
    verification_targets: Vec<Target>,
}

impl RecursiveCircuit {
    pub fn build_recursive_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        inner_circuit_data: &CircuitData<F, C, 2>,
    ) -> RecursiveTargets {
        // Add targets for the inner proof
        let inner_proof_targets = builder.add_proof_targets_inner_circuit(inner_circuit_data);
        
        // Verify the inner proof within this circuit
        builder.verify_proof_inner_circuit(&inner_proof_targets, inner_circuit_data);
        
        // Add additional constraints on the verified proof's public inputs
        let verified_amount = inner_proof_targets.public_inputs[0];
        let verified_balance = inner_proof_targets.public_inputs[1];
        
        // Example: Aggregate multiple transaction proofs
        let total_amount = builder.add(verified_amount, /* other amounts */);
        
        RecursiveTargets {
            inner_proof_targets,
            total_amount,
        }
    }
}
```

### Lookup Tables for Efficiency

```rust
use plonky2::gates::lookup_table::LookupTable;

pub fn create_range_lookup_table(max_value: u64) -> LookupTable {
    // Pre-compute range check values for efficiency
    let mut table_data = Vec::new();
    
    for i in 0..=max_value {
        table_data.push(vec![
            F::from_canonical_u64(i),      // value
            F::from_canonical_u64(i * i),  // value^2
            F::from_canonical_u64(if i < max_value { 1 } else { 0 }), // in_range
        ]);
    }
    
    LookupTable::new(
        "range_check",
        table_data,
        vec!["value", "value_squared", "in_range"],
    )
}

pub fn use_lookup_table_in_circuit(
    builder: &mut CircuitBuilder<F, 2>,
    lookup_table: &LookupTable,
) -> LookupTargets {
    let value = builder.add_private_input();
    
    // Look up the range check result
    let lookup_result = builder.add_lookup_table_target(lookup_table, &[value]);
    let in_range = lookup_result[2]; // Third column is in_range flag
    
    // Use the lookup result in constraints
    builder.assert_one(in_range); // Assert value is in range
    
    LookupTargets {
        value,
        in_range,
    }
}
```

### Custom Gates for Specialized Operations

```rust
use plonky2::gates::gate::Gate;
use plonky2::iop::wire::Wire;

pub struct HashGate {
    num_inputs: usize,
}

impl HashGate {
    pub fn new(num_inputs: usize) -> Self {
        Self { num_inputs }
    }
}

impl<F: Field> Gate<F> for HashGate {
    fn id(&self) -> String {
        format!("HashGate({})", self.num_inputs)
    }
    
    fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_u32::<LittleEndian>(self.num_inputs as u32)
    }
    
    fn deserialize(src: &mut &[u8]) -> IoResult<Self> {
        let num_inputs = src.read_u32::<LittleEndian>()? as usize;
        Ok(Self::new(num_inputs))
    }
    
    fn eval_unfiltered(&self, vars: EvaluationVars<F>) -> Vec<F> {
        // Implement hash function constraints
        let inputs = &vars.local_wires[0..self.num_inputs];
        let output = vars.local_wires[self.num_inputs];
        
        // Hash constraint: output = hash(inputs)
        // This would implement the actual hash function arithmetic
        vec![output - self.compute_hash(inputs)]
    }
    
    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        // Circuit version of eval_unfiltered
        let inputs = &vars.local_wires[0..self.num_inputs];
        let output = vars.local_wires[self.num_inputs];
        
        let computed_hash = self.compute_hash_circuit(builder, inputs);
        vec![builder.sub_extension(output, computed_hash)]
    }
}
```

## Circuit Optimization Strategies

### 1. Constraint Minimization

```rust
// Instead of multiple individual constraints
fn inefficient_constraints(builder: &mut CircuitBuilder<F, 2>, a: Target, b: Target, c: Target) {
    let ab = builder.mul(a, b);
    let ab_plus_c = builder.add(ab, c);
    let result1 = builder.mul(ab_plus_c, a);
    
    let bc = builder.mul(b, c);
    let bc_plus_a = builder.add(bc, a);
    let result2 = builder.mul(bc_plus_a, b);
    
    builder.connect(result1, result2);
}

// Combine into fewer, more complex constraints
fn efficient_constraints(builder: &mut CircuitBuilder<F, 2>, a: Target, b: Target, c: Target) {
    // Single constraint: a*(a*b + c) = b*(b*c + a)
    // Expanded: a²b + ac = b²c + ab
    // Rearranged: a²b - b²c + ac - ab = 0
    // Factored: b(a² - bc) + a(c - b) = 0
    
    let a_squared = builder.mul(a, a);
    let b_squared = builder.mul(b, b);
    let ab = builder.mul(a, b);
    let bc = builder.mul(b, c);
    let ac = builder.mul(a, c);
    
    let term1 = builder.mul(a, ab);      // a²b
    let term2 = builder.mul(b_squared, c); // b²c
    let left_side = builder.add(term1, ac);   // a²b + ac
    let right_side = builder.add(term2, ab);  // b²c + ab
    
    let constraint = builder.sub(left_side, right_side);
    builder.assert_zero(constraint);
}
```

### 2. Wire Reuse

```rust
fn optimized_wire_usage(builder: &mut CircuitBuilder<F, 2>) -> OptimizedTargets {
    let input1 = builder.add_private_input();
    let input2 = builder.add_private_input();
    
    // Reuse intermediate computations
    let squared1 = builder.mul(input1, input1);
    let squared2 = builder.mul(input2, input2);
    
    // Use the same squared values multiple times
    let sum_of_squares = builder.add(squared1, squared2);
    let product_of_squares = builder.mul(squared1, squared2);
    let diff_of_squares = builder.sub(squared1, squared2);
    
    OptimizedTargets {
        input1,
        input2,
        squared1,
        squared2,
        sum_of_squares,
        product_of_squares,
        diff_of_squares,
    }
}
```

### 3. Parallel Constraint Evaluation

```rust
use rayon::prelude::*;

pub struct ParallelCircuitBuilder {
    constraints: Vec<ConstraintGroup>,
}

impl ParallelCircuitBuilder {
    pub fn evaluate_constraints_parallel(&self, witness: &[F]) -> Vec<F> {
        self.constraints
            .par_iter()
            .flat_map(|group| group.evaluate_parallel(witness))
            .collect()
    }
}

struct ConstraintGroup {
    constraints: Vec<Constraint>,
    dependencies: Vec<usize>, // Wire indices this group depends on
}

impl ConstraintGroup {
    fn evaluate_parallel(&self, witness: &[F]) -> Vec<F> {
        self.constraints
            .par_iter()
            .map(|constraint| constraint.evaluate(witness))
            .collect()
    }
}
```

## Circuit Testing and Debugging

### Unit Testing Circuits

```rust
#[cfg(test)]
mod circuit_tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    
    #[test]
    fn test_transaction_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = TransactionCircuit::build_circuit(&mut builder);
        let data = builder.build::<C>();
        
        // Test with valid transaction
        let mut pw = PartialWitness::new();
        pw.set_target(targets.sender_balance, F::from_canonical_u64(1000));
        pw.set_target(targets.amount, F::from_canonical_u64(100));
        pw.set_target(targets.fee, F::from_canonical_u64(10));
        pw.set_target(targets.sender_secret, F::from_canonical_u64(12345));
        pw.set_target(targets.nullifier_seed, F::from_canonical_u64(67890));
        
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
    
    #[test]
    fn test_range_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = RangeCircuit::build_range_circuit(&mut builder, 64);
        let data = builder.build::<C>();
        
        // Test with value in range
        let mut pw = PartialWitness::new();
        pw.set_target(targets.value, F::from_canonical_u64(500));
        pw.set_target(targets.range_min, F::from_canonical_u64(0));
        pw.set_target(targets.range_max, F::from_canonical_u64(1000));
        pw.set_target(targets.randomness, F::from_canonical_u64(99999));
        
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
    
    #[test]
    fn test_circuit_performance() {
        use std::time::Instant;
        
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = TransactionCircuit::build_circuit(&mut builder);
        
        let build_start = Instant::now();
        let data = builder.build::<C>();
        let build_time = build_start.elapsed();
        
        println!("Circuit build time: {:?}", build_time);
        println!("Circuit size: {} gates", data.common.gates.len());
        
        let mut pw = PartialWitness::new();
        pw.set_target(targets.sender_balance, F::from_canonical_u64(1000));
        pw.set_target(targets.amount, F::from_canonical_u64(100));
        pw.set_target(targets.fee, F::from_canonical_u64(10));
        pw.set_target(targets.sender_secret, F::from_canonical_u64(12345));
        pw.set_target(targets.nullifier_seed, F::from_canonical_u64(67890));
        
        let prove_start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let prove_time = prove_start.elapsed();
        
        println!("Proof generation time: {:?}", prove_time);
        println!("Proof size: {} bytes", proof.to_bytes().len());
        
        let verify_start = Instant::now();
        let verify_result = data.verify(proof);
        let verify_time = verify_start.elapsed();
        
        println!("Verification time: {:?}", verify_time);
        assert!(verify_result.is_ok());
    }
}
```

### Circuit Profiling

```rust
use std::collections::HashMap;

pub struct CircuitProfiler {
    gate_counts: HashMap<String, usize>,
    constraint_counts: HashMap<String, usize>,
    wire_usage: usize,
}

impl CircuitProfiler {
    pub fn profile_circuit<F: Field, const D: usize>(
        data: &CircuitData<F, C, D>
    ) -> CircuitProfile {
        let mut profiler = CircuitProfiler {
            gate_counts: HashMap::new(),
            constraint_counts: HashMap::new(),
            wire_usage: data.common.num_wires(),
        };
        
        // Count gate types
        for gate in &data.common.gates {
            let gate_name = gate.0.id();
            *profiler.gate_counts.entry(gate_name).or_insert(0) += 1;
        }
        
        CircuitProfile {
            total_gates: data.common.gates.len(),
            gate_breakdown: profiler.gate_counts,
            total_wires: profiler.wire_usage,
            degree: data.common.degree(),
        }
    }
}

pub struct CircuitProfile {
    pub total_gates: usize,
    pub gate_breakdown: HashMap<String, usize>,
    pub total_wires: usize,
    pub degree: usize,
}

impl CircuitProfile {
    pub fn print_summary(&self) {
        println!("Circuit Profile:");
        println!("  Total gates: {}", self.total_gates);
        println!("  Total wires: {}", self.total_wires);
        println!("  Degree: {}", self.degree);
        println!("  Gate breakdown:");
        
        for (gate_type, count) in &self.gate_breakdown {
            println!("    {}: {}", gate_type, count);
        }
    }
}
```

# ZK Circuit Implementation Guide

This guide covers the cryptographic circuits and constraints used in lib-proofs' zero-knowledge proof system.

## Circuit Architecture Overview

lib-proofs uses Plonky2 as the backend proof system, which provides efficient arithmetic circuits over finite fields. Our circuits are designed for:

- **High Performance**: Optimized for both proving and verification speed
- **Low Memory Usage**: Efficient circuit construction and witness generation
- **Composability**: Circuits can be combined and nested recursively
- **Security**: Based on proven cryptographic assumptions

## Core Circuit Types

### 1. Transaction Circuits

Transaction circuits prove knowledge of valid financial transactions without revealing sensitive information.

#### Circuit Structure
```rust
// Conceptual circuit layout (actual implementation in Plonky2)
pub struct TransactionCircuit {
    // Public inputs
    pub amount_commitment: FieldElement,
    pub balance_commitment: FieldElement,
    pub nullifier: FieldElement,
    pub merkle_root: FieldElement,
    
    // Private witnesses
    sender_balance: FieldElement,
    amount: FieldElement,
    fee: FieldElement,
    sender_secret: FieldElement,
    nullifier_seed: FieldElement,
    merkle_path: Vec<FieldElement>,
}
```

#### Constraints
1. **Balance Constraint**: `sender_balance >= amount + fee`
2. **Commitment Consistency**: Commitments match private values
3. **Nullifier Uniqueness**: Nullifier derived correctly from secret
4. **Merkle Path Verification**: Sender's balance is in the state tree

#### Circuit Implementation Pattern
```rust
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;

impl TransactionCircuit {
    pub fn build_circuit(builder: &mut CircuitBuilder<F, 2>) -> TransactionTargets {
        // Public inputs
        let amount_commitment = builder.add_public_input();
        let balance_commitment = builder.add_public_input();
        let nullifier = builder.add_public_input();
        let merkle_root = builder.add_public_input();
        
        // Private witnesses
        let sender_balance = builder.add_private_input();
        let amount = builder.add_private_input();
        let fee = builder.add_private_input();
        let sender_secret = builder.add_private_input();
        let nullifier_seed = builder.add_private_input();
        
        // Constraint 1: Balance sufficiency
        let total_spent = builder.add(amount, fee);
        let balance_check = builder.sub(sender_balance, total_spent);
        
        // This would be a range check constraint in practice
        // ensure balance_check >= 0
        
        // Constraint 2: Commitment consistency
        // amount_commitment = hash(amount, randomness)
        let amount_hash = builder.hash_n_to_1([amount, /* randomness */]);
        builder.connect(amount_commitment, amount_hash);
        
        // Constraint 3: Nullifier derivation
        // nullifier = hash(sender_secret, nullifier_seed)
        let nullifier_hash = builder.hash_n_to_1([sender_secret, nullifier_seed]);
        builder.connect(nullifier, nullifier_hash);
        
        // Constraint 4: Merkle path verification
        // This would implement a merkle tree inclusion proof
        
        TransactionTargets {
            amount_commitment,
            balance_commitment,
            nullifier,
            merkle_root,
            sender_balance,
            amount,
            fee,
            sender_secret,
            nullifier_seed,
        }
    }
}
```

### 2. Range Proof Circuits

Range proofs demonstrate that a secret value lies within a specified range without revealing the value.

#### Circuit Structure
```rust
pub struct RangeCircuit {
    // Public inputs
    pub commitment: FieldElement,
    pub range_min: FieldElement,
    pub range_max: FieldElement,
    
    // Private witnesses
    value: FieldElement,
    randomness: FieldElement,
}
```

#### Binary Decomposition Method
```rust
impl RangeCircuit {
    pub fn build_range_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        bit_width: usize,
    ) -> RangeTargets {
        let commitment = builder.add_public_input();
        let range_min = builder.add_public_input();
        let range_max = builder.add_public_input();
        
        let value = builder.add_private_input();
        let randomness = builder.add_private_input();
        
        // Decompose value into bits
        let mut bits = Vec::new();
        let mut current_value = value;
        
        for i in 0..bit_width {
            let bit = builder.add_private_input();
            bits.push(bit);
            
            // Constrain bit to be 0 or 1
            let bit_constraint = builder.mul(bit, builder.sub(builder.one(), bit));
            builder.assert_zero(bit_constraint);
            
            // Update current_value = current_value - bit * 2^i
            let power_of_two = builder.constant(F::from_canonical_u64(1u64 << i));
            let bit_contribution = builder.mul(bit, power_of_two);
            current_value = builder.sub(current_value, bit_contribution);
        }
        
        // Assert that decomposition is complete
        builder.assert_zero(current_value);
        
        // Range check: range_min <= value <= range_max
        let value_minus_min = builder.sub(value, range_min);
        let max_minus_value = builder.sub(range_max, value);
        
        // These would need range check gadgets
        // ensure_non_negative(value_minus_min);
        // ensure_non_negative(max_minus_value);
        
        // Commitment verification
        let computed_commitment = builder.hash_n_to_1([value, randomness]);
        builder.connect(commitment, computed_commitment);
        
        RangeTargets {
            commitment,
            range_min,
            range_max,
            value,
            randomness,
            bits,
        }
    }
}
```

### 3. Identity Verification Circuits

Identity circuits prove attributes about an identity without revealing the identity itself.

#### Circuit Structure
```rust
pub struct IdentityCircuit {
    // Public inputs
    pub identity_commitment: FieldElement,
    pub min_age: FieldElement,
    pub required_jurisdiction: FieldElement,
    pub credential_requirement: FieldElement,
    
    // Private witnesses
    age: FieldElement,
    jurisdiction: FieldElement,
    credential_hash: FieldElement,
    identity_secret: FieldElement,
    randomness: FieldElement,
}
```

#### Constraint Implementation
```rust
impl IdentityCircuit {
    pub fn build_identity_circuit(builder: &mut CircuitBuilder<F, 2>) -> IdentityTargets {
        // Public inputs
        let identity_commitment = builder.add_public_input();
        let min_age = builder.add_public_input();
        let required_jurisdiction = builder.add_public_input();
        let credential_requirement = builder.add_public_input();
        
        // Private witnesses
        let age = builder.add_private_input();
        let jurisdiction = builder.add_private_input();
        let credential_hash = builder.add_private_input();
        let identity_secret = builder.add_private_input();
        let randomness = builder.add_private_input();
        
        // Age constraint: age >= min_age
        let age_diff = builder.sub(age, min_age);
        // Range check to ensure age_diff >= 0
        
        // Jurisdiction constraint: jurisdiction == required_jurisdiction OR required_jurisdiction == 0
        let jurisdiction_match = builder.sub(jurisdiction, required_jurisdiction);
        let jurisdiction_selector = builder.is_equal(required_jurisdiction, builder.zero());
        let jurisdiction_constraint = builder.mul(jurisdiction_match, 
            builder.sub(builder.one(), jurisdiction_selector));
        builder.assert_zero(jurisdiction_constraint);
        
        // Credential constraint: credential_hash == credential_requirement OR credential_requirement == 0
        let credential_match = builder.sub(credential_hash, credential_requirement);
        let credential_selector = builder.is_equal(credential_requirement, builder.zero());
        let credential_constraint = builder.mul(credential_match,
            builder.sub(builder.one(), credential_selector));
        builder.assert_zero(credential_constraint);
        
        // Identity commitment verification
        let computed_commitment = builder.hash_n_to_1([
            age, jurisdiction, credential_hash, identity_secret, randomness
        ]);
        builder.connect(identity_commitment, computed_commitment);
        
        IdentityTargets {
            identity_commitment,
            min_age,
            required_jurisdiction,
            credential_requirement,
            age,
            jurisdiction,
            credential_hash,
            identity_secret,
            randomness,
        }
    }
}
```

### 4. Storage Access Circuits

Storage circuits prove authorized access to data without revealing access credentials.

#### Circuit Structure
```rust
pub struct StorageAccessCircuit {
    // Public inputs
    pub access_granted: FieldElement,
    pub resource_hash: FieldElement,
    pub required_permission: FieldElement,
    
    // Private witnesses
    access_key: FieldElement,
    user_secret: FieldElement,
    user_permission_level: FieldElement,
}
```

#### Permission Logic Circuit
```rust
impl StorageAccessCircuit {
    pub fn build_access_circuit(builder: &mut CircuitBuilder<F, 2>) -> StorageTargets {
        let access_granted = builder.add_public_input();
        let resource_hash = builder.add_public_input();
        let required_permission = builder.add_public_input();
        
        let access_key = builder.add_private_input();
        let user_secret = builder.add_private_input();
        let user_permission_level = builder.add_private_input();
        
        // Key derivation: access_key = hash(user_secret, resource_hash)
        let derived_key = builder.hash_n_to_1([user_secret, resource_hash]);
        builder.connect(access_key, derived_key);
        
        // Permission check: user_permission_level >= required_permission
        let permission_diff = builder.sub(user_permission_level, required_permission);
        // Range check to ensure permission_diff >= 0
        
        // Access decision: access_granted = (permission_diff >= 0) ? 1 : 0
        // This would use a comparison gadget in practice
        
        StorageTargets {
            access_granted,
            resource_hash,
            required_permission,
            access_key,
            user_secret,
            user_permission_level,
        }
    }
}
```

### 5. Routing Circuits

Routing circuits prove network routing capabilities without revealing network topology.

#### Circuit Structure
```rust
pub struct RoutingCircuit {
    // Public inputs
    pub source_node: FieldElement,
    pub destination_node: FieldElement,
    pub max_hops: FieldElement,
    pub min_bandwidth: FieldElement,
    pub routing_feasible: FieldElement,
    
    // Private witnesses
    hop_count: FieldElement,
    available_bandwidth: FieldElement,
    route_latency: FieldElement,
    routing_secret: FieldElement,
}
```

#### Network Constraint Implementation
```rust
impl RoutingCircuit {
    pub fn build_routing_circuit(builder: &mut CircuitBuilder<F, 2>) -> RoutingTargets {
        let source_node = builder.add_public_input();
        let destination_node = builder.add_public_input();
        let max_hops = builder.add_public_input();
        let min_bandwidth = builder.add_public_input();
        let routing_feasible = builder.add_public_input();
        
        let hop_count = builder.add_private_input();
        let available_bandwidth = builder.add_private_input();
        let route_latency = builder.add_private_input();
        let routing_secret = builder.add_private_input();
        
        // Hop count constraint: hop_count <= max_hops
        let hop_diff = builder.sub(max_hops, hop_count);
        // Range check: hop_diff >= 0
        
        // Bandwidth constraint: available_bandwidth >= min_bandwidth
        let bandwidth_diff = builder.sub(available_bandwidth, min_bandwidth);
        // Range check: bandwidth_diff >= 0
        
        // Route authentication: verify routing_secret is valid for this path
        let route_hash = builder.hash_n_to_1([
            source_node, destination_node, hop_count, routing_secret
        ]);
        // Additional constraints would verify route_hash against network state
        
        // Feasibility decision
        let hop_feasible = builder.is_zero(builder.sub(max_hops, hop_count));
        let bandwidth_feasible = builder.is_zero(builder.sub(available_bandwidth, min_bandwidth));
        let route_feasible = builder.and(hop_feasible, bandwidth_feasible);
        builder.connect(routing_feasible, route_feasible);
        
        RoutingTargets {
            source_node,
            destination_node,
            max_hops,
            min_bandwidth,
            routing_feasible,
            hop_count,
            available_bandwidth,
            route_latency,
            routing_secret,
        }
    }
}
```

### 6. Data Integrity Circuits

Data integrity circuits prove correct storage and handling of data without revealing the data content.

#### Circuit Structure
```rust
pub struct DataIntegrityCircuit {
    // Public inputs
    pub data_hash: FieldElement,
    pub max_chunks: FieldElement,
    pub max_size: FieldElement,
    pub integrity_verified: FieldElement,
    
    // Private witnesses
    chunk_count: FieldElement,
    total_size: FieldElement,
    checksum: FieldElement,
    storage_secret: FieldElement,
    timestamp: FieldElement,
}
```

#### Integrity Verification Circuit
```rust
impl DataIntegrityCircuit {
    pub fn build_integrity_circuit(builder: &mut CircuitBuilder<F, 2>) -> IntegrityTargets {
        let data_hash = builder.add_public_input();
        let max_chunks = builder.add_public_input();
        let max_size = builder.add_public_input();
        let integrity_verified = builder.add_public_input();
        
        let chunk_count = builder.add_private_input();
        let total_size = builder.add_private_input();
        let checksum = builder.add_private_input();
        let storage_secret = builder.add_private_input();
        let timestamp = builder.add_private_input();
        
        // Size constraints
        let size_diff = builder.sub(max_size, total_size);
        // Range check: size_diff >= 0
        
        let chunk_diff = builder.sub(max_chunks, chunk_count);
        // Range check: chunk_diff >= 0
        
        // Data integrity verification
        let integrity_hash = builder.hash_n_to_1([
            chunk_count, total_size, checksum, storage_secret, timestamp
        ]);
        builder.connect(data_hash, integrity_hash);
        
        // All constraints satisfied
        let size_valid = builder.is_zero(builder.sub(max_size, total_size));
        let chunk_valid = builder.is_zero(builder.sub(max_chunks, chunk_count));
        let integrity_valid = builder.and(size_valid, chunk_valid);
        builder.connect(integrity_verified, integrity_valid);
        
        IntegrityTargets {
            data_hash,
            max_chunks,
            max_size,
            integrity_verified,
            chunk_count,
            total_size,
            checksum,
            storage_secret,
            timestamp,
        }
    }
}
```

## Advanced Circuit Techniques

### Recursive Proof Composition

```rust
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;

pub struct RecursiveCircuit {
    inner_proof_targets: Vec<Target>,
    verification_targets: Vec<Target>,
}

impl RecursiveCircuit {
    pub fn build_recursive_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        inner_circuit_data: &CircuitData<F, C, 2>,
    ) -> RecursiveTargets {
        // Add targets for the inner proof
        let inner_proof_targets = builder.add_proof_targets_inner_circuit(inner_circuit_data);
        
        // Verify the inner proof within this circuit
        builder.verify_proof_inner_circuit(&inner_proof_targets, inner_circuit_data);
        
        // Add additional constraints on the verified proof's public inputs
        let verified_amount = inner_proof_targets.public_inputs[0];
        let verified_balance = inner_proof_targets.public_inputs[1];
        
        // Example: Aggregate multiple transaction proofs
        let total_amount = builder.add(verified_amount, /* other amounts */);
        
        RecursiveTargets {
            inner_proof_targets,
            total_amount,
        }
    }
}
```

### Lookup Tables for Efficiency

```rust
use plonky2::gates::lookup_table::LookupTable;

pub fn create_range_lookup_table(max_value: u64) -> LookupTable {
    // Pre-compute range check values for efficiency
    let mut table_data = Vec::new();
    
    for i in 0..=max_value {
        table_data.push(vec![
            F::from_canonical_u64(i),      // value
            F::from_canonical_u64(i * i),  // value^2
            F::from_canonical_u64(if i < max_value { 1 } else { 0 }), // in_range
        ]);
    }
    
    LookupTable::new(
        "range_check",
        table_data,
        vec!["value", "value_squared", "in_range"],
    )
}

pub fn use_lookup_table_in_circuit(
    builder: &mut CircuitBuilder<F, 2>,
    lookup_table: &LookupTable,
) -> LookupTargets {
    let value = builder.add_private_input();
    
    // Look up the range check result
    let lookup_result = builder.add_lookup_table_target(lookup_table, &[value]);
    let in_range = lookup_result[2]; // Third column is in_range flag
    
    // Use the lookup result in constraints
    builder.assert_one(in_range); // Assert value is in range
    
    LookupTargets {
        value,
        in_range,
    }
}
```

### Custom Gates for Specialized Operations

```rust
use plonky2::gates::gate::Gate;
use plonky2::iop::wire::Wire;

pub struct HashGate {
    num_inputs: usize,
}

impl HashGate {
    pub fn new(num_inputs: usize) -> Self {
        Self { num_inputs }
    }
}

impl<F: Field> Gate<F> for HashGate {
    fn id(&self) -> String {
        format!("HashGate({})", self.num_inputs)
    }
    
    fn serialize(&self, dst: &mut Vec<u8>) -> IoResult<()> {
        dst.write_u32::<LittleEndian>(self.num_inputs as u32)
    }
    
    fn deserialize(src: &mut &[u8]) -> IoResult<Self> {
        let num_inputs = src.read_u32::<LittleEndian>()? as usize;
        Ok(Self::new(num_inputs))
    }
    
    fn eval_unfiltered(&self, vars: EvaluationVars<F>) -> Vec<F> {
        // Implement hash function constraints
        let inputs = &vars.local_wires[0..self.num_inputs];
        let output = vars.local_wires[self.num_inputs];
        
        // Hash constraint: output = hash(inputs)
        // This would implement the actual hash function arithmetic
        vec![output - self.compute_hash(inputs)]
    }
    
    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        // Circuit version of eval_unfiltered
        let inputs = &vars.local_wires[0..self.num_inputs];
        let output = vars.local_wires[self.num_inputs];
        
        let computed_hash = self.compute_hash_circuit(builder, inputs);
        vec![builder.sub_extension(output, computed_hash)]
    }
}
```

## Circuit Optimization Strategies

### 1. Constraint Minimization

```rust
// Instead of multiple individual constraints
fn inefficient_constraints(builder: &mut CircuitBuilder<F, 2>, a: Target, b: Target, c: Target) {
    let ab = builder.mul(a, b);
    let ab_plus_c = builder.add(ab, c);
    let result1 = builder.mul(ab_plus_c, a);
    
    let bc = builder.mul(b, c);
    let bc_plus_a = builder.add(bc, a);
    let result2 = builder.mul(bc_plus_a, b);
    
    builder.connect(result1, result2);
}

// Combine into fewer, more complex constraints
fn efficient_constraints(builder: &mut CircuitBuilder<F, 2>, a: Target, b: Target, c: Target) {
    // Single constraint: a*(a*b + c) = b*(b*c + a)
    // Expanded: a²b + ac = b²c + ab
    // Rearranged: a²b - b²c + ac - ab = 0
    // Factored: b(a² - bc) + a(c - b) = 0
    
    let a_squared = builder.mul(a, a);
    let b_squared = builder.mul(b, b);
    let ab = builder.mul(a, b);
    let bc = builder.mul(b, c);
    let ac = builder.mul(a, c);
    
    let term1 = builder.mul(a, ab);      // a²b
    let term2 = builder.mul(b_squared, c); // b²c
    let left_side = builder.add(term1, ac);   // a²b + ac
    let right_side = builder.add(term2, ab);  // b²c + ab
    
    let constraint = builder.sub(left_side, right_side);
    builder.assert_zero(constraint);
}
```

### 2. Wire Reuse

```rust
fn optimized_wire_usage(builder: &mut CircuitBuilder<F, 2>) -> OptimizedTargets {
    let input1 = builder.add_private_input();
    let input2 = builder.add_private_input();
    
    // Reuse intermediate computations
    let squared1 = builder.mul(input1, input1);
    let squared2 = builder.mul(input2, input2);
    
    // Use the same squared values multiple times
    let sum_of_squares = builder.add(squared1, squared2);
    let product_of_squares = builder.mul(squared1, squared2);
    let diff_of_squares = builder.sub(squared1, squared2);
    
    OptimizedTargets {
        input1,
        input2,
        squared1,
        squared2,
        sum_of_squares,
        product_of_squares,
        diff_of_squares,
    }
}
```

### 3. Parallel Constraint Evaluation

```rust
use rayon::prelude::*;

pub struct ParallelCircuitBuilder {
    constraints: Vec<ConstraintGroup>,
}

impl ParallelCircuitBuilder {
    pub fn evaluate_constraints_parallel(&self, witness: &[F]) -> Vec<F> {
        self.constraints
            .par_iter()
            .flat_map(|group| group.evaluate_parallel(witness))
            .collect()
    }
}

struct ConstraintGroup {
    constraints: Vec<Constraint>,
    dependencies: Vec<usize>, // Wire indices this group depends on
}

impl ConstraintGroup {
    fn evaluate_parallel(&self, witness: &[F]) -> Vec<F> {
        self.constraints
            .par_iter()
            .map(|constraint| constraint.evaluate(witness))
            .collect()
    }
}
```

## Circuit Testing and Debugging

### Unit Testing Circuits

```rust
#[cfg(test)]
mod circuit_tests {
    use super::*;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    
    #[test]
    fn test_transaction_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = TransactionCircuit::build_circuit(&mut builder);
        let data = builder.build::<C>();
        
        // Test with valid transaction
        let mut pw = PartialWitness::new();
        pw.set_target(targets.sender_balance, F::from_canonical_u64(1000));
        pw.set_target(targets.amount, F::from_canonical_u64(100));
        pw.set_target(targets.fee, F::from_canonical_u64(10));
        pw.set_target(targets.sender_secret, F::from_canonical_u64(12345));
        pw.set_target(targets.nullifier_seed, F::from_canonical_u64(67890));
        
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
    
    #[test]
    fn test_range_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = RangeCircuit::build_range_circuit(&mut builder, 64);
        let data = builder.build::<C>();
        
        // Test with value in range
        let mut pw = PartialWitness::new();
        pw.set_target(targets.value, F::from_canonical_u64(500));
        pw.set_target(targets.range_min, F::from_canonical_u64(0));
        pw.set_target(targets.range_max, F::from_canonical_u64(1000));
        pw.set_target(targets.randomness, F::from_canonical_u64(99999));
        
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
    
    #[test]
    fn test_circuit_performance() {
        use std::time::Instant;
        
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let targets = TransactionCircuit::build_circuit(&mut builder);
        
        let build_start = Instant::now();
        let data = builder.build::<C>();
        let build_time = build_start.elapsed();
        
        println!("Circuit build time: {:?}", build_time);
        println!("Circuit size: {} gates", data.common.gates.len());
        
        let mut pw = PartialWitness::new();
        pw.set_target(targets.sender_balance, F::from_canonical_u64(1000));
        pw.set_target(targets.amount, F::from_canonical_u64(100));
        pw.set_target(targets.fee, F::from_canonical_u64(10));
        pw.set_target(targets.sender_secret, F::from_canonical_u64(12345));
        pw.set_target(targets.nullifier_seed, F::from_canonical_u64(67890));
        
        let prove_start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let prove_time = prove_start.elapsed();
        
        println!("Proof generation time: {:?}", prove_time);
        println!("Proof size: {} bytes", proof.to_bytes().len());
        
        let verify_start = Instant::now();
        let verify_result = data.verify(proof);
        let verify_time = verify_start.elapsed();
        
        println!("Verification time: {:?}", verify_time);
        assert!(verify_result.is_ok());
    }
}
```

### Circuit Profiling

```rust
use std::collections::HashMap;

pub struct CircuitProfiler {
    gate_counts: HashMap<String, usize>,
    constraint_counts: HashMap<String, usize>,
    wire_usage: usize,
}

impl CircuitProfiler {
    pub fn profile_circuit<F: Field, const D: usize>(
        data: &CircuitData<F, C, D>
    ) -> CircuitProfile {
        let mut profiler = CircuitProfiler {
            gate_counts: HashMap::new(),
            constraint_counts: HashMap::new(),
            wire_usage: data.common.num_wires(),
        };
        
        // Count gate types
        for gate in &data.common.gates {
            let gate_name = gate.0.id();
            *profiler.gate_counts.entry(gate_name).or_insert(0) += 1;
        }
        
        CircuitProfile {
            total_gates: data.common.gates.len(),
            gate_breakdown: profiler.gate_counts,
            total_wires: profiler.wire_usage,
            degree: data.common.degree(),
        }
    }
}

pub struct CircuitProfile {
    pub total_gates: usize,
    pub gate_breakdown: HashMap<String, usize>,
    pub total_wires: usize,
    pub degree: usize,
}

impl CircuitProfile {
    pub fn print_summary(&self) {
        println!("Circuit Profile:");
        println!("  Total gates: {}", self.total_gates);
        println!("  Total wires: {}", self.total_wires);
        println!("  Degree: {}", self.degree);
        println!("  Gate breakdown:");
        
        for (gate_type, count) in &self.gate_breakdown {
            println!("    {}: {}", gate_type, count);
        }
    }
}
```

This circuit implementation guide provides the foundation for understanding and extending the zero-knowledge proof circuits in lib-proofs. The patterns and techniques shown here can be adapted for new proof types and optimized for specific use cases.
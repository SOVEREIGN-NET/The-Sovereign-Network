//! Plonky2 circuit implementation
//! 
//! Provides circuit building and configuration for Plonky2-based
//! zero-knowledge proofs with optimized performance.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::hash_blake3;

/// Circuit configuration for Plonky2 proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Security level (number of bits)
    pub security_bits: u32,
    /// Number of wires per gate
    pub num_wires: usize,
    /// Number of routed wires
    pub num_routed_wires: usize,
    /// Quotient degree factor
    pub quotient_degree_factor: usize,
    /// Field extension degree
    pub extension_degree: usize,
    /// Hash function for Fiat-Shamir
    pub hash_function: String,
}

impl CircuitConfig {
    /// Create standard configuration for high security
    pub fn standard() -> Self {
        Self {
            security_bits: 100,
            num_wires: 135,
            num_routed_wires: 80,
            quotient_degree_factor: 8,
            extension_degree: 2,
            hash_function: "blake3".to_string(),
        }
    }

    /// Create fast configuration for development
    pub fn fast() -> Self {
        Self {
            security_bits: 64,
            num_wires: 100,
            num_routed_wires: 60,
            quotient_degree_factor: 4,
            extension_degree: 2,
            hash_function: "blake3".to_string(),
        }
    }

    /// Create high-security configuration
    pub fn high_security() -> Self {
        Self {
            security_bits: 128,
            num_wires: 200,
            num_routed_wires: 120,
            quotient_degree_factor: 16,
            extension_degree: 2,
            hash_function: "blake3".to_string(),
        }
    }

    /// Get estimated proof size in bytes
    pub fn estimated_proof_size(&self) -> usize {
        // Rough estimation based on configuration
        let base_size = 1024; // Base proof overhead
        let wire_factor = self.num_wires * 32; // 32 bytes per wire element
        let security_factor = (self.security_bits / 8) as usize;
        
        base_size + wire_factor + security_factor * 64
    }

    /// Validate configuration parameters
    pub fn validate(&self) -> Result<()> {
        if self.security_bits < 64 {
            return Err(anyhow::anyhow!("Security bits must be at least 64"));
        }
        
        if self.num_wires < 50 {
            return Err(anyhow::anyhow!("Number of wires must be at least 50"));
        }
        
        if self.num_routed_wires > self.num_wires {
            return Err(anyhow::anyhow!("Routed wires cannot exceed total wires"));
        }
        
        if self.quotient_degree_factor < 2 {
            return Err(anyhow::anyhow!("Quotient degree factor must be at least 2"));
        }
        
        Ok(())
    }
}

/// Circuit element types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitElement {
    /// Input wire
    Input { index: usize, value: Option<[u8; 32]> },
    /// Output wire
    Output { index: usize, value: Option<[u8; 32]> },
    /// Addition gate
    AddGate { input_a: usize, input_b: usize, output: usize },
    /// Multiplication gate
    MulGate { input_a: usize, input_b: usize, output: usize },
    /// Constant gate
    ConstGate { value: [u8; 32], output: usize },
    /// Hash gate (Blake3)
    HashGate { inputs: Vec<usize>, output: usize },
    /// Boolean constraint gate
    BoolGate { input: usize },
    /// Equality constraint gate
    EqualityGate { input_a: usize, input_b: usize },
    /// Range constraint gate
    RangeGate { input: usize, min_value: u64, max_value: u64 },
}

/// Circuit builder for constructing Plonky2 circuits
#[derive(Debug, Clone)]
pub struct CircuitBuilder {
    /// Circuit configuration
    pub config: CircuitConfig,
    /// Circuit elements (gates and constraints)
    pub elements: Vec<CircuitElement>,
    /// Next available wire index
    pub next_wire_index: usize,
    /// Public inputs
    pub public_inputs: Vec<usize>,
    /// Private inputs
    pub private_inputs: Vec<usize>,
}

impl CircuitBuilder {
    /// Create new circuit builder
    pub fn new(config: CircuitConfig) -> Result<Self> {
        config.validate()?;
        
        Ok(Self {
            config,
            elements: Vec::new(),
            next_wire_index: 0,
            public_inputs: Vec::new(),
            private_inputs: Vec::new(),
        })
    }

    /// Create circuit builder with standard configuration
    pub fn standard() -> Result<Self> {
        Self::new(CircuitConfig::standard())
    }

    /// Create circuit builder with fast configuration
    pub fn fast() -> Result<Self> {
        Self::new(CircuitConfig::fast())
    }

    /// Add public input wire
    pub fn add_public_input(&mut self, value: Option<[u8; 32]>) -> usize {
        let wire_index = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::Input {
            index: wire_index,
            value,
        });
        
        self.public_inputs.push(wire_index);
        wire_index
    }

    /// Add private input wire
    pub fn add_private_input(&mut self, value: Option<[u8; 32]>) -> usize {
        let wire_index = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::Input {
            index: wire_index,
            value,
        });
        
        self.private_inputs.push(wire_index);
        wire_index
    }

    /// Add constant value
    pub fn add_constant(&mut self, value: [u8; 32]) -> usize {
        let output_wire = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::ConstGate {
            value,
            output: output_wire,
        });
        
        output_wire
    }

    /// Add addition gate
    pub fn add_addition(&mut self, input_a: usize, input_b: usize) -> usize {
        let output_wire = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::AddGate {
            input_a,
            input_b,
            output: output_wire,
        });
        
        output_wire
    }

    /// Add multiplication gate
    pub fn add_multiplication(&mut self, input_a: usize, input_b: usize) -> usize {
        let output_wire = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::MulGate {
            input_a,
            input_b,
            output: output_wire,
        });
        
        output_wire
    }

    /// Add hash gate (Blake3)
    pub fn add_hash(&mut self, inputs: Vec<usize>) -> usize {
        if inputs.is_empty() {
            panic!("Hash gate requires at least one input");
        }
        
        let output_wire = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::HashGate {
            inputs,
            output: output_wire,
        });
        
        output_wire
    }

    /// Add boolean constraint (ensures wire value is 0 or 1)
    pub fn add_boolean_constraint(&mut self, input: usize) {
        self.elements.push(CircuitElement::BoolGate { input });
    }

    /// Add equality constraint
    pub fn add_equality_constraint(&mut self, input_a: usize, input_b: usize) {
        self.elements.push(CircuitElement::EqualityGate { input_a, input_b });
    }

    /// Add range constraint
    pub fn add_range_constraint(&mut self, input: usize, min_value: u64, max_value: u64) {
        self.elements.push(CircuitElement::RangeGate {
            input,
            min_value,
            max_value,
        });
    }

    /// Add output wire
    pub fn add_output(&mut self, input_wire: usize) -> usize {
        let output_wire = self.next_wire_index;
        self.next_wire_index += 1;
        
        self.elements.push(CircuitElement::Output {
            index: output_wire,
            value: None,
        });
        
        // Add equality constraint to connect input to output
        self.add_equality_constraint(input_wire, output_wire);
        
        output_wire
    }

    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats {
        let mut add_gates = 0;
        let mut mul_gates = 0;
        let mut hash_gates = 0;
        let mut constraint_gates = 0;
        
        for element in &self.elements {
            match element {
                CircuitElement::AddGate { .. } => add_gates += 1,
                CircuitElement::MulGate { .. } => mul_gates += 1,
                CircuitElement::HashGate { .. } => hash_gates += 1,
                CircuitElement::BoolGate { .. } |
                CircuitElement::EqualityGate { .. } |
                CircuitElement::RangeGate { .. } => constraint_gates += 1,
                _ => {}
            }
        }
        
        CircuitStats {
            total_wires: self.next_wire_index,
            public_inputs: self.public_inputs.len(),
            private_inputs: self.private_inputs.len(),
            add_gates,
            mul_gates,
            hash_gates,
            constraint_gates,
            total_gates: self.elements.len(),
        }
    }

    /// Estimate proof generation time
    pub fn estimate_proof_time(&self) -> EstimatedTime {
        let stats = self.stats();
        
        // Rough estimates based on gate complexity
        let base_time_ms = 100;
        let add_time_ms = stats.add_gates * 2;
        let mul_time_ms = stats.mul_gates * 5;
        let hash_time_ms = stats.hash_gates * 20;
        let constraint_time_ms = stats.constraint_gates * 3;
        
        let total_ms = base_time_ms + add_time_ms + mul_time_ms + hash_time_ms + constraint_time_ms;
        
        EstimatedTime {
            setup_ms: total_ms / 10,
            proving_ms: total_ms,
            verification_ms: total_ms / 100,
        }
    }
}

/// Circuit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStats {
    pub total_wires: usize,
    pub public_inputs: usize,
    pub private_inputs: usize,
    pub add_gates: usize,
    pub mul_gates: usize,
    pub hash_gates: usize,
    pub constraint_gates: usize,
    pub total_gates: usize,
}

/// Estimated time for circuit operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedTime {
    pub setup_ms: usize,
    pub proving_ms: usize,
    pub verification_ms: usize,
}

/// Zero-knowledge circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCircuit {
    /// Circuit configuration
    pub config: CircuitConfig,
    /// Circuit elements
    pub elements: Vec<CircuitElement>,
    /// Public input indices
    pub public_inputs: Vec<usize>,
    /// Private input indices
    pub private_inputs: Vec<usize>,
    /// Output indices
    pub outputs: Vec<usize>,
    /// Circuit hash for verification
    pub circuit_hash: [u8; 32],
}

impl ZkCircuit {
    /// Build circuit from circuit builder
    pub fn from_builder(builder: CircuitBuilder) -> Self {
        // Find output wires
        let outputs: Vec<usize> = builder.elements.iter()
            .filter_map(|element| {
                if let CircuitElement::Output { index, .. } = element {
                    Some(*index)
                } else {
                    None
                }
            })
            .collect();

        // Calculate circuit hash for integrity
        let mut circuit_data = Vec::new();
        circuit_data.extend_from_slice(&builder.config.security_bits.to_le_bytes());
        circuit_data.extend_from_slice(&builder.config.num_wires.to_le_bytes());
        
        for element in &builder.elements {
            // Serialize element for hashing (simplified)
            match element {
                CircuitElement::AddGate { input_a, input_b, output } => {
                    circuit_data.extend_from_slice(b"ADD");
                    circuit_data.extend_from_slice(&input_a.to_le_bytes());
                    circuit_data.extend_from_slice(&input_b.to_le_bytes());
                    circuit_data.extend_from_slice(&output.to_le_bytes());
                }
                CircuitElement::MulGate { input_a, input_b, output } => {
                    circuit_data.extend_from_slice(b"MUL");
                    circuit_data.extend_from_slice(&input_a.to_le_bytes());
                    circuit_data.extend_from_slice(&input_b.to_le_bytes());
                    circuit_data.extend_from_slice(&output.to_le_bytes());
                }
                CircuitElement::HashGate { inputs, output } => {
                    circuit_data.extend_from_slice(b"HASH");
                    circuit_data.extend_from_slice(&inputs.len().to_le_bytes());
                    for input in inputs {
                        circuit_data.extend_from_slice(&input.to_le_bytes());
                    }
                    circuit_data.extend_from_slice(&output.to_le_bytes());
                }
                _ => {
                    // Add other gate types as needed
                    circuit_data.extend_from_slice(b"OTHER");
                }
            }
        }
        
        let circuit_hash = hash_blake3(&circuit_data);

        Self {
            config: builder.config,
            elements: builder.elements,
            public_inputs: builder.public_inputs,
            private_inputs: builder.private_inputs,
            outputs,
            circuit_hash,
        }
    }

    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats {
        let mut add_gates = 0;
        let mut mul_gates = 0;
        let mut hash_gates = 0;
        let mut constraint_gates = 0;
        
        for element in &self.elements {
            match element {
                CircuitElement::AddGate { .. } => add_gates += 1,
                CircuitElement::MulGate { .. } => mul_gates += 1,
                CircuitElement::HashGate { .. } => hash_gates += 1,
                CircuitElement::BoolGate { .. } |
                CircuitElement::EqualityGate { .. } |
                CircuitElement::RangeGate { .. } => constraint_gates += 1,
                _ => {}
            }
        }
        
        CircuitStats {
            total_wires: self.elements.len(),
            public_inputs: self.public_inputs.len(),
            private_inputs: self.private_inputs.len(),
            add_gates,
            mul_gates,
            hash_gates,
            constraint_gates,
            total_gates: self.elements.len(),
        }
    }

    /// Validate circuit structure
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        
        // Check that all wire indices are valid
        let max_wire_index = self.elements.len();
        
        for element in &self.elements {
            match element {
                CircuitElement::Input { index, .. } |
                CircuitElement::Output { index, .. } => {
                    if *index >= max_wire_index {
                        return Err(anyhow::anyhow!("Invalid wire index: {}", index));
                    }
                }
                CircuitElement::AddGate { input_a, input_b, output } |
                CircuitElement::MulGate { input_a, input_b, output } => {
                    if *input_a >= max_wire_index || *input_b >= max_wire_index || *output >= max_wire_index {
                        return Err(anyhow::anyhow!("Invalid wire indices in gate"));
                    }
                }
                CircuitElement::HashGate { inputs, output } => {
                    for input in inputs {
                        if *input >= max_wire_index {
                            return Err(anyhow::anyhow!("Invalid input wire index: {}", input));
                        }
                    }
                    if *output >= max_wire_index {
                        return Err(anyhow::anyhow!("Invalid output wire index: {}", output));
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Get estimated proof size
    pub fn estimated_proof_size(&self) -> usize {
        self.config.estimated_proof_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_config() {
        let config = CircuitConfig::standard();
        assert!(config.validate().is_ok());
        assert!(config.estimated_proof_size() > 0);
        
        let fast_config = CircuitConfig::fast();
        assert!(fast_config.validate().is_ok());
        assert!(fast_config.estimated_proof_size() < config.estimated_proof_size());
    }

    #[test]
    fn test_circuit_builder() {
        let mut builder = CircuitBuilder::standard().unwrap();
        
        let input_a = builder.add_public_input(Some([1u8; 32]));
        let input_b = builder.add_private_input(Some([2u8; 32]));
        let sum = builder.add_addition(input_a, input_b);
        let output = builder.add_output(sum);
        
        let stats = builder.stats();
        assert_eq!(stats.public_inputs, 1);
        assert_eq!(stats.private_inputs, 1);
        assert_eq!(stats.add_gates, 1);
        
        let time_estimate = builder.estimate_proof_time();
        assert!(time_estimate.proving_ms > 0);
    }

    #[test]
    fn test_circuit_construction() {
        let mut builder = CircuitBuilder::fast().unwrap();
        
        let input1 = builder.add_public_input(Some([10u8; 32]));
        let input2 = builder.add_private_input(Some([20u8; 32]));
        let constant = builder.add_constant([5u8; 32]);
        
        let sum = builder.add_addition(input1, input2);
        let product = builder.add_multiplication(sum, constant);
        let hash_result = builder.add_hash(vec![product]);
        
        builder.add_boolean_constraint(input1);
        builder.add_range_constraint(input2, 0, 100);
        builder.add_equality_constraint(sum, product);
        
        let output = builder.add_output(hash_result);
        
        let circuit = ZkCircuit::from_builder(builder);
        assert!(circuit.validate().is_ok());
        assert_eq!(circuit.outputs.len(), 1);
        assert_ne!(circuit.circuit_hash, [0u8; 32]);
        
        let stats = circuit.stats();
        assert!(stats.total_gates > 0);
        assert!(stats.hash_gates > 0);
        assert!(stats.constraint_gates > 0);
    }

    #[test]
    fn test_complex_circuit() {
        let mut builder = CircuitBuilder::standard().unwrap();
        
        // Build a circuit that computes hash(a + b * c) and verifies range
        let a = builder.add_public_input(Some([1u8; 32]));
        let b = builder.add_private_input(Some([2u8; 32]));
        let c = builder.add_private_input(Some([3u8; 32]));
        
        let bc = builder.add_multiplication(b, c);
        let abc = builder.add_addition(a, bc);
        let hash_abc = builder.add_hash(vec![abc]);
        
        // Add constraints
        builder.add_range_constraint(a, 0, 255);
        builder.add_range_constraint(b, 0, 255);
        builder.add_range_constraint(c, 0, 255);
        
        let output = builder.add_output(hash_abc);
        
        let circuit = ZkCircuit::from_builder(builder);
        assert!(circuit.validate().is_ok());
        
        let stats = circuit.stats();
        assert_eq!(stats.public_inputs, 1);
        assert_eq!(stats.private_inputs, 2);
        assert_eq!(stats.mul_gates, 1);
        assert_eq!(stats.add_gates, 1);
        assert_eq!(stats.hash_gates, 1);
        assert_eq!(stats.constraint_gates, 3);
    }

    #[test]
    fn test_invalid_circuit_config() {
        let mut config = CircuitConfig::standard();
        config.security_bits = 32; // Too low
        assert!(config.validate().is_err());
        
        config.security_bits = 100;
        config.num_routed_wires = config.num_wires + 1; // Invalid
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_circuit_hash_deterministic() {
        let mut builder1 = CircuitBuilder::fast().unwrap();
        let input1 = builder1.add_public_input(Some([1u8; 32]));
        let output1 = builder1.add_output(input1);
        let circuit1 = ZkCircuit::from_builder(builder1);
        
        let mut builder2 = CircuitBuilder::fast().unwrap();
        let input2 = builder2.add_public_input(Some([1u8; 32]));
        let output2 = builder2.add_output(input2);
        let circuit2 = ZkCircuit::from_builder(builder2);
        
        // Same circuit structure should produce same hash
        assert_eq!(circuit1.circuit_hash, circuit2.circuit_hash);
    }
}

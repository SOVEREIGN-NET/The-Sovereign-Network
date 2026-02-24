# Proofs

# Proofs Module Overview

## Summary

The **Proofs** module is a unified framework designed for the generation and verification of zero-knowledge proofs (ZK proofs) using the Plonky2 proof system. It consists of two primary sub-modules: **Proofs — docs** and **Proofs — src**. Together, these sub-modules provide a robust set of tools for developers to implement privacy-preserving computations across various applications, such as financial transactions, identity verification, and data integrity checks.

## Purpose

The overarching goal of the **Proofs** module is to abstract the complexities of cryptographic operations, allowing developers to create and manage zero-knowledge proofs efficiently. By leveraging the functionalities provided by the sub-modules, users can ensure secure and private transactions without exposing sensitive information.

## Sub-module Integration

- **[Proofs — docs](proofs-docs.md)**: This sub-module offers comprehensive documentation and user-friendly APIs for generating and verifying ZK proofs. It serves as a guide for developers to understand the capabilities and usage of the Proofs module.
  
- **[Proofs — src](proofs-src.md)**: This sub-module contains the core implementation of the zero-knowledge proof system, including transaction validation, identity verification, range proofs, and Merkle tree operations. It focuses on high-performance implementations and optimized algorithms for each proof type.

## Key Workflows

The **Proofs** module facilitates several key workflows that span both sub-modules:

1. **Proof Generation**: Developers can utilize the APIs in the **Proofs — docs** sub-module to create zero-knowledge proofs based on the functionalities implemented in the **Proofs — src** sub-module.

2. **Proof Verification**: The verification process is streamlined through the documentation and implementation provided, ensuring that generated proofs can be validated efficiently.

3. **Application Integration**: The combined capabilities of both sub-modules allow for seamless integration into applications requiring privacy-preserving features, such as secure transactions and identity checks.

For detailed information on each sub-module, please refer to their respective documentation pages: [Proofs — docs](proofs-docs.md) and [Proofs — src](proofs-src.md).
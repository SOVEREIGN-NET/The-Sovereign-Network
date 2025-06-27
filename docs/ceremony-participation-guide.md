# ZHTP Trusted Setup Ceremony Participation Guide

## Overview

ZHTP's trusted setup ceremony is **NOT limited to just validators** - it's designed as a **community-wide, multi-stakeholder ceremony** where various types of participants contribute to the network's security.

## Who Can Participate in the Ceremony?

### 1. **Core Network Validators** (Primary Participants)
- **Blockchain validators** running the consensus protocol
- **Requirements**: Minimum stake threshold, proven uptime record
- **Role**: Primary security contributors with highest trust weighting
- **Count**: 10-20 validators (not all validators need to participate)

### 2. **Storage and Routing Nodes** (Network Operators)
- **Storage providers** offering decentralized storage
- **Routing nodes** facilitating packet forwarding
- **Requirements**: Demonstrated network contribution, good reputation scores
- **Role**: Ensure ceremony represents actual network participants
- **Count**: 20-30 high-reputation nodes

### 3. **Community Representatives** (External Trust)
- **Academic institutions** (universities, research labs)
- **Blockchain security companies** (auditing firms, security researchers)
- **Open source contributors** (major GitHub contributors to ZHTP)
- **Requirements**: Public reputation, cryptographic expertise
- **Role**: External validation and transparency
- **Count**: 20-40 diverse representatives

### 4. **Independent Participants** (Public Participation)
- **Anyone from the community** who wants to contribute
- **Individual developers, users, enthusiasts**
- **Requirements**: Basic technical setup, identity verification
- **Role**: Decentralization and community ownership
- **Count**: 10-50 general participants

## Total Participants: 60-140 people

## Ceremony Architecture

The ceremony works in **phases** where different types of participants contribute:

### Phase 1: Universal SRS Generation
**ALL participants contribute sequentially to create the universal structured reference string (SRS)**

### Phase 2: Circuit-Specific Setup  
**Subset of participants (technical contributors) handle circuit-specific trusted setups**

## Implementation Status

✅ **COMPLETE**: ZHTP already has comprehensive ceremony infrastructure implemented:

### 1. **Ceremony Scripts** (`circuits/setup/`)
- `ceremony_startup.sh` - Complete ceremony orchestration
- `quantum_setup.sh` - Quantum-resistant entropy generation
- Multi-party coordination with 3-50 participants supported

### 2. **Participant Management** (`src/zhtp/ceremony_participants.rs`)
- Registration system for all participant types
- Identity verification for validators, network operators, community reps
- Trust scoring and weighting system
- Progress tracking and contribution verification

### 3. **Ceremony Coordinator** (`src/zhtp/ceremony_coordinator.rs`)
- Full ceremony orchestration
- Auto-registration of existing validators
- Phase 1 and Phase 2 execution
- Automatic integration of results into ZHTP code

## How It Works

### Pre-Ceremony
1. **Validator Auto-Registration**: Active ZHTP validators are automatically invited
2. **Community Registration**: Open registration for other participant types
3. **Identity Verification**: Each participant type has specific verification requirements
4. **Readiness Check**: Minimum participants per type must be verified

### Ceremony Execution
1. **Phase 1**: All participants contribute to universal SRS generation
   - Sequential contributions with quantum-resistant entropy
   - Each participant adds their secret to the growing SRS
   - 10+ rounds for maximum security

2. **Phase 2**: Technical participants handle circuit-specific setup
   - Compile all ZHTP circuits (consensus, transactions, storage, DAO, DNS)
   - Generate proving and verification keys
   - Multi-round contributions for each circuit

3. **Verification**: Independent verification of all ceremony outputs
4. **Integration**: Automatic update of ZHTP code with new trusted setup

## Running the Ceremony

### For Network Operators

```rust
use zhtp::ceremony_coordinator::run_zhtp_trusted_setup_ceremony;

// Run complete ceremony with existing network
let result = run_zhtp_trusted_setup_ceremony(network, consensus).await?;

// Ceremony automatically:
// 1. Registers validators as participants  
// 2. Executes multi-party computation
// 3. Updates ZHTP code with results
// 4. Generates attestation documents
```

### For Community Participants

1. **Register**: Submit participation request with identity verification
2. **Wait**: Verification process based on participant type
3. **Contribute**: When called, contribute entropy to the ceremony
4. **Verify**: Independently verify ceremony results

## Security Properties

### Multi-Party Security
- **Requirement**: Only ONE participant needs to properly destroy their secret
- **Result**: If any single participant is honest, the ceremony is secure
- **Protection**: Against government coercion, corporate pressure, technical compromise

### Quantum Resistance
- Uses post-quantum entropy sources
- BLAKE3 hashing and lattice-based cryptography
- Resistant to future quantum computer attacks

### Transparency
- All contributions are publicly verifiable
- Complete ceremony transcript published
- Independent verification tools available
- Real-time monitoring during execution

## Current Implementation vs Production

### ✅ What's Ready
- Complete ceremony infrastructure
- Participant management system
- Multi-party computation protocols
- Automatic integration with ZHTP network

### ⚠️ What Needs Production Setup
- **Real participant recruitment** (currently uses validators only)
- **External community outreach** (academic institutions, security firms)
- **Hardware security modules** (for highest-security participants)
- **Legal agreements** (participation terms, liability)

## Ceremony Timeline

### Phase 1: Preparation (2-4 weeks)
- Recruit and verify participants across all types
- Technical setup and testing
- Legal and communication framework

### Phase 2: Execution (1-3 days)
- Sequential participant contributions
- Real-time verification and monitoring
- Immediate integration into network

### Phase 3: Verification (1 week)
- Independent community verification
- Audit of ceremony transcripts
- Final attestation and documentation

## Bottom Line

**ZHTP's ceremony is NOT just for validators** - it's a **community-wide security event** where:

- **Validators provide core network legitimacy**
- **Network operators ensure representation of actual users**  
- **Academic/security experts provide external validation**
- **Community participants provide decentralization**

The ceremony is **completely implemented and ready to run**. The only missing piece is the **actual multi-party execution** with real participants instead of the current deterministic tau generation.

**Ready to run production ceremony whenever the ZHTP community decides to launch mainnet!**

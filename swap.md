# Sovereign Network  
## SOV Swap DEX & DAO Registry  
### Financial and Organizational Backbone

## Overview

The **SOV Swap DEX** and **DAO Registry** form the financial and organizational backbone of the **Sovereign Network**: a decentralized economy uniting citizens, industries, and welfare systems into a single on-chain society.

They power:
- Token creation
- DAO lifecycle management
- Welfare staking and UBI routing

Fully integrated with:
- SOV Tokenomics
- Sovereign ID (SID)
- UBI and welfare staking model

Every website, dApp, or organization inside the Sovereign Network operates as a **DAO** with its own token, treasury, and governance.

---

## 1. Core Modules

### A. Sovereign DEX (SOV Swap)

**Purpose**  
Enable decentralized token swapping, staking, and liquidity across all ecosystem tokens while enforcing strict separation between for-profit and non-profit economies.

#### Features

##### 1. Token Swap Engine
- AMM-based, SOV-centered liquidity pairs
- Supported swaps:
  - Non-Profit ↔ Non-Profit ✅
  - For-Profit ↔ For-Profit ✅
  - Any ↔ SOV ✅
  - For-Profit ↔ Non-Profit ❌ (protocol-restricted)
- Real-time price aggregation (in-house)
- Buyer-side fee automatically funds UBI

##### 2. Liquidity Pools
- Stake SOV + DAO tokens for APY
- Rewards scale with transaction volume and DAO participation
- No mixed FP/NP pools allowed

##### 3. UBI-Linked Fee Routing
Buyer-side fee split:
- 50% → UBI Treasury
- 25% → Liquidity Rewards
- 25% → DAO Registry Maintenance

Creates a self-sustaining social yield.

##### 4. Brokerage Functionality
- DAOs may buy tokens directly from citizens
- Citizens may:
  - Sell to DAO treasury
  - Sell on open DEX
- Reduces volatility and ensures local liquidity

---

### B. DAO Launchpad & Registry

**Purpose**  
Allow any SID to create a for-profit or non-profit DAO directly from the Sovereign App.

#### Features

##### 1. DAO Auto-Generation
Guided setup:
- DAO type (NP / FP)
- Mission and purpose
- Token configuration
- Initial SOV staking

Auto-deployed:
- Token contract
- Tokenomics
- Treasury
- Registry entry
- DEX integration

##### 2. Auto Tokenomics Builder

| DAO Type     | Share to Sovereign Treasury | Rationale |
|--------------|-----------------------------|-----------|
| Non-Profit   | 100%                         | Fully network-owned |
| For-Profit   | 20%                          | Funds UBI and ops |

##### 3. DAO Funding via Staking
- Citizens stake SOV
- Upon threshold:
  - DAO launches
  - Token minted
  - Stakers receive proportional DAO tokens
  - Staked SOV becomes backing reserve

##### 4. Token Class Rules
**For-Profit Tokens**
- Tradable within FP ecosystem
- Cannot enter NP economy

**Non-Profit Tokens**
- Earn-only
- Backed by welfare staking
- Non-tradable across classes

SOV remains the universal bridge.

##### 5. DAO Brokerage
- Token buybacks for exits and stabilization
- No external exchanges required

##### 6. DAO Classification

| DAO Type | Access | Token | Entry Method | Examples |
|--------|--------|-------|--------------|----------|
| Non-Profit | Open | Welfare | Auto | Health, Education |
| For-Profit | Restricted | Utility | Contract | Energy, Tech |

---

## 2. Access Contract System

### Contract Types

**Public Access Contract (NP)**
- Granted to all verified SIDs
- Enables welfare participation

**Employment / Access Contract (FP)**
- Invite-only
- Tracks employment, tax, profit-sharing, voting

All contracts are on-chain verifiable and SID-bound.

---

## 3. CBE DAO (Corporate Template)

Standardized DAO for real-world operations.

Includes:
- Frontend landing (cbe.zhtp/<dao>)
- Governance
- Token vesting
- Employment contracts
- Treasury and brokerage
- Compliance layer:
  - Tax reporting
  - Legal fields
  - Payroll via DAO tokens

---

## 4. Transaction & Fee Logic

| Event | Fee Payer | Destination | Description |
|------|----------|-------------|-------------|
| Token Swap | Buyer | UBI Treasury | Social contribution |
| DAO Creation | Founder | Sovereign Treasury | Registry fee |
| Token Buyback | DAO | Internal | Price stability |
| Staking | None | DAO Treasury | Reserve backing |

---

## 5. On-Chain Architecture


# Other — treasury-kernel

# Treasury Kernel Module Documentation

## Overview

The **Treasury Kernel** module is a critical component of the blockchain ecosystem, responsible for managing token supply, treasury distributions, and economic interactions. It encompasses various token contracts, treasury contracts, and supply management functionalities, ensuring that the economic model operates smoothly and securely.

### Purpose

The Treasury Kernel serves several key functions:
- **Token Management**: It provides a framework for creating and managing different types of tokens, including mintable, burnable, and fixed-supply tokens.
- **Treasury Operations**: It handles treasury-related operations, including fee distributions and fund allocations to various sectors.
- **Supply Management**: It manages the operational token supply, allowing for controlled minting and burning of tokens based on specific use cases.

## Key Components

### 1. Token Contracts

The module includes several token contracts, each with distinct characteristics:

- **TokenContract**: A generic ERC-20-style token contract that allows for minting and burning of tokens. It includes functions like `transfer()`, `mint()`, and `burn()`, but has significant risks due to unrestricted access to `mint()` and `burn()` functions.

- **SovToken**: A fixed-supply sovereign token with a total supply of 1 trillion. It has no mint or burn functions post-initialization, ensuring supply stability.

- **CbeToken**: Another fixed-supply token with a total supply of 100 billion, distributed across four pools with vesting requirements.

- **DAOToken**: A governance token that is mintable and burnable only by the staking contract, ensuring that supply changes are controlled.

### 2. Treasury Contracts

The treasury contracts manage the allocation and distribution of funds:

- **SovDaoTreasury**: Responsible for crediting received amounts for fee distribution.
- **NonprofitTreasury**: Handles incoming funds and allows for DAO-approved withdrawals.
- **ForProfitTreasury**: Manages profit declarations and mandatory tribute settlements.

### 3. Supply Manager

The **SupplyManager** is responsible for operational token supply management, allowing for unlimited minting for network operations. It includes functions like `mint_operational_tokens()` and `burn_tokens()`, which are crucial for maintaining the economic balance.

### 4. UBI Distributor

The **UbiDistributor** contract manages the Universal Basic Income (UBI) distribution to citizens. It receives funds from governance and allows citizens to claim their UBI based on specific conditions.

### 5. DAO Consensus Layer

The DAO consensus layer validates governance proposals and votes but does not directly mutate balances. It delegates execution to the blockchain layer, ensuring that all economic actions are properly authorized.

## Call Graph

The following Mermaid diagram illustrates the relationships between the key components of the Treasury Kernel module:

```mermaid
graph TD;
    A[TokenContract] -->|mint()| B[SupplyManager]
    A -->|burn()| B
    A -->|transfer()| C[DAOToken]
    C -->|mint()| D[StakingContract]
    C -->|burn()| D
    E[SovToken] -->|init()| F[SupplyManager]
    G[CbeToken] -->|init()| F
    H[UbiDistributor] -->|claim_ubi()| I[TokenContract]
    J[SovDaoTreasury] -->|credit()| K[TreasuryRegistry]
    L[NonprofitTreasury] -->|receive()| K
    M[ForProfitTreasury] -->|declare_profit()| K
```

## Execution Flow

The execution flow within the Treasury Kernel module is primarily driven by external calls that trigger balance mutations. Key entry points include:

- **Token Operations**: Functions like `mint()`, `burn()`, and `transfer()` in the `TokenContract` and `DAOToken` manage token supply and transfers.
- **Treasury Operations**: Functions in the treasury contracts handle incoming funds and distributions, ensuring that treasury balances are updated accordingly.
- **UBI Claims**: The `claim_ubi()` function in the `UbiDistributor` allows citizens to claim their UBI, which involves transferring tokens from the UBI pool.

## Risk Assessment

The Treasury Kernel module has several risk vectors associated with supply mutations:

- **High Risk**: Unrestricted `mint()` and `burn()` functions in the `TokenContract` pose significant risks, as any caller can manipulate the token supply.
- **Medium Risk**: The `DAOToken` minting and burning functions are gated by the staking contract, but they are not kernel-protected.
- **Low Risk**: Properly gated functions in the treasury contracts and fixed-supply tokens mitigate risks effectively.

## Conclusion

The Treasury Kernel module is a foundational element of the blockchain's economic framework, providing essential functionalities for token management, treasury operations, and supply control. Understanding its components and interactions is crucial for developers looking to contribute to or extend the capabilities of the module. Proper attention to security and risk management is vital to maintain the integrity of the economic model.
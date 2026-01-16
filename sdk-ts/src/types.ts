/**
 * Core type definitions following zhtp-cli and lib-network patterns
 */

/**
 * Domain operation types
 */
export enum DomainOp {
  Register = 'register',
  Check = 'check',
  Lookup = 'lookup',
  Transfer = 'transfer',
  Release = 'release',
  Renew = 'renew',
}

export interface DomainOpConfig {
  endpointPath: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  title: string;
}

const DOMAIN_OPS: Record<DomainOp, DomainOpConfig> = {
  [DomainOp.Register]: {
    endpointPath: '/api/v1/web4/domains/register',
    method: 'POST',
    title: 'Register Domain',
  },
  [DomainOp.Check]: {
    endpointPath: '/api/v1/web4/domains/check',
    method: 'GET',
    title: 'Check Domain Availability',
  },
  [DomainOp.Lookup]: {
    endpointPath: '/api/v1/web4/domains/lookup',
    method: 'GET',
    title: 'Lookup Domain',
  },
  [DomainOp.Transfer]: {
    endpointPath: '/api/v1/web4/domains/transfer',
    method: 'POST',
    title: 'Transfer Domain',
  },
  [DomainOp.Release]: {
    endpointPath: '/api/v1/web4/domains/release',
    method: 'POST',
    title: 'Release Domain',
  },
  [DomainOp.Renew]: {
    endpointPath: '/api/v1/web4/domains/renew',
    method: 'POST',
    title: 'Renew Domain',
  },
};

export function getDomainOpConfig(op: DomainOp): DomainOpConfig {
  return DOMAIN_OPS[op];
}

/**
 * Wallet operation types
 */
export enum WalletOp {
  Create = 'create',
  List = 'list',
  Balance = 'balance',
  Transfer = 'transfer',
  History = 'history',
  Stake = 'stake',
  Unstake = 'unstake',
}

export interface WalletOpConfig {
  endpointPath: string;
  method: 'GET' | 'POST';
  title: string;
}

const WALLET_OPS: Record<WalletOp, WalletOpConfig> = {
  [WalletOp.Create]: {
    endpointPath: '/api/v1/wallet/create',
    method: 'POST',
    title: 'Create Wallet',
  },
  [WalletOp.List]: {
    endpointPath: '/api/v1/wallet/list',
    method: 'GET',
    title: 'List Wallets',
  },
  [WalletOp.Balance]: {
    endpointPath: '/api/v1/wallet/balance',
    method: 'GET',
    title: 'Get Balance',
  },
  [WalletOp.Transfer]: {
    endpointPath: '/api/v1/wallet/send',
    method: 'POST',
    title: 'Transfer',
  },
  [WalletOp.History]: {
    endpointPath: '/api/v1/wallet/transactions',
    method: 'GET',
    title: 'Transaction History',
  },
  [WalletOp.Stake]: {
    endpointPath: '/api/v1/wallet/stake',
    method: 'POST',
    title: 'Stake',
  },
  [WalletOp.Unstake]: {
    endpointPath: '/api/v1/wallet/unstake',
    method: 'POST',
    title: 'Unstake',
  },
};

export function getWalletOpConfig(op: WalletOp): WalletOpConfig {
  return WALLET_OPS[op];
}

/**
 * Domain information response
 */
export interface DomainInfo {
  domain: string;
  owner: string;
  registeredAt: number;
  expiresAt: number;
  contentCid: string;
  contentVersion: number;
  metadata?: Record<string, string>;
}

/**
 * Domain registration request
 */
export interface DomainRegisterRequest {
  domain: string;
  owner: string;
  contentMappings?: Record<string, string>;
  metadata?: Record<string, string>;
  signature: string;
  timestamp: number;
  fee: bigint;
}

/**
 * Wallet information
 */
export interface WalletInfo {
  address: string;
  type: 'primary' | 'secondary' | 'staking';
  balance: bigint;
  stakedAmount?: bigint;
  pendingUnstake?: bigint;
  lastUpdated: number;
}

/**
 * Transaction information
 */
export interface Transaction {
  hash: string;
  from: string;
  to: string;
  amount: bigint;
  fee: bigint;
  timestamp: number;
  status: 'pending' | 'confirmed' | 'failed';
  blockNumber?: number;
  confirmations?: number;
}

/**
 * Deployment manifest following zhtp-cli pattern
 */
export interface DeployManifest {
  version: number;
  domain: string;
  mode: 'spa' | 'static';
  files: FileEntry[];
  rootHash: string;
  totalSize: bigint;
  deployedAt: number;
  authorDid: string;
  signature: string;
}

/**
 * File entry in manifest
 */
export interface FileEntry {
  path: string;
  size: number;
  mimeType: string;
  hash: string;
}

/**
 * Trust configuration for QUIC client
 * Mirrors zhtp-cli TrustConfig
 */
export interface TrustConfig {
  mode: 'bootstrap' | 'tofu' | 'pinned' | 'default';
  nodeDidExpectation?: string;
  pinnedSpki?: string;
  trustDbPath?: string;
}

/**
 * Client configuration
 */
export interface ZhtpClientConfig {
  baseUrl: string;
  timeout?: number;
  allowBootstrap?: boolean;
  debug?: boolean;
}

/**
 * Domain-specific types for the SDK
 */

export interface RegisterOptions {
  contentCid?: string;
  fee?: number;
  years?: number;
  metadata?: Record<string, string>;
  governance?: {
    config?: {
      contractAddress?: string;
      did?: string;
    };
    delegate?: {
      delegate: string;
      expiration?: number;
    };
  };
}

export interface RegisterResult {
  domain: string;
  owner: string;
  registeredAt: number;
  expiresAt: number;
  transactionHash: string;
  contentCid?: string;
}

export interface DomainInfo {
  domain: string;
  owner: string;
  registeredAt: number;
  expiresAt: number;
  contentCid: string;
  contentVersion: number;
  governance?: {
    config?: {
      contractAddress?: string;
      did?: string;
    };
    delegate?: {
      delegate: string;
      expiration?: number;
    };
  };
  metadata?: Record<string, string>;
}

export interface DomainStatus {
  domain: string;
  status: 'active' | 'expired' | 'reserved' | 'not_found';
  owner?: string;
  expiresAt?: number;
}

export interface DomainHistory {
  domain: string;
  events: DomainEvent[];
  totalEvents: number;
}

export interface DomainEvent {
  type: 'registered' | 'transferred' | 'renewed' | 'updated' | 'released';
  timestamp: number;
  from: string;
  to?: string;
  transactionHash: string;
  metadata?: Record<string, string>;
}

export interface TransferOptions {
  fee?: number;
}

export interface Proof {
  signature: string;
  publicKey: string;
  timestamp?: number;
}

export interface DeployOptions {
  domain: string;
  buildDir: string;
  mode: 'spa' | 'static';
  metadata?: Record<string, string>;
}

export interface DeployResult {
  domain: string;
  manifestCid: string;
  version: number;
  filesDeployed: number;
  totalSize: number;
  deployedAt: number;
  url: string;
}

export interface UpdateOptions {
  domain: string;
  buildDir: string;
}

export interface UpdateResult {
  domain: string;
  manifestCid: string;
  version: number;
  filesDeployed: number;
  totalSize: number;
  updatedAt: number;
}

export interface Deployment {
  version: number;
  manifestCid: string;
  deployedAt: number;
  filesCount: number;
  totalSize: number;
  metadata?: Record<string, string>;
}

export interface Manifest {
  version: number;
  created: number;
  updated: number;
  files: Record<string, FileEntry>;
  root?: string;
  metadata?: ManifestMetadata;
}

export interface FileEntry {
  cid: string;
  size: number;
  mimeType: string;
  path: string;
}

export interface ManifestMetadata {
  name?: string;
  description?: string;
  author?: string;
  license?: string;
  homepage?: string;
}

export type WalletType = 'primary' | 'secondary' | 'staking';

export interface Wallet {
  address: string;
  walletType: WalletType;
  balance: number;
  stakedAmount?: number;
  pendingUnstake?: number;
  lastUpdated: number;
}

export interface Balance {
  address: string;
  balance: number;
  stakedAmount?: number;
  pendingUnstake?: number;
  lastUpdated: number;
}

export interface Transaction {
  transactionHash: string;
  status: 'pending' | 'confirmed' | 'failed';
  from: string;
  to: string;
  amount: number;
  fee: number;
  timestamp: number;
  blockNumber?: number;
  confirmations?: number;
  type: 'transfer' | 'stake' | 'unstake' | 'domain_registration' | 'domain_transfer';
}

export interface SendOptions {
  amount: number;
  fee?: number;
  memo?: string;
}

export interface StakeOptions {
  amount: number;
  fee?: number;
}

export interface UnstakeOptions {
  amount: number;
  fee?: number;
}

export interface Identity {
  id: string;
  did: string;
  publicKey: string;
  privateKey?: string;
}

export interface ClientOptions {
  baseUrl: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  debug?: boolean;
}

export interface ProgressCallback {
  (progress: {
    loaded: number;
    total: number;
    percentage: number;
    status: string;
  }): void;
}

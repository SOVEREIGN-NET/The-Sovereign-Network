/**
 * Response types for ZHTP/Web4 API
 */

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
  timestamp?: number;
}

export interface SimpleDomainRegistrationResponse {
  domain: string;
  owner: string;
  registeredAt: number;
  expiresAt: number;
  contentCid?: string;
  transactionHash?: string;
}

export interface DomainCheckResponse {
  domain: string;
  available: boolean;
  owner?: string;
  registeredAt?: number;
}

export interface DomainInfo {
  domain: string;
  owner: string;
  registeredAt: number;
  expiresAt: number;
  contentCid: string;
  contentVersion: number;
  governance?: {
    config?: GovernancePointer;
    delegate?: GovernanceDelegation;
  };
  metadata?: Record<string, string>;
}

export interface GovernancePointer {
  contractAddress?: string;
  did?: string;
}

export interface GovernanceDelegation {
  delegate: string;
  expiration?: number;
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

export interface BlobUploadResponse {
  cid: string;
  size: number;
  contentType: string;
  uploadedAt: number;
}

export interface ManifestUploadResponse {
  cid: string;
  version: number;
  fileCount: number;
  totalSize: number;
  uploadedAt: number;
}

export interface ManifestFetchResponse {
  cid: string;
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

export interface ChunkedUploadInitResponse {
  uploadId: string;
  expiresAt: number;
  chunkSize: number;
}

export interface ChunkedUploadChunkResponse {
  uploadId: string;
  chunkIndex: number;
  received: boolean;
  nextChunkIndex: number;
}

export interface ChunkedUploadFinalizeResponse {
  cid: string;
  size: number;
  uploadedAt: number;
  verified: boolean;
}

export interface TransactionResponse {
  transactionHash: string;
  status: 'pending' | 'confirmed' | 'failed';
  from: string;
  to: string;
  amount: number;
  fee: number;
  timestamp: number;
  blockNumber?: number;
  confirmations?: number;
}

export interface WalletInfo {
  address: string;
  walletType: 'primary' | 'secondary' | 'staking';
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

export interface DeploymentResult {
  domain: string;
  manifestCid: string;
  version: number;
  filesDeployed: number;
  totalSize: number;
  deployedAt: number;
  url: string;
}

export interface Deployment {
  version: number;
  manifestCid: string;
  deployedAt: number;
  filesCount: number;
  totalSize: number;
  metadata?: Record<string, string>;
}

export interface ErrorResponse {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp?: number;
}

/**
 * Request types for ZHTP/Web4 API
 */

export interface SimpleDomainRegistrationRequest {
  domain: string;
  publicKey: string;
  signature: string;
  content?: string;
  identityId?: string;
  fee?: number;
  metadata?: Record<string, string>;
}

export interface DomainCheckRequest {
  domain: string;
}

export interface DomainLookupRequest {
  domain: string;
}

export interface DomainTransferRequest {
  domain: string;
  newOwner: string;
  publicKey: string;
  signature: string;
}

export interface DomainReleaseRequest {
  domain: string;
  publicKey: string;
  signature: string;
}

export interface BlobUploadRequest {
  data: Uint8Array;
  contentType: string;
}

export interface ManifestUploadRequest {
  manifest: ManifestContent;
  signature: string;
  publicKey: string;
}

export interface ManifestContent {
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

export interface ChunkedUploadInitRequest {
  contentType: string;
  totalSize: number;
  filename: string;
}

export interface ChunkedUploadChunkRequest {
  uploadId: string;
  chunkIndex: number;
  chunk: Uint8Array;
  totalChunks: number;
}

export interface ChunkedUploadFinalizeRequest {
  uploadId: string;
  contentHash: string;
}

export interface SendTransactionRequest {
  from: string;
  to: string;
  amount: number;
  publicKey: string;
  signature: string;
  fee?: number;
  memo?: string;
}

export interface StakeRequest {
  identityId: string;
  amount: number;
  publicKey: string;
  signature: string;
  fee?: number;
}

export interface UnstakeRequest {
  identityId: string;
  amount: number;
  publicKey: string;
  signature: string;
  fee?: number;
}

export interface SignatureVerificationRequest {
  publicKey: string;
  signature: string;
  message: Uint8Array;
}

export interface AuthSignRequest {
  message: Uint8Array;
}

export interface AuthSignResponse {
  signature: string;
  publicKey: string;
  timestamp: number;
}

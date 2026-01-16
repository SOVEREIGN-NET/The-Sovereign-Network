/**
 * @zhtp/sdk - TypeScript SDK for ZHTP/Web4 API
 *
 * A production-ready SDK for registering domains, deploying dApps,
 * and managing wallets on the ZHTP network.
 */

// Internal imports for use in this module
import { ZhtpClient, createZhtpClient } from './client.js';
import { IdentityManager } from './crypto/identity.js';

// Main client
export { ZhtpClient, createZhtpClient } from './client.js';

// Managers
export { DomainManager } from './managers/domain.js';
export { ContentManager } from './managers/content.js';
export { DeployManager } from './managers/deploy.js';
export { WalletManager } from './managers/wallet.js';

// Identity
export { IdentityManager, loadIdentityFromKeystore, createIdentity } from './crypto/identity.js';
export type { IdentityConfig } from './crypto/identity.js';

// Crypto utilities
export {
  blake3Hash,
  calculateContentHash,
  bytesToHex,
  hexToBytes,
  base64Encode,
  base64Decode,
  stringToBytes,
  bytesToString,
  calculateDomainFee,
  validateDomain,
  generateDid,
  extractPublicKeyFromDid,
} from './crypto/utils.js';

// Transport
export { HttpTransport } from './transport/http.js';
export { HttpError } from './transport/http.js';
export type { Transport, TransportOptions, RequestOptions, Response } from './transport/types.js';

// Domain types
export type {
  RegisterOptions,
  RegisterResult,
  DomainInfo,
  DomainStatus,
  DomainHistory,
  DomainEvent,
  TransferOptions,
  Proof,
  DeployOptions,
  DeployResult,
  UpdateOptions,
  UpdateResult,
  Deployment,
  Manifest,
  FileEntry,
  ManifestMetadata,
  Wallet,
  WalletType,
  Balance,
  Transaction,
  SendOptions,
  StakeOptions,
  UnstakeOptions,
  Identity,
  ClientOptions,
  ProgressCallback,
} from './types/domain.js';

// Request types
export type {
  SimpleDomainRegistrationRequest,
  DomainCheckRequest,
  DomainLookupRequest,
  DomainTransferRequest,
  DomainReleaseRequest,
  BlobUploadRequest,
  ManifestUploadRequest,
  ManifestContent,
  ChunkedUploadInitRequest,
  ChunkedUploadChunkRequest,
  ChunkedUploadFinalizeRequest,
  SendTransactionRequest,
  StakeRequest,
  UnstakeRequest,
  SignatureVerificationRequest,
  AuthSignRequest,
  AuthSignResponse,
} from './types/requests.js';

// Response types
export type {
  ApiResponse,
  SimpleDomainRegistrationResponse,
  DomainCheckResponse,
  DomainStatus as DomainStatusResponse,
  DomainHistory as DomainHistoryResponse,
  DomainEvent as DomainEventResponse,
  BlobUploadResponse,
  ManifestUploadResponse,
  ManifestFetchResponse,
  ChunkedUploadInitResponse,
  ChunkedUploadChunkResponse,
  ChunkedUploadFinalizeResponse,
  TransactionResponse,
  WalletInfo,
  Balance as BalanceResponse,
  Transaction as TransactionHistoryResponse,
  DeploymentResult,
  Deployment as DeploymentResponse,
  ErrorResponse,
} from './types/responses.js';

// Package version
export const VERSION = '1.0.0';

// Quick start helper - create a client from just a public key
export function createClient(publicKey: string, baseUrl = 'http://localhost:8080') {
  const identity = IdentityManager.fromPublicKey(publicKey);
  return createZhtpClient(identity, baseUrl);
}

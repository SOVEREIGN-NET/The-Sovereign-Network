/**
 * @zhtp/sdk - TypeScript SDK for ZHTP/Web4 Protocol (QUIC-Native)
 *
 * Following zhtp-cli patterns:
 * - Three-layer client initialization (identity → trust config → connect)
 * - Operation enums for polymorphic routing
 * - Pure validation functions
 * - Dependency injection for testability
 * - Domain-specific error types with context
 * - QUIC-native transport with UHP handshake
 */

// Error types
export { SdkError, IdentityError, WalletError, DomainError, DeploymentError, NetworkError, ValidationError } from './error.js';
export type { ValidationIssue, SdkResult } from './error.js';

// Output abstraction
export { ConsoleOutput, SilentOutput, MockOutput } from './output.js';
export type { Output } from './output.js';

// Identity and keystore
export {
  loadIdentityFromKeystore,
  generateDid,
  extractPublicKeyFromDid,
  createIdentity,
  validateIdentity,
  serializeIdentity,
} from './identity.js';
export type { LoadedIdentity, ZhtpIdentity, KeyPair, PrivateKeyMaterial } from './identity.js';

// Validation functions
export {
  validateDomain,
  validateWalletAddress,
  validateTransactionAmount,
  validateWalletName,
  validateSufficientBalance,
  validateDid,
  validateMetadata,
  calculateDomainRegistrationFee,
  calculateTransactionFee,
} from './validation.js';

// Types
export { DomainOp, WalletOp, getDomainOpConfig, getWalletOpConfig } from './types.js';
export type {
  DomainInfo,
  DomainRegisterRequest,
  WalletInfo,
  Transaction,
  DeployManifest,
  FileEntry,
  TrustConfig,
  ZhtpClientConfig,
} from './types.js';

// QUIC client and connection
export { ZhtpQuicClient, connectClient } from './quic/client.js';
export type { QuicClientConfig, AuthenticatedConnection } from './quic/types.js';

// Main client and initialization
export { ZhtpClient, loadIdentity, buildTrustConfig, initializeClient, connect } from './client.js';

// Managers
export { DomainManager } from './managers/domain.js';
export type { RegisterOptions, TransferProof } from './managers/domain.js';
export { WalletManager } from './managers/wallet.js';
export { ContentManager } from './managers/content.js';
export type { FileUploadResult, ManifestOptions } from './managers/content.js';
export { DeployManager } from './managers/deploy.js';
export type { DeployOptions, DeployResult } from './managers/deploy.js';

// Export version and name
export const VERSION = '1.0.0';
export const SDK_NAME = '@zhtp/sdk';

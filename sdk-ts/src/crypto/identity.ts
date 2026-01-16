/**
 * Identity management for ZHTP SDK
 * Handles DID generation, keystore loading, and identity operations
 */

import { Identity } from '../types/domain.js';
import { generateDid, hexToBytes } from './utils.js';

export interface IdentityConfig {
  id: string;
  publicKey: string;
  privateKey?: string;
  did?: string;
}

export class IdentityManager {
  private identity: Identity;

  constructor(config: IdentityConfig) {
    this.identity = {
      id: config.id,
      publicKey: config.publicKey,
      privateKey: config.privateKey,
      did: config.did || generateDid(config.publicKey),
    };
  }

  /**
   * Create an IdentityManager from a config object
   */
  static from(config: IdentityConfig): IdentityManager {
    return new IdentityManager(config);
  }

  /**
   * Create an IdentityManager from a public key
   */
  static fromPublicKey(publicKey: string, id?: string): IdentityManager {
    return new IdentityManager({
      id: id || generateDid(publicKey),
      publicKey,
    });
  }

  /**
   * Get the identity object
   */
  getIdentity(): Identity {
    return { ...this.identity };
  }

  /**
   * Get identity ID
   */
  getId(): string {
    return this.identity.id;
  }

  /**
   * Get DID
   */
  getDid(): string {
    return this.identity.did;
  }

  /**
   * Get public key (hex-encoded)
   */
  getPublicKey(): string {
    return this.identity.publicKey;
  }

  /**
   * Get public key as bytes
   */
  getPublicKeyBytes(): Uint8Array {
    return hexToBytes(this.identity.publicKey);
  }

  /**
   * Check if identity has private key (for signing)
   */
  hasPrivateKey(): boolean {
    return !!this.identity.privateKey;
  }

  /**
   * Get private key if available
   */
  getPrivateKey(): string | undefined {
    return this.identity.privateKey;
  }

  /**
   * Set private key
   */
  setPrivateKey(privateKey: string): void {
    this.identity.privateKey = privateKey;
  }

  /**
   * Serialize identity for storage
   */
  serialize(): IdentityConfig {
    return {
      id: this.identity.id,
      publicKey: this.identity.publicKey,
      privateKey: this.identity.privateKey,
      did: this.identity.did,
    };
  }
}

/**
 * Load identity from zhtp-cli compatible keystore format
 *
 * The keystore uses Argon2 + AES-GCM encryption:
 * - Read keystore file (JSON)
 * - Decrypt using password with Argon2 KDF
 * - Extract public key and optionally private key
 *
 * Format:
 * {
 *   "id": "identity_id",
 *   "publicKey": "hex_encoded_public_key",
 *   "encrypted": "base64_encrypted_data",
 *   "salt": "hex_salt",
 *   "iv": "hex_iv"
 * }
 *
 * Note: This is a placeholder for the actual keystore loading implementation.
 * Actual implementation requires Argon2 and AES-GCM crypto libraries.
 */
export async function loadIdentityFromKeystore(
  _keystorePath: string,
  _password: string
): Promise<IdentityManager> {
  // TODO: Implement actual keystore loading
  // This requires:
  // 1. Reading keystore file
  // 2. Parsing JSON
  // 3. Decrypting with Argon2 KDF + AES-GCM
  // 4. Extracting identity information

  throw new Error('Keystore loading not yet implemented. Use IdentityManager.from() instead.');
}

/**
 * Create a new identity
 * Note: Private key generation requires the Dilithium2 WASM module
 */
export async function createIdentity(_id?: string): Promise<IdentityManager> {
  // TODO: Implement identity creation with key generation
  // This requires:
  // 1. Loading Dilithium2 WASM module
  // 2. Generating keypair
  // 3. Creating identity with DID

  throw new Error('Identity creation not yet implemented. Use IdentityManager.from() instead.');
}

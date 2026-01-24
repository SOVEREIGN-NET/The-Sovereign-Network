/**
 * Identity management - first layer of client initialization
 * Load identity from keystore, manage keypairs, generate DIDs
 */

import { IdentityError, ValidationError } from './error.js';
import { validateDid } from './validation.js';

/**
 * Loaded identity with both public and private keys
 */
export interface LoadedIdentity {
  identity: ZhtpIdentity;
  keypair: KeyPair;
}

/**
 * ZHTP Identity - public information
 */
export interface ZhtpIdentity {
  id: string; // Identity ID (unique identifier)
  did: string; // DID format: did:zhtp:{hex_public_key}
  publicKey: string; // Hex-encoded public key
  createdAt: number; // Unix timestamp
  isActive: boolean;
}

/**
 * Private key material
 */
export interface PrivateKeyMaterial {
  dilithiumSk: string; // Dilithium5 secret key (base64)
  kyberSk: string; // Kyber1024 secret key (base64)
  masterSeed: string; // Master seed (base64)
}

/**
 * KeyPair - both public and private keys
 */
export interface KeyPair {
  publicKey: string; // Hex-encoded
  privateKey: PrivateKeyMaterial;
  // Extended key material for post-quantum operations (optional)
  dilithiumPk?: string; // Dilithium5 public key (base64)
  kyberPk?: string; // Kyber1024 public key (base64)
}

/**
 * Keystore file format (JSON)
 */
interface KeystoreFile {
  id: string;
  did: string;
  publicKey: string;
  createdAt: number;
  isActive: boolean;
}

interface PrivateKeyFile {
  dilithiumSk: string;
  kyberSk: string;
  masterSeed: string;
}

/**
 * Raw keystore identity file format (as stored on disk)
 */
interface RawKeystoreIdentity {
  id: number[]; // byte array
  did: string;
  public_key: {
    dilithium_pk: number[];
    kyber_pk: number[];
    key_id: number[];
  };
  created_at: number;
  // Other fields we don't need for basic loading
  [key: string]: unknown;
}

/**
 * Raw keystore private key file format
 */
interface RawKeystorePrivateKey {
  dilithium_sk: number[]; // byte array
  kyber_sk: number[]; // byte array
  master_seed: number[]; // byte array
}

/**
 * Convert byte array to hex string
 */
function bytesToHex(bytes: number[]): string {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert byte array to base64 string
 */
function bytesToBase64(bytes: number[]): string {
  // In Node.js environment
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  // In browser environment
  const binary = String.fromCharCode(...bytes);
  return btoa(binary);
}

/**
 * Load identity from keystore
 * Mirrors zhtp-cli pattern: load_identity_from_keystore
 * Files needed:
 * - {keystorePath}/user_identity.json
 * - {keystorePath}/user_private_key.json
 */
export async function loadIdentityFromKeystore(
  keystorePath: string,
): Promise<LoadedIdentity> {
  // Use dynamic import for fs to support both Node.js and potential browser bundling
  const fs = await import('fs').then(m => m.promises);
  const path = await import('path');

  const identityPath = path.join(keystorePath, 'user_identity.json');
  const privateKeyPath = path.join(keystorePath, 'user_private_key.json');

  try {
    // Read identity file
    const identityData = await fs.readFile(identityPath, 'utf-8');
    const rawIdentity: RawKeystoreIdentity = JSON.parse(identityData);

    // Read private key file
    const privateKeyData = await fs.readFile(privateKeyPath, 'utf-8');
    const rawPrivateKey: RawKeystorePrivateKey = JSON.parse(privateKeyData);

    // Convert identity ID bytes to hex string
    const identityId = bytesToHex(rawIdentity.id);

    // Extract DID - should already be in correct format
    const did = rawIdentity.did;

    // Validate DID format
    const didValidation = validateDid(did);
    if (!didValidation.valid) {
      throw new IdentityError('Invalid DID format in keystore', {
        did,
        errors: didValidation.errors,
      });
    }

    // Extract public key from DID (the hex part after did:zhtp:)
    const publicKeyHex = did.split(':')[2];

    // Convert private keys to base64 for storage
    const privateKey: PrivateKeyMaterial = {
      dilithiumSk: bytesToBase64(rawPrivateKey.dilithium_sk),
      kyberSk: bytesToBase64(rawPrivateKey.kyber_sk),
      masterSeed: bytesToBase64(rawPrivateKey.master_seed),
    };

    // Also store dilithium public key for signing operations
    const dilithiumPkBase64 = bytesToBase64(rawIdentity.public_key.dilithium_pk);
    const kyberPkBase64 = bytesToBase64(rawIdentity.public_key.kyber_pk);

    const loadedIdentity: LoadedIdentity = {
      identity: {
        id: identityId,
        did,
        publicKey: publicKeyHex,
        createdAt: rawIdentity.created_at || Math.floor(Date.now() / 1000),
        isActive: true,
      },
      keypair: {
        publicKey: publicKeyHex,
        privateKey,
        // Extended key material for post-quantum operations
        dilithiumPk: dilithiumPkBase64,
        kyberPk: kyberPkBase64,
      },
    };

    // Validate the loaded identity
    const validationError = validateIdentity(loadedIdentity);
    if (validationError) {
      throw validationError;
    }

    return loadedIdentity;
  } catch (e) {
    if (e instanceof IdentityError || e instanceof ValidationError) {
      throw e;
    }
    throw new IdentityError(
      `Failed to load identity from keystore: ${e instanceof Error ? e.message : 'unknown error'}`,
      { keystorePath, identityPath, privateKeyPath },
    );
  }
}

/**
 * Generate a DID from public key
 * Format: did:zhtp:{hex_public_key}
 */
export function generateDid(publicKey: string): string {
  return `did:zhtp:${publicKey}`;
}

/**
 * Extract public key from DID
 */
export function extractPublicKeyFromDid(did: string): string {
  const validation = validateDid(did);
  if (!validation.valid) {
    throw new IdentityError('Invalid DID format', {
      did,
      errors: validation.errors,
    });
  }

  const parts = did.split(':');
  return parts[2];
}

/**
 * Create identity from components
 * Used when constructing identity programmatically (for testing or manual setup)
 */
export function createIdentity(
  id: string,
  publicKey: string,
  privateKey: PrivateKeyMaterial,
): LoadedIdentity {
  const did = generateDid(publicKey);

  const validation = validateDid(did);
  if (!validation.valid) {
    throw new ValidationError('Failed to create identity with invalid DID', validation.errors, {
      id,
      publicKey,
    });
  }

  return {
    identity: {
      id,
      did,
      publicKey,
      createdAt: Math.floor(Date.now() / 1000),
      isActive: true,
    },
    keypair: {
      publicKey,
      privateKey,
    },
  };
}

/**
 * Validate loaded identity
 */
export function validateIdentity(loaded: LoadedIdentity): ValidationError | null {
  const didValidation = validateDid(loaded.identity.did);
  if (!didValidation.valid) {
    return new ValidationError('Identity validation failed', didValidation.errors, {
      id: loaded.identity.id,
      did: loaded.identity.did,
    });
  }

  // Verify public key matches DID
  const didPublicKey = extractPublicKeyFromDid(loaded.identity.did);
  if (didPublicKey !== loaded.identity.publicKey) {
    return new ValidationError('Identity public key mismatch', [], {
      didPublicKey,
      identityPublicKey: loaded.identity.publicKey,
    });
  }

  // Verify keypair public key matches identity
  if (loaded.keypair.publicKey !== loaded.identity.publicKey) {
    return new ValidationError('Keypair public key does not match identity', [], {
      keypairPublicKey: loaded.keypair.publicKey,
      identityPublicKey: loaded.identity.publicKey,
    });
  }

  return null;
}

/**
 * Serialize identity for storage
 */
export function serializeIdentity(loaded: LoadedIdentity): {
  identity: KeystoreFile;
  privateKey: PrivateKeyFile;
} {
  return {
    identity: {
      id: loaded.identity.id,
      did: loaded.identity.did,
      publicKey: loaded.identity.publicKey,
      createdAt: loaded.identity.createdAt,
      isActive: loaded.identity.isActive,
    },
    privateKey: {
      dilithiumSk: loaded.keypair.privateKey.dilithiumSk,
      kyberSk: loaded.keypair.privateKey.kyberSk,
      masterSeed: loaded.keypair.privateKey.masterSeed,
    },
  };
}

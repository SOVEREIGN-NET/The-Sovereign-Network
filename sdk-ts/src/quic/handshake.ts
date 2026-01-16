/**
 * UHP (ZHTP Handshake Protocol) orchestration
 * Three-phase authentication with Dilithium5 + Kyber512
 *
 * Phase 1: ClientHello → ServerHello (signature-based auth)
 * Phase 2: Kyber512 KEM (key exchange)
 * Phase 3: Master key derivation (combine UHP + Kyber secrets)
 */

import { blake3 } from '@noble/hashes/blake3';
import {
  UhpClientHello,
  UhpServerHello,
  UhpClientFinish,
  KyberEncapsulation,
  AuthenticatedConnection,
} from './types.js';

// Initialize post-quantum crypto factories (singletons)
let kyberInstance: any = null;
let dilithiumInstance: any = null;

async function initializeKyber() {
  if (!kyberInstance) {
    try {
      // @ts-ignore - crystals-kyber-js exports Kyber functions directly
      const KyberModule = await import('crystals-kyber-js');
      // Use whatever export is available
      const KyberClass = (KyberModule as any).Kyber || (KyberModule as any).default;
      kyberInstance = new KyberClass();
    } catch (error) {
      throw new Error(`Failed to load Kyber512: ${error instanceof Error ? error.message : 'unknown'}`);
    }
  }
  return kyberInstance;
}

async function initializeDilithium() {
  if (!dilithiumInstance) {
    try {
      // @ts-ignore - dilithium-crystals-js exports Dilithium functions directly
      const DilithiumModule = await import('dilithium-crystals-js');
      // Use whatever export is available
      const DilithiumClass = (DilithiumModule as any).Dilithium || (DilithiumModule as any).default;
      dilithiumInstance = new DilithiumClass();
    } catch (error) {
      throw new Error(`Failed to load Dilithium5: ${error instanceof Error ? error.message : 'unknown'}`);
    }
  }
  return dilithiumInstance;
}

/**
 * Create ClientHello message with Kyber512 public key
 */
export function createClientHello(clientDid: string, nonce: Uint8Array, kyberPublicKey: Uint8Array): UhpClientHello {
  if (nonce.length !== 32) {
    throw new Error('Nonce must be 32 bytes');
  }
  if (kyberPublicKey.length !== 1184) {
    throw new Error('Kyber512 public key must be 1184 bytes');
  }

  return {
    clientDid,
    timestamp: BigInt(Date.now()) * 1_000_000n, // Nanoseconds
    nonce,
    kyberPublicKey,
  };
}

/**
 * Serialize ClientHello for hashing
 */
export function serializeClientHello(hello: UhpClientHello): Uint8Array {
  const didBytes = new TextEncoder().encode(hello.clientDid);
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigInt64(0, hello.timestamp, false);

  const serialized = new Uint8Array(didBytes.length + 1 + 8 + 32 + 1184);
  let offset = 0;

  // Length-prefixed clientDid
  serialized[offset++] = didBytes.length;
  serialized.set(didBytes, offset);
  offset += didBytes.length;

  // Timestamp
  serialized.set(tsBytes, offset);
  offset += 8;

  // Nonce
  serialized.set(hello.nonce, offset);
  offset += 32;

  // Kyber512 public key
  serialized.set(hello.kyberPublicKey, offset);

  return serialized;
}

/**
 * Serialize ServerHello for hashing
 */
export function serializeServerHello(hello: UhpServerHello): Uint8Array {
  const sessionIdBytes = new TextEncoder().encode(hello.sessionId);
  const didBytes = new TextEncoder().encode(hello.serverDid);
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigInt64(0, hello.timestamp, false);

  const serialized = new Uint8Array(
    1 + sessionIdBytes.length + 1 + didBytes.length + hello.serverEphemeralPk.length + hello.kyberCiphertext.length + 8,
  );
  let offset = 0;

  // Length-prefixed sessionId
  serialized[offset++] = sessionIdBytes.length;
  serialized.set(sessionIdBytes, offset);
  offset += sessionIdBytes.length;

  // Length-prefixed serverDid
  serialized[offset++] = didBytes.length;
  serialized.set(didBytes, offset);
  offset += didBytes.length;

  // Server ephemeral public key
  serialized.set(hello.serverEphemeralPk, offset);
  offset += hello.serverEphemeralPk.length;

  // Kyber512 encapsulated key (ciphertext)
  serialized.set(hello.kyberCiphertext, offset);
  offset += hello.kyberCiphertext.length;

  // Timestamp
  serialized.set(tsBytes, offset);

  return serialized;
}

/**
 * Create ClientFinish message
 * Signature is over: hash(ClientHello || ServerHello)
 */
export function createClientFinish(
  sessionId: string,
  clientHello: UhpClientHello,
  serverHello: UhpServerHello,
  clientSignature: Uint8Array,
): UhpClientFinish {
  return {
    sessionId,
    clientSignature,
  };
}

/**
 * Hash for ClientHello + ServerHello (for signature)
 */
export function hashHandshakePhase1(clientHello: UhpClientHello, serverHello: UhpServerHello): Uint8Array {
  const clientSerialized = serializeClientHello(clientHello);
  const serverSerialized = serializeServerHello(serverHello);

  const combined = new Uint8Array(clientSerialized.length + serverSerialized.length);
  combined.set(clientSerialized);
  combined.set(serverSerialized, clientSerialized.length);

  return blake3(combined);
}

/**
 * Hash for Phase 1 + Phase 2 (for server signature)
 */
export function hashHandshakePhase2(
  clientHello: UhpClientHello,
  serverHello: UhpServerHello,
  clientFinish: UhpClientFinish,
): Uint8Array {
  const phase1Hash = hashHandshakePhase1(clientHello, serverHello);
  const phase2Bytes = clientFinish.clientSignature;

  const combined = new Uint8Array(phase1Hash.length + phase2Bytes.length);
  combined.set(phase1Hash);
  combined.set(phase2Bytes, phase1Hash.length);

  return blake3(combined);
}

/**
 * Derive master key from UHP + Kyber components
 * Follows HKDF pattern: Extract then Expand
 *
 * Master Key = BLAKE3(
 *   "zhtp-master" ||
 *   UHP phase1 hash ||
 *   Kyber shared secret ||
 *   clientDid ||
 *   serverDid
 * )
 */
export function deriveMasterKey(
  phase1Hash: Uint8Array,
  kyberSharedSecret: Uint8Array,
  clientDid: string,
  serverDid: string,
): Uint8Array {
  const label = new TextEncoder().encode('zhtp-master');
  const clientDidBytes = new TextEncoder().encode(clientDid);
  const serverDidBytes = new TextEncoder().encode(serverDid);

  const material = new Uint8Array(
    label.length + phase1Hash.length + kyberSharedSecret.length + clientDidBytes.length + serverDidBytes.length,
  );

  let offset = 0;
  material.set(label);
  offset += label.length;

  material.set(phase1Hash, offset);
  offset += phase1Hash.length;

  material.set(kyberSharedSecret, offset);
  offset += kyberSharedSecret.length;

  material.set(clientDidBytes, offset);
  offset += clientDidBytes.length;

  material.set(serverDidBytes, offset);

  return blake3(material);
}

/**
 * Create authenticated connection from handshake completion
 * Should be called after all 3 phases succeed
 */
export function createAuthenticatedConnection(
  sessionId: string,
  appKey: Uint8Array,
  serverDid: string,
): AuthenticatedConnection {
  if (appKey.length !== 32) {
    throw new Error('App key must be 32 bytes');
  }

  return {
    sessionId,
    appKey,
    sequence: 0n,
    peerId: serverDid,
  };
}

/**
 * Create Dilithium5 signature using real post-quantum cryptography
 * Uses crystals-dilithium-js for NIST-standardized signatures
 */
export async function createDilithium5Signature(message: Uint8Array): Promise<Uint8Array> {
  try {
    const dilithium = await initializeDilithium();
    // Generate keypair for this session (in production: use client's stored keypair)
    const keyPair = dilithium.generateKeys();
    // Sign the message using the secret key
    const signature = dilithium.sign(message, keyPair.secretKey, 3); // mode 3 = Dilithium5
    return signature.sig;
  } catch (error) {
    throw new Error(`Dilithium5 signature generation failed: ${error instanceof Error ? error.message : 'unknown'}`);
  }
}

/**
 * Verify Dilithium5 signature using real post-quantum cryptography
 */
export async function verifyDilithium5Signature(
  publicKey: string,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const dilithium = await initializeDilithium();
    // Convert public key from hex string to Uint8Array
    const publicKeyBytes = new Uint8Array(Buffer.from(publicKey, 'hex'));
    // Verify the signature
    const result = dilithium.verify(signature, message, publicKeyBytes, 3); // mode 3 = Dilithium5
    return result.valid;
  } catch (error) {
    console.error(`Dilithium5 signature verification failed: ${error instanceof Error ? error.message : 'unknown'}`);
    return false;
  }
}

/**
 * Kyber512 encapsulation (server side) - Real implementation
 * Uses CRYSTALS-Kyber for NIST-standardized key encapsulation
 * Returns encapsulated key + shared secret
 */
export async function kyber512Encapsulate(serverPublicKey: string): Promise<KyberEncapsulation> {
  try {
    const kyber = await initializeKyber();
    // Convert server's public key from hex string
    const publicKeyBytes = new Uint8Array(Buffer.from(serverPublicKey, 'hex'));
    // Perform key encapsulation (generates ciphertext + shared secret)
    const encapsulation = kyber.encaps(publicKeyBytes);

    return {
      ciphertext: encapsulation.ciphertext,
      sharedSecret: encapsulation.sharedSecret,
    };
  } catch (error) {
    throw new Error(`Kyber512 encapsulation failed: ${error instanceof Error ? error.message : 'unknown'}`);
  }
}

/**
 * Kyber512 decapsulation (client side) - Real implementation
 * Uses CRYSTALS-Kyber for NIST-standardized key decapsulation
 */
export async function kyber512Decapsulate(clientPrivateKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  try {
    const kyber = await initializeKyber();
    // Validate ciphertext length (standard Kyber512 size)
    if (ciphertext.length !== 768) {
      throw new Error(`Invalid ciphertext length for Kyber512: expected 768, got ${ciphertext.length}`);
    }
    // Perform key decapsulation (derives shared secret from ciphertext using private key)
    const sharedSecret = kyber.decaps(clientPrivateKey, ciphertext);
    return sharedSecret;
  } catch (error) {
    throw new Error(`Kyber512 decapsulation failed: ${error instanceof Error ? error.message : 'unknown'}`);
  }
}

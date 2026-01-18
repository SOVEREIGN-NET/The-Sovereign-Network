/**
 * UHP (ZHTP Handshake Protocol) orchestration
 *
 * QUIC is transport-only for alpha. UHP v2 provides identity and PQ security.
 * The sdk-ts QUIC handshake is intentionally minimal and does not implement
 * post-quantum key agreement at the transport layer.
 */

import { blake3 } from '@noble/hashes/blake3';
import { UhpClientHello, UhpServerHello, UhpClientFinish, AuthenticatedConnection } from './types.js';

// Initialize post-quantum crypto factories (singletons)
let dilithiumInstance: any = null;

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
 * Create ClientHello message (transport-level only)
 */
export function createClientHello(clientDid: string, nonce: Uint8Array): UhpClientHello {
  if (nonce.length !== 32) {
    throw new Error('Nonce must be 32 bytes');
  }

  return {
    clientDid,
    timestamp: BigInt(Date.now()) * 1_000_000n, // Nanoseconds
    nonce,
  };
}

/**
 * Serialize ClientHello for hashing
 */
export function serializeClientHello(hello: UhpClientHello): Uint8Array {
  const didBytes = new TextEncoder().encode(hello.clientDid);
  const tsBytes = new Uint8Array(8);
  new DataView(tsBytes.buffer).setBigInt64(0, hello.timestamp, false);

  const serialized = new Uint8Array(didBytes.length + 1 + 8 + 32);
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
    1 + sessionIdBytes.length + 1 + didBytes.length + hello.serverEphemeralPk.length + 8,
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
    sequence: 1n,  // Start at 1 (server's last_counter starts at 0)
    peerId: serverDid,
    establishedAt: Date.now(),
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

// UHP v2 session key derivation is handled in the core implementation, not in QUIC.

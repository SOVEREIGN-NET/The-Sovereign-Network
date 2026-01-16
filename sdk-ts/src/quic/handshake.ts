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
  UhpServerFinish,
  KyberEncapsulation,
  AuthenticatedConnection,
} from './types.js';
import { ZhtpIdentity } from '../identity.js';

/**
 * Create ClientHello message
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
 * Placeholder: In production, these would call actual Dilithium5 signing
 * For now, return zero-length signatures (will be replaced with real crypto)
 */
export function createDilithium5Signature(message: Uint8Array): Uint8Array {
  // Placeholder: Real implementation would use dilithium5 library
  // For now: Return 2420 bytes (standard Dilithium5 signature size)
  const sig = new Uint8Array(2420);
  // In production: sig = dilithium5.sign(clientPrivateKey, message)
  return sig;
}

/**
 * Placeholder: Verify Dilithium5 signature
 */
export function verifyDilithium5Signature(
  _publicKey: string,
  _message: Uint8Array,
  _signature: Uint8Array,
): boolean {
  // Placeholder: Real implementation would use dilithium5 library
  // For now: Always return true in Phase 2 (will be fixed in Phase 3)
  return true;
}

/**
 * Placeholder: Kyber512 encapsulation (server side)
 * Returns encapsulated key + shared secret
 */
export function kyber512Encapsulate(_serverPublicKey: string): KyberEncapsulation {
  // Placeholder: Real implementation would use kyber512 library
  // Standard sizes:
  // - ciphertext: 768 bytes
  // - sharedSecret: 32 bytes
  return {
    ciphertext: new Uint8Array(768),
    sharedSecret: new Uint8Array(32),
  };
}

/**
 * Placeholder: Kyber512 decapsulation (client side)
 */
export function kyber512Decapsulate(_clientPrivateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  // Placeholder: Real implementation would use kyber512 library
  // For now: Return 32-byte shared secret
  if (ciphertext.length !== 768) {
    throw new Error('Invalid ciphertext length for Kyber512');
  }
  return new Uint8Array(32);
}

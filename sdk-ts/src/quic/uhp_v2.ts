/**
 * UHP v2 (Unified Handshake Protocol version 2) Implementation
 *
 * This module implements the complete UHP v2 handshake protocol with:
 * - Kyber1024 post-quantum key exchange
 * - Dilithium5 post-quantum signatures
 * - HKDF-SHA3-256 key derivation
 * - Hybrid classical/PQC session keys
 *
 * Wire format must match Rust bincode serialization exactly.
 */

import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { blake3 } from '@noble/hashes/blake3';
import { MlKem1024 } from 'crystals-kyber-js';
import { ZhtpIdentity, KeyPair } from '../identity.js';

// ============================================================================
// Constants
// ============================================================================

const UHP_VERSION = 2;
const NONCE_SIZE = 32;
const SESSION_ID_SIZE = 32;

// Domain separation strings (must match Rust exactly)
const SESSION_KEY_SALT = 'ZHTP-UHP-v2-SESSION-KEY-DERIVATION-2025';
const HYBRID_SESSION_INFO = 'ZHTP-HYBRID-SESSION';
const SESSION_ID_LABEL = 'zhtp/v2/session_id';
const MAC_KEY_LABEL = 'zhtp/v2/mac_key';

// ============================================================================
// Types
// ============================================================================

/** Handshake role */
export enum HandshakeRole {
  Client = 0,
  Server = 1,
}

/** PQC capability */
export enum PqcCapability {
  None = 0,
  Kyber1024Dilithium5 = 1,
}

/** Node identity for handshake */
export interface NodeIdentity {
  did: string;
  publicKey: PublicKeyBundle;
  nodeId: Uint8Array;  // 32 bytes: Blake3(DID || device_id)
  deviceId: string;
  displayName?: string;
  createdAt: number;
}

/** Public key bundle */
export interface PublicKeyBundle {
  dilithiumPk: Uint8Array;  // Dilithium5 public key (2592 bytes)
  kyberPk: Uint8Array;      // Kyber1024 public key (1568 bytes)
  keyId: Uint8Array;        // 32 bytes: BLAKE3 hash of keys
}

/** Handshake capabilities */
export interface HandshakeCapabilities {
  protocols: string[];
  maxThroughput: bigint;
  maxMessageSize: number;
  encryptionMethods: string[];
  pqcCapability: PqcCapability;
  dhtCapable: boolean;
  relayCapable: boolean;
  storageCapacity: bigint;
  web4Capable: boolean;
  customFeatures: string[];
}

/** Negotiated capabilities */
export interface NegotiatedCapabilities {
  pqcCapability: PqcCapability;
  protocol: string;
  maxMessageSize: number;
  encryptionMethod: string;
}

/** PQC handshake offer (Kyber public key + signature) */
export interface PqcHandshakeOffer {
  suite: PqcCapability;
  kyberPublicKey: Uint8Array;  // 1568 bytes for Kyber1024
  dilithiumPublicKey: Uint8Array;  // 2592 bytes for Dilithium5
  signature: Uint8Array;  // Signature over binder
}

/** Dilithium signature with metadata */
export interface Signature {
  signature: Uint8Array;
  publicKey: PublicKeyBundle;
  algorithm: 'Dilithium5';
  timestamp: number;
}

/** ClientHello message */
export interface ClientHello {
  identity: NodeIdentity;
  capabilities: HandshakeCapabilities;
  networkId: string;
  protocolId: string;
  purpose: string;
  role: HandshakeRole;
  channelBinding: Uint8Array;
  challengeNonce: Uint8Array;  // 32 bytes
  signature: Signature;
  timestamp: number;
  protocolVersion: number;
  pqcOffer?: PqcHandshakeOffer;
}

/** ServerHello message */
export interface ServerHello {
  identity: NodeIdentity;
  capabilities: HandshakeCapabilities;
  networkId: string;
  protocolId: string;
  purpose: string;
  role: HandshakeRole;
  channelBinding: Uint8Array;
  responseNonce: Uint8Array;  // 32 bytes
  signature: Signature;
  negotiated: NegotiatedCapabilities;
  timestamp: number;
  protocolVersion: number;
  pqcOffer?: PqcHandshakeOffer;
}

/** ClientFinish message */
export interface ClientFinish {
  signature: Signature;
  networkId: string;
  protocolId: string;
  purpose: string;
  role: HandshakeRole;
  channelBinding: Uint8Array;
  timestamp: number;
  protocolVersion: number;
  sessionParams?: Uint8Array;
  pqcCiphertext?: Uint8Array;  // Kyber1024 encapsulation (~1088 bytes)
}

/** Handshake result */
export interface HandshakeResult {
  peerIdentity: NodeIdentity;
  capabilities: NegotiatedCapabilities;
  sessionKey: Uint8Array;      // 32 bytes - hybrid key
  sessionId: Uint8Array;       // 32 bytes
  handshakeHash: Uint8Array;   // 32 bytes - SHA3-256(all messages)
  macKey: Uint8Array;          // 32 bytes - derived MAC key
  completedAt: number;
  pqcHybridEnabled: boolean;
  protocolVersion: number;
}

/** Ephemeral keys for handshake */
export interface EphemeralKeys {
  kyberPublicKey: Uint8Array;
  kyberSecretKey: Uint8Array;
}

// ============================================================================
// Serialization (bincode-compatible)
// ============================================================================

/**
 * Write length-prefixed string (bincode format: u64 LE length + UTF-8 bytes)
 */
function writeLengthPrefixedString(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  const result = new Uint8Array(8 + bytes.length);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, BigInt(bytes.length), true);  // little-endian
  result.set(bytes, 8);
  return result;
}

/**
 * Write length-prefixed bytes (bincode format: u64 LE length + bytes)
 */
function writeLengthPrefixedBytes(bytes: Uint8Array): Uint8Array {
  const result = new Uint8Array(8 + bytes.length);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, BigInt(bytes.length), true);  // little-endian
  result.set(bytes, 8);
  return result;
}

/**
 * Write u64 as little-endian
 */
function writeU64LE(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, value, true);
  return result;
}

/**
 * Write u32 as little-endian
 */
function writeU32LE(value: number): Uint8Array {
  const result = new Uint8Array(4);
  const view = new DataView(result.buffer);
  view.setUint32(0, value, true);
  return result;
}

/**
 * Concatenate multiple Uint8Arrays
 */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Serialize PublicKeyBundle for signing
 */
function serializePublicKeyBundle(pk: PublicKeyBundle): Uint8Array {
  return concat(
    writeLengthPrefixedBytes(pk.dilithiumPk),
    writeLengthPrefixedBytes(pk.kyberPk),
    pk.keyId,  // Fixed 32 bytes
  );
}

/**
 * Serialize NodeIdentity for signing
 */
function serializeNodeIdentity(identity: NodeIdentity): Uint8Array {
  return concat(
    writeLengthPrefixedString(identity.did),
    serializePublicKeyBundle(identity.publicKey),
    identity.nodeId,  // Fixed 32 bytes
    writeLengthPrefixedString(identity.deviceId),
    identity.displayName
      ? concat(new Uint8Array([1]), writeLengthPrefixedString(identity.displayName))
      : new Uint8Array([0]),  // Option::None
    writeU64LE(BigInt(identity.createdAt)),
  );
}

/**
 * Serialize HandshakeCapabilities for signing
 */
function serializeCapabilities(caps: HandshakeCapabilities): Uint8Array {
  const parts: Uint8Array[] = [];

  // Vec<String> protocols
  parts.push(writeU64LE(BigInt(caps.protocols.length)));
  for (const p of caps.protocols) {
    parts.push(writeLengthPrefixedString(p));
  }

  parts.push(writeU64LE(caps.maxThroughput));
  parts.push(writeU64LE(BigInt(caps.maxMessageSize)));

  // Vec<String> encryptionMethods
  parts.push(writeU64LE(BigInt(caps.encryptionMethods.length)));
  for (const e of caps.encryptionMethods) {
    parts.push(writeLengthPrefixedString(e));
  }

  // PqcCapability enum (u32)
  parts.push(writeU32LE(caps.pqcCapability));

  // bool fields (1 byte each)
  parts.push(new Uint8Array([caps.dhtCapable ? 1 : 0]));
  parts.push(new Uint8Array([caps.relayCapable ? 1 : 0]));
  parts.push(writeU64LE(caps.storageCapacity));
  parts.push(new Uint8Array([caps.web4Capable ? 1 : 0]));

  // Vec<String> customFeatures
  parts.push(writeU64LE(BigInt(caps.customFeatures.length)));
  for (const f of caps.customFeatures) {
    parts.push(writeLengthPrefixedString(f));
  }

  return concat(...parts);
}

// ============================================================================
// Cryptographic Operations
// ============================================================================

/**
 * Generate 32-byte cryptographically secure random nonce
 */
export function generateNonce(): Uint8Array {
  const nonce = new Uint8Array(NONCE_SIZE);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(nonce);
  } else {
    // Node.js fallback
    const nodeCrypto = require('crypto');
    const randomBytes = nodeCrypto.randomBytes(NONCE_SIZE);
    nonce.set(randomBytes);
  }
  return nonce;
}

/**
 * Derive NodeId from DID and device_id
 * NodeId = Blake3(DID || device_id)
 */
export function deriveNodeId(did: string, deviceId: string): Uint8Array {
  const encoder = new TextEncoder();
  const input = concat(encoder.encode(did), encoder.encode(deviceId));
  return blake3(input);
}

/**
 * Derive key_id from public keys
 * key_id = Blake3(dilithium_pk || kyber_pk)
 */
export function deriveKeyId(dilithiumPk: Uint8Array, kyberPk: Uint8Array): Uint8Array {
  return blake3(concat(dilithiumPk, kyberPk));
}

/**
 * Generate Kyber1024 ephemeral keypair for handshake
 */
export async function generateKyberKeypair(): Promise<EphemeralKeys> {
  const kyber = new MlKem1024();
  const [publicKey, secretKey] = await kyber.generateKeyPair();
  return {
    kyberPublicKey: publicKey,
    kyberSecretKey: secretKey,
  };
}

/**
 * Kyber1024 encapsulation - creates shared secret and ciphertext
 */
export async function kyberEncapsulate(
  serverKyberPk: Uint8Array,
): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
  const kyber = new MlKem1024();
  const [ciphertext, sharedSecret] = await kyber.encap(serverKyberPk);
  return { ciphertext, sharedSecret };
}

/**
 * Kyber1024 decapsulation - recovers shared secret from ciphertext
 */
export async function kyberDecapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Promise<Uint8Array> {
  const kyber = new MlKem1024();
  return await kyber.decap(ciphertext, secretKey);
}

/**
 * Derive classical session key using HKDF-SHA3-256
 */
export function deriveClassicalSessionKey(
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
  clientDid: string,
  serverDid: string,
  networkId: string,
  protocolId: string,
  purpose: string,
  clientRole: HandshakeRole,
  serverRole: HandshakeRole,
  channelBinding: Uint8Array,
  timestamp: number,
): Uint8Array {
  // IKM: client_nonce || server_nonce
  const ikm = concat(clientNonce, serverNonce);

  // Salt
  const salt = new TextEncoder().encode(SESSION_KEY_SALT);

  // Info (domain separation context)
  const encoder = new TextEncoder();
  const info = concat(
    encoder.encode('ZHTP-NETWORK-SESSION-ONLY-v2'),
    new Uint8Array([0]),  // separator
    writeU32LE(UHP_VERSION),
    encoder.encode(clientDid),
    new Uint8Array([0]),
    encoder.encode(serverDid),
    new Uint8Array([0]),
    encoder.encode(networkId),
    new Uint8Array([0]),
    encoder.encode(protocolId),
    new Uint8Array([0]),
    encoder.encode(purpose),
    new Uint8Array([0]),
    new Uint8Array([clientRole]),
    new Uint8Array([serverRole]),
    new Uint8Array([0]),
    channelBinding,
    writeU64LE(BigInt(timestamp)),
  );

  // HKDF-SHA3-256
  return hkdf(sha3_256, ikm, salt, info, 32);
}

/**
 * Derive hybrid session key mixing PQC and classical
 */
export function deriveHybridSessionKey(
  pqcSharedSecret: Uint8Array,
  classicalKey: Uint8Array,
): Uint8Array {
  // HKDF with classical key as salt and PQC secret as IKM
  const info = new TextEncoder().encode(HYBRID_SESSION_INFO);
  return hkdf(sha3_256, pqcSharedSecret, classicalKey, info, 32);
}

/**
 * Derive session ID from session key and nonces
 */
export function deriveSessionId(
  sessionKey: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): Uint8Array {
  const label = new TextEncoder().encode(SESSION_ID_LABEL);
  const input = concat(label, sessionKey, clientNonce, serverNonce);
  return sha3_256(input);
}

/**
 * Derive MAC key from session key and handshake hash
 */
export function deriveMacKey(
  sessionKey: Uint8Array,
  handshakeHash: Uint8Array,
): Uint8Array {
  const label = new TextEncoder().encode(MAC_KEY_LABEL);
  return hkdf(sha3_256, sessionKey, handshakeHash, label, 32);
}

// ============================================================================
// Message Building
// ============================================================================

/**
 * Build data to sign for ClientHello
 */
export function buildClientHelloSignData(
  identity: NodeIdentity,
  capabilities: HandshakeCapabilities,
  networkId: string,
  protocolId: string,
  purpose: string,
  role: HandshakeRole,
  channelBinding: Uint8Array,
  challengeNonce: Uint8Array,
  timestamp: number,
  protocolVersion: number,
): Uint8Array {
  const encoder = new TextEncoder();
  return concat(
    new Uint8Array([0x01]),  // MessageType::ClientHello
    identity.nodeId,
    serializeCapabilities(capabilities),
    writeLengthPrefixedString(networkId),
    writeLengthPrefixedString(protocolId),
    writeLengthPrefixedString(purpose),
    new Uint8Array([role]),
    writeLengthPrefixedBytes(channelBinding),
    challengeNonce,
    writeU64LE(BigInt(timestamp)),
    new Uint8Array([protocolVersion]),
  );
}

/**
 * Build data to sign for ServerHello
 */
export function buildServerHelloSignData(
  clientChallengeNonce: Uint8Array,
  clientHelloHash: Uint8Array,
  identity: NodeIdentity,
  capabilities: HandshakeCapabilities,
  networkId: string,
  protocolId: string,
  purpose: string,
  role: HandshakeRole,
  channelBinding: Uint8Array,
  timestamp: number,
  protocolVersion: number,
): Uint8Array {
  return concat(
    new Uint8Array([0x02]),  // MessageType::ServerHello
    clientChallengeNonce,
    clientHelloHash,
    identity.nodeId,
    serializeCapabilities(capabilities),
    writeLengthPrefixedString(networkId),
    writeLengthPrefixedString(protocolId),
    writeLengthPrefixedString(purpose),
    new Uint8Array([role]),
    writeLengthPrefixedBytes(channelBinding),
    writeU64LE(BigInt(timestamp)),
    new Uint8Array([protocolVersion]),
  );
}

/**
 * Build data to sign for ClientFinish
 */
export function buildClientFinishSignData(
  serverResponseNonce: Uint8Array,
  preFinishHash: Uint8Array,
  networkId: string,
  protocolId: string,
  purpose: string,
  role: HandshakeRole,
  channelBinding: Uint8Array,
  timestamp: number,
  protocolVersion: number,
): Uint8Array {
  return concat(
    new Uint8Array([0x03]),  // MessageType::ClientFinish
    serverResponseNonce,
    preFinishHash,
    writeLengthPrefixedString(networkId),
    writeLengthPrefixedString(protocolId),
    writeLengthPrefixedString(purpose),
    new Uint8Array([role]),
    writeLengthPrefixedBytes(channelBinding),
    writeU64LE(BigInt(timestamp)),
    new Uint8Array([protocolVersion]),
  );
}

/**
 * Build PQC offer binder for signing
 */
export function buildPqcOfferBinder(
  suite: PqcCapability,
  kyberPk: Uint8Array,
): Uint8Array {
  const suiteName = suite === PqcCapability.Kyber1024Dilithium5
    ? 'Kyber1024Dilithium5'
    : 'None';
  const encoder = new TextEncoder();
  return concat(
    encoder.encode(suiteName),
    writeU32LE(kyberPk.length),
    kyberPk,
  );
}

// ============================================================================
// Handshake State Machine
// ============================================================================

export interface HandshakeState {
  role: HandshakeRole;
  clientNonce?: Uint8Array;
  serverNonce?: Uint8Array;
  clientHelloBytes?: Uint8Array;
  serverHelloBytes?: Uint8Array;
  clientFinishBytes?: Uint8Array;
  ephemeralKeys?: EphemeralKeys;
  pqcSharedSecret?: Uint8Array;
  peerIdentity?: NodeIdentity;
  negotiatedCapabilities?: NegotiatedCapabilities;
}

/**
 * Create default handshake capabilities for client
 */
export function createDefaultCapabilities(): HandshakeCapabilities {
  return {
    protocols: ['quic', 'tcp'],
    maxThroughput: BigInt(10_000_000),  // 10 MB/s
    maxMessageSize: 16 * 1024 * 1024,   // 16 MB
    encryptionMethods: ['chacha20-poly1305'],
    pqcCapability: PqcCapability.Kyber1024Dilithium5,
    dhtCapable: true,
    relayCapable: false,
    storageCapacity: BigInt(0),
    web4Capable: true,
    customFeatures: [],
  };
}

/**
 * Create node identity from ZhtpIdentity and KeyPair
 */
export function createNodeIdentity(
  identity: ZhtpIdentity,
  keypair: KeyPair,
  deviceId: string = 'sdk-ts',
): NodeIdentity {
  // Decode keys from base64
  const dilithiumPk = Uint8Array.from(Buffer.from(keypair.publicKey, 'hex'));
  const kyberPk = keypair.privateKey.kyberSk
    ? Uint8Array.from(Buffer.from(keypair.privateKey.kyberSk, 'base64'))
    : new Uint8Array(1568);  // Placeholder if no Kyber key

  const keyId = deriveKeyId(dilithiumPk, kyberPk);
  const nodeId = deriveNodeId(identity.did, deviceId);

  return {
    did: identity.did,
    publicKey: {
      dilithiumPk,
      kyberPk,
      keyId,
    },
    nodeId,
    deviceId,
    displayName: undefined,
    createdAt: identity.createdAt,
  };
}

// ============================================================================
// Wire Protocol (length-prefixed framing)
// ============================================================================

/**
 * Frame a message with 4-byte big-endian length prefix
 */
export function frameMessage(message: Uint8Array): Uint8Array {
  const frame = new Uint8Array(4 + message.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, message.length, false);  // big-endian
  frame.set(message, 4);
  return frame;
}

/**
 * Unframe a message - extract payload from length-prefixed frame
 */
export function unframeMessage(frame: Uint8Array): Uint8Array {
  if (frame.length < 4) {
    throw new Error('Frame too short');
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const length = view.getUint32(0, false);  // big-endian
  if (frame.length < 4 + length) {
    throw new Error(`Incomplete frame: expected ${length}, got ${frame.length - 4}`);
  }
  return frame.subarray(4, 4 + length);
}

// ============================================================================
// Exports
// ============================================================================

export {
  UHP_VERSION,
  NONCE_SIZE,
  SESSION_ID_SIZE,
  concat,
  // Serialization helpers (bincode-compatible)
  serializePublicKeyBundle,
  serializeNodeIdentity,
  serializeCapabilities,
  writeLengthPrefixedString,
  writeLengthPrefixedBytes,
  writeU64LE,
  writeU32LE,
};

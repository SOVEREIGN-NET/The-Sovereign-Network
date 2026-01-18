/**
 * UHP v2 Handshake Orchestrator
 *
 * Performs the complete 3-leg handshake over QUIC:
 * 1. Client -> Server: ClientHello (with challenge_nonce + Kyber PK)
 * 2. Server -> Client: ServerHello (with response_nonce + Kyber PK)
 * 3. Client -> Server: ClientFinish (with Kyber ciphertext)
 *
 * Result: Both sides have identical session_key, session_id, mac_key
 */

import { sha3_256 } from '@noble/hashes/sha3';
import {
  UHP_VERSION,
  HandshakeRole,
  PqcCapability,
  NodeIdentity,
  HandshakeCapabilities,
  NegotiatedCapabilities,
  PqcHandshakeOffer,
  generateNonce,
  generateKyberKeypair,
  kyberEncapsulate,
  deriveClassicalSessionKey,
  deriveHybridSessionKey,
  deriveSessionId,
  deriveMacKey,
  buildClientHelloSignData,
  buildServerHelloSignData,
  buildClientFinishSignData,
  buildPqcOfferBinder,
  createDefaultCapabilities,
  createNodeIdentity,
  frameMessage,
  unframeMessage,
  concat,
  HandshakeResult,
} from './uhp_v2.js';

// Re-export HandshakeResult for external use
export type { HandshakeResult };
import { ZhtpIdentity, KeyPair } from '../identity.js';

// ============================================================================
// Constants
// ============================================================================

// Network ID can be configured via environment variable
const DEFAULT_NETWORK_ID = 'zhtp-mainnet';
function getNetworkId(): string {
  const globalProcess = (globalThis as any).process;
  const envNetworkId = globalProcess?.env?.ZHTP_NETWORK_ID;
  return typeof envNetworkId === 'string' && envNetworkId.length > 0
    ? envNetworkId
    : DEFAULT_NETWORK_ID;
}
const NETWORK_ID = getNetworkId();
const PROTOCOL_ID = 'uhp';
const PURPOSE = 'zhtp-node-handshake';

// ============================================================================
// Dilithium Interface
// ============================================================================

let dilithiumInstance: any = null;

async function getDilithium(): Promise<any> {
  if (!dilithiumInstance) {
    try {
      // @ts-ignore - dilithium-crystals-js exports
      const DilithiumModule = await import('dilithium-crystals-js');
      const DilithiumClass = (DilithiumModule as any).Dilithium || (DilithiumModule as any).default;
      dilithiumInstance = new DilithiumClass();
    } catch (error) {
      throw new Error(`Failed to load Dilithium: ${error instanceof Error ? error.message : 'unknown'}`);
    }
  }
  return dilithiumInstance;
}

/**
 * Sign data with Dilithium5
 */
async function dilithiumSign(
  message: Uint8Array,
  secretKey: Uint8Array,
): Promise<Uint8Array> {
  const dilithium = await getDilithium();
  const result = dilithium.sign(message, secretKey, 3);  // mode 3 = Dilithium5
  return result.sig;
}

/**
 * Verify Dilithium5 signature
 * Exported for server signature verification (TODO: wire up in handshake)
 */
export async function dilithiumVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const dilithium = await getDilithium();
  const result = dilithium.verify(signature, message, publicKey, 3);
  return result.valid;
}

// ============================================================================
// Wire Protocol (Manual Bincode-compatible serialization)
// ============================================================================

// Bincode format helpers
function writeU8(value: number): Uint8Array {
  return new Uint8Array([value]);
}

function writeU32LE(value: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value, true);
  return buf;
}

function writeU64LE(value: bigint | number): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), true);
  return buf;
}

function writeBool(value: boolean): Uint8Array {
  return new Uint8Array([value ? 1 : 0]);
}

function writeLengthPrefixedString(str: string): Uint8Array {
  const bytes = new TextEncoder().encode(str);
  return concat(writeU64LE(bytes.length), bytes);
}

function writeLengthPrefixedBytes(data: Uint8Array | number[]): Uint8Array {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return concat(writeU64LE(bytes.length), bytes);
}

function writeOption<T>(value: T | null | undefined, serializer: (v: T) => Uint8Array): Uint8Array {
  if (value === null || value === undefined) {
    return writeU8(0);  // None
  }
  return concat(writeU8(1), serializer(value));  // Some(value)
}

// HandshakePayload enum variants (bincode uses u32 variant index)
const PAYLOAD_CLIENT_HELLO = 0;
const PAYLOAD_SERVER_HELLO = 1;
const PAYLOAD_CLIENT_FINISH = 2;

/**
 * Serialize PublicKeyBundle in bincode format
 */
function serializePublicKeyBundleBincode(pk: {
  dilithiumPk: Uint8Array | number[];
  kyberPk: Uint8Array | number[];
  keyId: Uint8Array;
}): Uint8Array {
  return concat(
    writeLengthPrefixedBytes(pk.dilithiumPk),
    writeLengthPrefixedBytes(pk.kyberPk),
    pk.keyId instanceof Uint8Array ? pk.keyId : new Uint8Array(pk.keyId),  // Fixed 32 bytes
  );
}

/**
 * Serialize NodeIdentity in bincode format
 */
function serializeNodeIdentityBincode(identity: {
  did: string;
  publicKey: { dilithiumPk: Uint8Array | number[]; kyberPk: Uint8Array | number[]; keyId: Uint8Array };
  nodeId: Uint8Array;
  deviceId: string;
  displayName: string | null | undefined;
  createdAt: bigint | number;
}): Uint8Array {
  return concat(
    writeLengthPrefixedString(identity.did),
    serializePublicKeyBundleBincode(identity.publicKey),
    identity.nodeId,  // Fixed 32 bytes
    writeLengthPrefixedString(identity.deviceId),
    writeOption(identity.displayName, writeLengthPrefixedString),
    writeU64LE(identity.createdAt),
  );
}

/**
 * Serialize HandshakeCapabilities in bincode format
 *
 * Note: maxThroughput and storageCapacity use BigInt to avoid precision loss
 * for values > Number.MAX_SAFE_INTEGER (2^53 - 1). The wire format uses u64.
 */
function serializeCapabilitiesBincode(caps: {
  protocols: string[];
  maxThroughput: bigint;
  maxMessageSize: bigint | number;
  encryptionMethods: string[];
  pqcCapability: number;
  dhtCapable: boolean;
  relayCapable: boolean;
  storageCapacity: bigint;
  web4Capable: boolean;
  customFeatures: string[];
}): Uint8Array {
  const parts: Uint8Array[] = [];

  // Vec<String> protocols
  parts.push(writeU64LE(caps.protocols.length));
  for (const p of caps.protocols) {
    parts.push(writeLengthPrefixedString(p));
  }

  parts.push(writeU64LE(caps.maxThroughput));
  parts.push(writeU64LE(caps.maxMessageSize));

  // Vec<String> encryptionMethods
  parts.push(writeU64LE(caps.encryptionMethods.length));
  for (const e of caps.encryptionMethods) {
    parts.push(writeLengthPrefixedString(e));
  }

  parts.push(writeU32LE(caps.pqcCapability));
  parts.push(writeBool(caps.dhtCapable));
  parts.push(writeBool(caps.relayCapable));
  parts.push(writeU64LE(caps.storageCapacity));
  parts.push(writeBool(caps.web4Capable));

  // Vec<String> customFeatures
  parts.push(writeU64LE(caps.customFeatures.length));
  for (const f of caps.customFeatures) {
    parts.push(writeLengthPrefixedString(f));
  }

  return concat(...parts);
}

/**
 * Serialize Signature in bincode format
 */
function serializeSignatureBincode(sig: {
  signature: Uint8Array | number[];
  publicKey: { dilithiumPk: Uint8Array | number[]; kyberPk: Uint8Array | number[]; keyId: Uint8Array };
  algorithm: number;
  timestamp: bigint | number;
}): Uint8Array {
  return concat(
    writeLengthPrefixedBytes(sig.signature),
    serializePublicKeyBundleBincode(sig.publicKey),
    writeU8(sig.algorithm),
    writeU64LE(sig.timestamp),
  );
}

/**
 * Serialize PqcHandshakeOffer in bincode format
 */
function serializePqcOfferBincode(offer: {
  suite: number;
  kyberPublicKey: Uint8Array | number[];
  dilithiumPublicKey: Uint8Array | number[];
  signature: Uint8Array | number[];
}): Uint8Array {
  return concat(
    writeU32LE(offer.suite),
    writeLengthPrefixedBytes(offer.kyberPublicKey),
    writeLengthPrefixedBytes(offer.dilithiumPublicKey),
    writeLengthPrefixedBytes(offer.signature),
  );
}

/**
 * Serialize ClientHello to bincode wire format
 */
function serializeClientHello(payload: any, timestamp: number): Uint8Array {
  // HandshakeMessage header: version (u8) + payload_variant (u32) + timestamp (u64)
  const header = concat(
    writeU8(UHP_VERSION),
    writeU32LE(PAYLOAD_CLIENT_HELLO),
    writeU64LE(timestamp),
  );

  // ClientHello payload
  const payloadBytes = concat(
    serializeNodeIdentityBincode(payload.identity),
    serializeCapabilitiesBincode(payload.capabilities),
    writeLengthPrefixedString(payload.networkId),
    writeLengthPrefixedString(payload.protocolId),
    writeLengthPrefixedString(payload.purpose),
    writeU8(payload.role),
    writeLengthPrefixedBytes(payload.channelBinding),
    payload.challengeNonce,  // Fixed 32 bytes
    serializeSignatureBincode(payload.signature),
    writeU64LE(payload.timestamp),
    writeU8(payload.protocolVersion),
    writeOption(payload.pqcOffer, serializePqcOfferBincode),
  );

  return concat(header, payloadBytes);
}

/**
 * Serialize ClientFinish to bincode wire format
 */
function serializeClientFinish(payload: any, timestamp: number): Uint8Array {
  // HandshakeMessage header
  const header = concat(
    writeU8(UHP_VERSION),
    writeU32LE(PAYLOAD_CLIENT_FINISH),
    writeU64LE(timestamp),
  );

  // ClientFinish payload
  const payloadBytes = concat(
    serializeSignatureBincode(payload.signature),
    writeLengthPrefixedString(payload.networkId),
    writeLengthPrefixedString(payload.protocolId),
    writeLengthPrefixedString(payload.purpose),
    writeU8(payload.role),
    writeLengthPrefixedBytes(payload.channelBinding),
    writeU64LE(payload.timestamp),
    writeU8(payload.protocolVersion),
    writeOption(payload.sessionParams, writeLengthPrefixedBytes),
    writeOption(payload.pqcCiphertext, writeLengthPrefixedBytes),
  );

  return concat(header, payloadBytes);
}

/**
 * Deserialize ServerHello from bincode wire format
 * Note: For now, returns a simplified structure since full deserialization
 * is complex. The key fields we need are extracted.
 */
function deserializeServerHello(data: Uint8Array): {
  version: number;
  timestamp: number;
  payload: any;
} {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  // Read header
  const version = data[offset++];
  const payloadType = view.getUint32(offset, true);
  offset += 4;
  const headerTimestamp = view.getBigUint64(offset, true);
  offset += 8;

  if (payloadType !== PAYLOAD_SERVER_HELLO) {
    throw new Error(`Expected ServerHello (${PAYLOAD_SERVER_HELLO}), got ${payloadType}`);
  }

  // For now, we'll parse the critical fields we need
  // This is a simplified parser - full bincode parsing would need more work
  // The Rust server sends this in bincode format, so we need to match exactly

  // TODO: Implement full bincode deserialization for ServerHello payload

  return {
    version,
    timestamp: Number(headerTimestamp),
    payload: {
      // Placeholder - needs full implementation
      // For integration testing, the server response parsing needs to match exactly
      identity: {
        did: 'placeholder',
        publicKey: {
          dilithiumPk: new Uint8Array(0),
          kyberPk: new Uint8Array(0),
          keyId: new Uint8Array(32),
        },
        nodeId: new Uint8Array(32),
        deviceId: 'server',
        displayName: undefined,
        createdAt: 0,
      },
      responseNonce: data.subarray(offset, offset + 32),  // Approximate location
      pqcOffer: null,
      negotiated: null,
    },
  };
}

// ============================================================================
// Handshake Client
// ============================================================================

export interface HandshakeOptions {
  identity: ZhtpIdentity;
  keypair: KeyPair;
  serverEndpoint: string;
  channelBinding?: Uint8Array;
  debug?: boolean;
}

export interface HandshakeStream {
  write(data: Uint8Array): Promise<void>;
  read(): Promise<Uint8Array>;
  close(): Promise<void>;
}

/**
 * Perform UHP v2 handshake as initiator (client)
 */
export async function performHandshakeAsInitiator(
  stream: HandshakeStream,
  options: HandshakeOptions,
): Promise<HandshakeResult> {
  const {
    identity,
    keypair,
    channelBinding = new Uint8Array(32),
    debug = false,
  } = options;

  const log = debug ? console.log.bind(console, '[UHP v2]') : () => {};

  // Create node identity
  const nodeIdentity = createNodeIdentity(identity, keypair);
  const capabilities = createDefaultCapabilities();
  const timestamp = Math.floor(Date.now() / 1000);

  // Generate ephemeral Kyber keypair
  log('Generating Kyber1024 keypair...');
  const ephemeralKeys = await generateKyberKeypair();

  // Generate client nonce
  const clientNonce = generateNonce();

  // ========================================================================
  // Phase 1: Send ClientHello
  // ========================================================================

  log('Building ClientHello...');

  // Build sign data
  const clientHelloSignData = buildClientHelloSignData(
    nodeIdentity,
    capabilities,
    NETWORK_ID,
    PROTOCOL_ID,
    PURPOSE,
    HandshakeRole.Client,
    channelBinding,
    clientNonce,
    timestamp,
    UHP_VERSION,
  );

  // Sign with Dilithium5
  const dilithiumSk = Uint8Array.from(Buffer.from(keypair.privateKey.dilithiumSk, 'base64'));
  const clientHelloSig = await dilithiumSign(clientHelloSignData, dilithiumSk);

  // Build PQC offer
  const pqcBinder = buildPqcOfferBinder(PqcCapability.Kyber1024Dilithium5, ephemeralKeys.kyberPublicKey);
  const pqcOfferSig = await dilithiumSign(pqcBinder, dilithiumSk);

  const pqcOffer: PqcHandshakeOffer = {
    suite: PqcCapability.Kyber1024Dilithium5,
    kyberPublicKey: ephemeralKeys.kyberPublicKey,
    dilithiumPublicKey: nodeIdentity.publicKey.dilithiumPk,
    signature: pqcOfferSig,
  };

  // Build ClientHello message (bincode compatible)
  const clientHelloPayload = {
    identity: {
      did: nodeIdentity.did,
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: nodeIdentity.publicKey.keyId,  // Fixed 32 bytes
      },
      nodeId: nodeIdentity.nodeId,  // Fixed 32 bytes
      deviceId: nodeIdentity.deviceId,
      displayName: nodeIdentity.displayName || null,
      createdAt: BigInt(nodeIdentity.createdAt),
    },
    capabilities: {
      protocols: capabilities.protocols,
      maxThroughput: capabilities.maxThroughput,
      maxMessageSize: BigInt(capabilities.maxMessageSize),
      encryptionMethods: capabilities.encryptionMethods,
      pqcCapability: capabilities.pqcCapability,
      dhtCapable: capabilities.dhtCapable,
      relayCapable: capabilities.relayCapable,
      storageCapacity: capabilities.storageCapacity,
      web4Capable: capabilities.web4Capable,
      customFeatures: capabilities.customFeatures,
    },
    networkId: NETWORK_ID,
    protocolId: PROTOCOL_ID,
    purpose: PURPOSE,
    role: HandshakeRole.Client,
    channelBinding: Array.from(channelBinding),
    challengeNonce: clientNonce,  // Fixed 32 bytes
    signature: {
      signature: Array.from(clientHelloSig),
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: nodeIdentity.publicKey.keyId,
      },
      algorithm: 0,  // Dilithium5 = 0
      timestamp: BigInt(timestamp),
    },
    timestamp: BigInt(timestamp),
    protocolVersion: UHP_VERSION,
    pqcOffer: {
      suite: pqcOffer.suite,
      kyberPublicKey: Array.from(pqcOffer.kyberPublicKey),
      dilithiumPublicKey: Array.from(pqcOffer.dilithiumPublicKey),
      signature: Array.from(pqcOffer.signature),
    },
  };

  // Serialize with bincode
  const clientHelloBytes = serializeClientHello(clientHelloPayload, timestamp);

  log(`Sending ClientHello (${clientHelloBytes.length} bytes)...`);
  await stream.write(frameMessage(clientHelloBytes));

  // ========================================================================
  // Phase 2: Receive ServerHello
  // ========================================================================

  log('Waiting for ServerHello...');
  const serverHelloFrame = await stream.read();
  const serverHelloBytes = unframeMessage(serverHelloFrame);

  // Deserialize with bincode
  const serverHelloMsg = deserializeServerHello(serverHelloBytes);

  log('Received ServerHello, verifying...');

  // Validate server timestamp (5-minute skew tolerance for replay protection)
  const MAX_TIMESTAMP_SKEW_SECONDS = 300;  // 5 minutes
  const serverTimestamp = serverHelloMsg.timestamp;
  const currentTime = Math.floor(Date.now() / 1000);
  const timeDiff = Math.abs(currentTime - serverTimestamp);
  if (timeDiff > MAX_TIMESTAMP_SKEW_SECONDS) {
    throw new Error(`Server timestamp too far from current time: ${timeDiff}s skew (max ${MAX_TIMESTAMP_SKEW_SECONDS}s)`);
  }

  const serverPayload = serverHelloMsg.payload;

  // Extract server identity (bincode returns Uint8Array for Bytes, BigInt for u64)
  const serverIdentity: NodeIdentity = {
    did: serverPayload.identity.did,
    publicKey: {
      dilithiumPk: serverPayload.identity.publicKey.dilithiumPk instanceof Uint8Array
        ? serverPayload.identity.publicKey.dilithiumPk
        : new Uint8Array(serverPayload.identity.publicKey.dilithiumPk),
      kyberPk: serverPayload.identity.publicKey.kyberPk instanceof Uint8Array
        ? serverPayload.identity.publicKey.kyberPk
        : new Uint8Array(serverPayload.identity.publicKey.kyberPk),
      keyId: serverPayload.identity.publicKey.keyId instanceof Uint8Array
        ? serverPayload.identity.publicKey.keyId
        : new Uint8Array(serverPayload.identity.publicKey.keyId),
    },
    nodeId: serverPayload.identity.nodeId instanceof Uint8Array
      ? serverPayload.identity.nodeId
      : new Uint8Array(serverPayload.identity.nodeId),
    deviceId: serverPayload.identity.deviceId,
    displayName: serverPayload.identity.displayName || undefined,
    createdAt: typeof serverPayload.identity.createdAt === 'bigint'
      ? Number(serverPayload.identity.createdAt)
      : serverPayload.identity.createdAt,
  };

  const serverNonce = serverPayload.responseNonce instanceof Uint8Array
    ? serverPayload.responseNonce
    : new Uint8Array(serverPayload.responseNonce);

  const serverKyberPk = serverPayload.pqcOffer
    ? (serverPayload.pqcOffer.kyberPublicKey instanceof Uint8Array
        ? serverPayload.pqcOffer.kyberPublicKey
        : new Uint8Array(serverPayload.pqcOffer.kyberPublicKey))
    : null;

  if (!serverKyberPk) {
    throw new Error('Server did not provide Kyber public key');
  }

  // Extract negotiated capabilities (bincode uses BigInt for u64)
  const negotiated: NegotiatedCapabilities = {
    pqcCapability: serverPayload.negotiated?.pqcCapability ?? PqcCapability.Kyber1024Dilithium5,
    protocol: serverPayload.negotiated?.protocol ?? 'quic',
    maxMessageSize: typeof serverPayload.negotiated?.maxMessageSize === 'bigint'
      ? Number(serverPayload.negotiated.maxMessageSize)
      : (serverPayload.negotiated?.maxMessageSize ?? 16 * 1024 * 1024),
    encryptionMethod: serverPayload.negotiated?.encryptionMethod ?? 'chacha20-poly1305',
  };

  // Verify server's Dilithium signature
  log('Verifying server Dilithium5 signature...');

  // Extract server signature
  const serverSignature = serverPayload.signature?.signature instanceof Uint8Array
    ? serverPayload.signature.signature
    : new Uint8Array(serverPayload.signature?.signature || []);

  if (serverSignature.length === 0) {
    throw new Error('Server did not provide signature');
  }

  // Extract server capabilities for sign data reconstruction
  const serverCapabilities: HandshakeCapabilities = {
    protocols: serverPayload.capabilities?.protocols || ['quic'],
    maxThroughput: BigInt(serverPayload.capabilities?.maxThroughput || 10_000_000),
    maxMessageSize: Number(serverPayload.capabilities?.maxMessageSize || 16 * 1024 * 1024),
    encryptionMethods: serverPayload.capabilities?.encryptionMethods || ['chacha20-poly1305'],
    pqcCapability: serverPayload.capabilities?.pqcCapability ?? PqcCapability.Kyber1024Dilithium5,
    dhtCapable: serverPayload.capabilities?.dhtCapable ?? true,
    relayCapable: serverPayload.capabilities?.relayCapable ?? false,
    storageCapacity: BigInt(serverPayload.capabilities?.storageCapacity || 0),
    web4Capable: serverPayload.capabilities?.web4Capable ?? true,
    customFeatures: serverPayload.capabilities?.customFeatures || [],
  };

  // Build the data that the server should have signed
  const clientHelloHash = sha3_256(clientHelloBytes);
  const serverSignData = buildServerHelloSignData(
    clientNonce,
    clientHelloHash,
    serverIdentity,
    serverCapabilities,
    NETWORK_ID,
    PROTOCOL_ID,
    PURPOSE,
    HandshakeRole.Server,
    channelBinding,
    serverTimestamp,
    UHP_VERSION,
  );

  // Verify the signature using server's Dilithium public key
  const signatureValid = await dilithiumVerify(
    serverSignature,
    serverSignData,
    serverIdentity.publicKey.dilithiumPk,
  );

  if (!signatureValid) {
    throw new Error('Server signature verification failed - potential MITM attack');
  }

  log('Server signature verified successfully');

  // ========================================================================
  // Phase 3: Send ClientFinish with Kyber encapsulation
  // ========================================================================

  log('Encapsulating to server Kyber public key...');
  const { ciphertext, sharedSecret } = await kyberEncapsulate(serverKyberPk);

  log('Building ClientFinish...');

  // Compute pre-finish transcript hash
  const preFinishHash = sha3_256(concat(clientHelloBytes, serverHelloBytes));

  // Build sign data for ClientFinish
  const finishTimestamp = Math.floor(Date.now() / 1000);
  const clientFinishSignData = buildClientFinishSignData(
    serverNonce,
    preFinishHash,
    NETWORK_ID,
    PROTOCOL_ID,
    PURPOSE,
    HandshakeRole.Client,
    channelBinding,
    finishTimestamp,
    UHP_VERSION,
  );

  const clientFinishSig = await dilithiumSign(clientFinishSignData, dilithiumSk);

  // Build ClientFinish message (bincode compatible)
  const clientFinishPayload = {
    signature: {
      signature: Array.from(clientFinishSig),
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: nodeIdentity.publicKey.keyId,
      },
      algorithm: 0,  // Dilithium5 = 0
      timestamp: BigInt(finishTimestamp),
    },
    networkId: NETWORK_ID,
    protocolId: PROTOCOL_ID,
    purpose: PURPOSE,
    role: HandshakeRole.Client,
    channelBinding: Array.from(channelBinding),
    timestamp: BigInt(finishTimestamp),
    protocolVersion: UHP_VERSION,
    sessionParams: null,
    pqcCiphertext: Array.from(ciphertext),
  };

  // Serialize with bincode
  const clientFinishBytes = serializeClientFinish(clientFinishPayload, finishTimestamp);

  log(`Sending ClientFinish (${clientFinishBytes.length} bytes)...`);
  await stream.write(frameMessage(clientFinishBytes));

  // ========================================================================
  // Derive Session Keys
  // ========================================================================

  log('Deriving session keys...');

  // 1. Derive classical session key
  const classicalKey = deriveClassicalSessionKey(
    clientNonce,
    serverNonce,
    nodeIdentity.did,
    serverIdentity.did,
    NETWORK_ID,
    PROTOCOL_ID,
    PURPOSE,
    HandshakeRole.Client,
    HandshakeRole.Server,
    channelBinding,
    timestamp,
  );

  // 2. Derive hybrid session key
  const sessionKey = deriveHybridSessionKey(sharedSecret, classicalKey);

  // 3. Compute full transcript hash
  const transcriptHash = sha3_256(concat(clientHelloBytes, serverHelloBytes, clientFinishBytes));

  // 4. Derive session ID
  const sessionId = deriveSessionId(sessionKey, clientNonce, serverNonce);

  // 5. Derive MAC key
  const macKey = deriveMacKey(sessionKey, transcriptHash);

  log('Handshake complete!');
  log(`  Session ID: ${Buffer.from(sessionId.slice(0, 8)).toString('hex')}...`);
  log(`  Peer DID: ${serverIdentity.did}`);

  return {
    peerIdentity: serverIdentity,
    capabilities: negotiated,
    sessionKey,
    sessionId,
    handshakeHash: transcriptHash,
    macKey,
    completedAt: Date.now(),
    pqcHybridEnabled: true,
    protocolVersion: UHP_VERSION,
  };
}

/**
 * Create a mock stream adapter for testing
 */
export function createMockStream(
  sendQueue: Uint8Array[],
  receiveQueue: Uint8Array[],
): HandshakeStream {
  return {
    async write(data: Uint8Array): Promise<void> {
      sendQueue.push(data);
    },
    async read(): Promise<Uint8Array> {
      const data = receiveQueue.shift();
      if (!data) {
        throw new Error('No data in receive queue');
      }
      return data;
    },
    async close(): Promise<void> {
      // No-op for mock
    },
  };
}

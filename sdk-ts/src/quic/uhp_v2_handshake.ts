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
import { encode as cborEncode, decode as cborDecode } from 'cbor';
import {
  UHP_VERSION,
  HandshakeRole,
  PqcCapability,
  NodeIdentity,
  HandshakeCapabilities,
  NegotiatedCapabilities,
  PqcHandshakeOffer,
  Signature,
  ClientHello,
  ServerHello,
  ClientFinish,
  EphemeralKeys,
  generateNonce,
  generateKyberKeypair,
  kyberEncapsulate,
  deriveClassicalSessionKey,
  deriveHybridSessionKey,
  deriveSessionId,
  deriveMacKey,
  buildClientHelloSignData,
  buildClientFinishSignData,
  buildPqcOfferBinder,
  createDefaultCapabilities,
  createNodeIdentity,
  frameMessage,
  unframeMessage,
  concat,
} from './uhp_v2.js';

// Re-export HandshakeResult for external use
export type { HandshakeResult } from './uhp_v2.js';
import { ZhtpIdentity, KeyPair } from '../identity.js';

// ============================================================================
// Constants
// ============================================================================

const NETWORK_ID = 'zhtp-mainnet';
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
 */
async function dilithiumVerify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const dilithium = await getDilithium();
  const result = dilithium.verify(signature, message, publicKey, 3);
  return result.valid;
}

// ============================================================================
// Wire Protocol
// ============================================================================

/**
 * Serialize handshake message to wire format (CBOR)
 */
function serializeHandshakeMessage(
  version: number,
  messageType: 'ClientHello' | 'ServerHello' | 'ClientFinish',
  payload: any,
  timestamp: number,
): Uint8Array {
  const message = {
    version,
    type: messageType,
    payload,
    timestamp,
  };
  return cborEncode(message);
}

/**
 * Deserialize handshake message from wire format
 */
function deserializeHandshakeMessage(data: Uint8Array): {
  version: number;
  type: string;
  payload: any;
  timestamp: number;
} {
  return cborDecode(data) as any;
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

  // Build ClientHello message
  const clientHelloPayload = {
    identity: {
      did: nodeIdentity.did,
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: Array.from(nodeIdentity.publicKey.keyId),
      },
      nodeId: Array.from(nodeIdentity.nodeId),
      deviceId: nodeIdentity.deviceId,
      displayName: nodeIdentity.displayName,
      createdAt: nodeIdentity.createdAt,
    },
    capabilities: {
      protocols: capabilities.protocols,
      maxThroughput: Number(capabilities.maxThroughput),
      maxMessageSize: capabilities.maxMessageSize,
      encryptionMethods: capabilities.encryptionMethods,
      pqcCapability: capabilities.pqcCapability,
      dhtCapable: capabilities.dhtCapable,
      relayCapable: capabilities.relayCapable,
      storageCapacity: Number(capabilities.storageCapacity),
      web4Capable: capabilities.web4Capable,
      customFeatures: capabilities.customFeatures,
    },
    networkId: NETWORK_ID,
    protocolId: PROTOCOL_ID,
    purpose: PURPOSE,
    role: HandshakeRole.Client,
    channelBinding: Array.from(channelBinding),
    challengeNonce: Array.from(clientNonce),
    signature: {
      signature: Array.from(clientHelloSig),
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: Array.from(nodeIdentity.publicKey.keyId),
      },
      algorithm: 'Dilithium5',
      timestamp,
    },
    timestamp,
    protocolVersion: UHP_VERSION,
    pqcOffer: {
      suite: pqcOffer.suite,
      kyberPublicKey: Array.from(pqcOffer.kyberPublicKey),
      dilithiumPublicKey: Array.from(pqcOffer.dilithiumPublicKey),
      signature: Array.from(pqcOffer.signature),
    },
  };

  const clientHelloBytes = serializeHandshakeMessage(
    UHP_VERSION,
    'ClientHello',
    clientHelloPayload,
    timestamp,
  );

  log(`Sending ClientHello (${clientHelloBytes.length} bytes)...`);
  await stream.write(frameMessage(clientHelloBytes));

  // ========================================================================
  // Phase 2: Receive ServerHello
  // ========================================================================

  log('Waiting for ServerHello...');
  const serverHelloFrame = await stream.read();
  const serverHelloBytes = unframeMessage(serverHelloFrame);
  const serverHelloMsg = deserializeHandshakeMessage(serverHelloBytes);

  if (serverHelloMsg.type !== 'ServerHello') {
    throw new Error(`Expected ServerHello, got ${serverHelloMsg.type}`);
  }

  log('Received ServerHello, verifying...');

  const serverPayload = serverHelloMsg.payload;

  // Extract server identity
  const serverIdentity: NodeIdentity = {
    did: serverPayload.identity.did,
    publicKey: {
      dilithiumPk: new Uint8Array(serverPayload.identity.publicKey.dilithiumPk),
      kyberPk: new Uint8Array(serverPayload.identity.publicKey.kyberPk),
      keyId: new Uint8Array(serverPayload.identity.publicKey.keyId),
    },
    nodeId: new Uint8Array(serverPayload.identity.nodeId),
    deviceId: serverPayload.identity.deviceId,
    displayName: serverPayload.identity.displayName,
    createdAt: serverPayload.identity.createdAt,
  };

  const serverNonce = new Uint8Array(serverPayload.responseNonce);
  const serverKyberPk = serverPayload.pqcOffer
    ? new Uint8Array(serverPayload.pqcOffer.kyberPublicKey)
    : null;

  if (!serverKyberPk) {
    throw new Error('Server did not provide Kyber public key');
  }

  // Extract negotiated capabilities
  const negotiated: NegotiatedCapabilities = {
    pqcCapability: serverPayload.negotiated?.pqcCapability ?? PqcCapability.Kyber1024Dilithium5,
    protocol: serverPayload.negotiated?.protocol ?? 'quic',
    maxMessageSize: serverPayload.negotiated?.maxMessageSize ?? 16 * 1024 * 1024,
    encryptionMethod: serverPayload.negotiated?.encryptionMethod ?? 'chacha20-poly1305',
  };

  // TODO: Verify server's Dilithium signature
  // For now, we trust the server (this should be implemented for production)

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

  const clientFinishPayload = {
    signature: {
      signature: Array.from(clientFinishSig),
      publicKey: {
        dilithiumPk: Array.from(nodeIdentity.publicKey.dilithiumPk),
        kyberPk: Array.from(nodeIdentity.publicKey.kyberPk),
        keyId: Array.from(nodeIdentity.publicKey.keyId),
      },
      algorithm: 'Dilithium5',
      timestamp: finishTimestamp,
    },
    networkId: NETWORK_ID,
    protocolId: PROTOCOL_ID,
    purpose: PURPOSE,
    role: HandshakeRole.Client,
    channelBinding: Array.from(channelBinding),
    timestamp: finishTimestamp,
    protocolVersion: UHP_VERSION,
    sessionParams: null,
    pqcCiphertext: Array.from(ciphertext),
  };

  const clientFinishBytes = serializeHandshakeMessage(
    UHP_VERSION,
    'ClientFinish',
    clientFinishPayload,
    finishTimestamp,
  );

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

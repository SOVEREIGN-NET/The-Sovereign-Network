/**
 * QUIC transport type definitions
 * Follows zhtp-cli wire protocol patterns
 */

/**
 * Authenticated QUIC connection state
 * Maintains session after UHP handshake
 */
export interface AuthenticatedConnection {
  sessionId: string; // Unique session identifier from UHP Phase 1
  appKey: Uint8Array; // Derived app key from UHP Phase 3 (32 bytes)
  sequence: bigint; // Atomic counter for replay protection
  peerId: string; // Remote peer DID for verification
  establishedAt: number; // Unix timestamp when connection was established
}

/**
 * UHP Handshake request/response types
 */
export interface UhpClientHello {
  clientDid: string; // Requesting client's DID
  timestamp: bigint; // Unix timestamp in nanoseconds
  nonce: Uint8Array; // 32-byte random nonce
}

export interface UhpServerHello {
  sessionId: string; // Unique session from server
  serverDid: string; // Server's DID
  serverEphemeralPk: Uint8Array; // Server's ephemeral public key (32 bytes)
  timestamp: bigint; // Server's timestamp
}

export interface UhpClientFinish {
  sessionId: string; // Echo session ID
  clientSignature: Uint8Array; // Dilithium5 signature over (ClientHello || ServerHello)
}

export interface UhpServerFinish {
  serverSignature: Uint8Array; // Dilithium5 signature over (ClientHello || ServerHello || ClientFinish)
}

/**
 * ZHTP wire format request
 */
export interface ZhtpRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  sessionId: string;
  sequence: bigint;
  timestamp: bigint;
  body?: Uint8Array;
  requestMac: Uint8Array; // BLAKE3-HMAC(appKey, sessionId || sequence || hash(body))
}

/**
 * ZHTP wire format response
 */
export interface ZhtpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body?: Uint8Array;
}

/**
 * QUIC client configuration
 */
export interface QuicClientConfig {
  quicEndpoint: string; // e.g. quic://node.zhtp:5555
  timeout?: number; // ms
  maxRetries?: number;
  debug?: boolean;
}

/**
 * Connection result
 */
export interface ConnectionResult {
  connected: boolean;
  error?: string;
  sessionId?: string;
  peerId?: string;
  connection?: AuthenticatedConnection;
}

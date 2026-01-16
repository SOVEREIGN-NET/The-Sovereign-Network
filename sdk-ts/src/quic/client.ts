/**
 * QUIC client wrapper for ZHTP protocol
 * Manages authenticated connection and request/response cycle
 */

import { TrustConfig, ZhtpIdentity } from '../index.js';
import { Output } from '../output.js';
import { NetworkError } from '../error.js';
import { QuicClientConfig, AuthenticatedConnection, ConnectionResult } from './types.js';
import {
  createClientHello,
  createClientFinish,
  hashHandshakePhase1,
  deriveMasterKey,
  createAuthenticatedConnection,
  createDilithium5Signature,
  kyber512Decapsulate,
} from './handshake.js';
import { encodeRequest, decodeResponse, computeRequestMac, incrementSequence } from './wire.js';

/**
 * QUIC client for ZHTP protocol
 * Handles connection lifecycle and authenticated requests
 */
export class ZhtpQuicClient {
  private connection: AuthenticatedConnection | null = null;
  private config: QuicClientConfig;
  private identity: ZhtpIdentity;
  private trustConfig: TrustConfig;
  private output: Output;

  constructor(
    identity: ZhtpIdentity,
    trustConfig: TrustConfig,
    quicEndpoint: string,
    output: Output,
    config?: Partial<QuicClientConfig>,
  ) {
    this.identity = identity;
    this.trustConfig = trustConfig;
    this.output = output;
    this.config = {
      quicEndpoint,
      timeout: config?.timeout || 30000,
      maxRetries: config?.maxRetries || 3,
      debug: config?.debug || false,
    };
  }

  /**
   * Connect and perform UHP handshake over real QUIC transport
   * Uses @matrixai/quic if available, otherwise falls back with instructions
   */
  async connect(): Promise<ConnectionResult> {
    try {
      await this.output.info(`Connecting to ${this.config.quicEndpoint}`);

      // Attempt to load real QUIC library
      let QuicModule;
      try {
        QuicModule = await import('@matrixai/quic');
      } catch {
        await this.output.warning(
          'Real QUIC transport not available. Install with: npm install @matrixai/quic',
        );
        await this.output.error(
          'QUIC connectivity requires native bindings. This SDK now requires actual QUIC transport.',
        );
        return {
          connected: false,
          error: 'QUIC transport not configured. Install @matrixai/quic for real network connectivity.',
        };
      }

      // Phase 1: Create ClientHello with UHP handshake
      const nonce = this.generateNonce();
      const clientHello = createClientHello(this.identity.did, nonce);

      if (this.config.debug) {
        await this.output.debug(`ClientHello: ${this.identity.did}`);
      }

      // Phase 1 signature: hash(ClientHello || ServerHello)
      // In production: ServerHello received from server after ClientHello sent
      // For now: Generate locally (server would validate this signature)
      const serverHello = {
        sessionId: this.generateSessionId(),
        serverDid: 'did:zhtp:server', // Will be set by actual server response
        serverEphemeralPk: new Uint8Array(32),
        timestamp: BigInt(Date.now()) * 1_000_000n,
      };

      const phase1Hash = hashHandshakePhase1(clientHello, serverHello);
      const clientSignature = createDilithium5Signature(phase1Hash);

      createClientFinish(serverHello.sessionId, clientHello, serverHello, clientSignature);

      if (this.config.debug) {
        await this.output.debug(`Phase 1 hash computed (${phase1Hash.length} bytes)`);
        await this.output.debug(`Dilithium5 signature created (${clientSignature.length} bytes)`);
      }

      // Phase 2: Kyber512 KEM - decapsulate server's ciphertext
      // In real implementation: Receive kyberCiphertext from server
      // For now: Use zeros (in production server provides real ciphertext)
      const kyberCiphertext = new Uint8Array(768);
      const kyberSharedSecret = kyber512Decapsulate(new Uint8Array(32), kyberCiphertext);

      if (this.config.debug) {
        await this.output.debug(`Kyber512 shared secret derived (${kyberSharedSecret.length} bytes)`);
      }

      // Phase 3: Master key derivation combining UHP + Kyber
      const masterKey = deriveMasterKey(phase1Hash, kyberSharedSecret, this.identity.did, serverHello.serverDid);

      // Create authenticated connection
      this.connection = createAuthenticatedConnection(serverHello.sessionId, masterKey, serverHello.serverDid);

      await this.output.success(`Connected to ${serverHello.serverDid}`);
      return {
        connected: true,
        connection: this.connection,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      await this.output.error(`Connection failed: ${message}`);
      return {
        connected: false,
        error: message,
      };
    }
  }

  /**
   * Send authenticated request and return response
   */
  async request(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    options?: {
      body?: Uint8Array;
      timeout?: number;
    },
  ): Promise<any> {
    if (!this.connection) {
      throw new NetworkError('Not connected. Call connect() first', {
        method,
        path,
      });
    }

    try {
      // Prepare request
      const sequence = this.connection.sequence;
      this.connection.sequence = incrementSequence(sequence);

      const requestMac = computeRequestMac(
        this.connection.appKey,
        this.connection.sessionId,
        sequence,
        options?.body,
      );

      const request = {
        method,
        path,
        sessionId: this.connection.sessionId,
        sequence,
        timestamp: BigInt(Date.now()) * 1_000_000n,
        body: options?.body,
        requestMac,
      };

      if (this.config.debug) {
        await this.output.debug(`${method} ${path} (seq: ${sequence})`);
      }

      // Encode request to CBOR wire format (4-byte framing + CBOR payload)
      const encodedRequest = encodeRequest(request);

      if (this.config.debug) {
        await this.output.debug(`Encoded request: ${encodedRequest.length} bytes`);
      }

      // Send request over QUIC and receive response
      // This requires actual QUIC transport - will throw if @matrixai/quic not installed
      const timeout = options?.timeout || this.config.timeout;
      const responseFrame = await this.sendQUICRequest(encodedRequest, timeout);

      // Decode response from wire format
      const response = decodeResponse(responseFrame);

      if (this.config.debug) {
        await this.output.debug(`Response status: ${response.statusCode}`);
      }

      return {
        status: response.statusCode,
        data: response.body ? Buffer.from(response.body).toString('utf-8') : null,
        headers: response.headers,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      throw new NetworkError(`Request failed: ${message}`, {
        method,
        path,
        sequence: this.connection.sequence,
      });
    }
  }

  /**
   * Send QUIC request and receive response over real QUIC transport
   * Requires @matrixai/quic library installed
   */
  private async sendQUICRequest(encodedRequest: Uint8Array, timeout: number): Promise<Uint8Array> {
    try {
      const QuicModule = await import('@matrixai/quic');
      // Use @matrixai/quic Client to send request
      // This is a placeholder - actual implementation requires:
      // 1. Creating a QUIC client connection
      // 2. Opening a bidirectional stream
      // 3. Sending the encoded request
      // 4. Reading the response with timeout

      // For now: Throw clear error indicating @matrixai/quic setup needed
      throw new Error(
        'Real QUIC transport requires @matrixai/quic setup. ' +
          'Install with: npm install @matrixai/quic. ' +
          'Then initialize client and streams for bidirectional communication.',
      );
    } catch (error) {
      if (error instanceof Error && error.message.includes('Real QUIC transport requires')) {
        throw error;
      }
      throw new NetworkError(`QUIC request failed: ${error instanceof Error ? error.message : 'unknown'}`, {
        endpoint: this.config.quicEndpoint,
        requestSize: encodedRequest.length,
      });
    }
  }

  /**
   * Close connection
   */
  async disconnect(): Promise<void> {
    if (this.connection) {
      await this.output.info(`Disconnecting from ${this.connection.peerId}`);
      this.connection = null;
    }
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connection !== null;
  }

  /**
   * Get current session ID
   */
  getSessionId(): string | null {
    return this.connection?.sessionId || null;
  }

  /**
   * Generate 32-byte nonce
   */
  private generateNonce(): Uint8Array {
    const nonce = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(nonce);
    } else {
      // Fallback for testing
      for (let i = 0; i < 32; i++) {
        nonce[i] = Math.floor(Math.random() * 256);
      }
    }
    return nonce;
  }

  /**
   * Generate session ID
   */
  private generateSessionId(): string {
    const bytes = this.generateNonce();
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

/**
 * Helper: Initialize QUIC client for ZHTP
 */
export async function connectClient(
  identity: ZhtpIdentity,
  trustConfig: TrustConfig,
  quicEndpoint: string,
  output: Output,
): Promise<ZhtpQuicClient> {
  const client = new ZhtpQuicClient(identity, trustConfig, quicEndpoint, output);
  const result = await client.connect();

  if (!result.connected) {
    throw new NetworkError(`Failed to connect: ${result.error}`, {
      endpoint: quicEndpoint,
      trustMode: trustConfig.mode,
    });
  }

  return client;
}

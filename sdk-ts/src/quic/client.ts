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
   * Connect and perform UHP handshake
   */
  async connect(): Promise<ConnectionResult> {
    try {
      await this.output.info(`Connecting to ${this.config.quicEndpoint}`);

      // Phase 1: ClientHello → ServerHello
      const nonce = this.generateNonce();
      const clientHello = createClientHello(this.identity.did, nonce);

      if (this.config.debug) {
        await this.output.debug(`ClientHello: ${this.identity.did}`);
      }

      // In production: Send ClientHello, receive ServerHello
      // For now: Simulate server response
      const serverHello = {
        sessionId: this.generateSessionId(),
        serverDid: 'did:zhtp:server-placeholder',
        serverEphemeralPk: new Uint8Array(32), // Placeholder
        timestamp: BigInt(Date.now()) * 1_000_000n,
      };

      // Phase 1 signature: hash(ClientHello || ServerHello)
      const phase1Hash = hashHandshakePhase1(clientHello, serverHello);
      const clientSignature = createDilithium5Signature(phase1Hash);

      createClientFinish(serverHello.sessionId, clientHello, serverHello, clientSignature);

      if (this.config.debug) {
        await this.output.debug(`Phase 1 hash computed (${phase1Hash.length} bytes)`);
      }

      // Phase 2: Kyber512 KEM (client receives ciphertext, decapsulates)
      // In production: Receive ciphertext from server
      const kyberCiphertext = new Uint8Array(768); // Placeholder
      const kyberSharedSecret = kyber512Decapsulate(new Uint8Array(0), kyberCiphertext);

      if (this.config.debug) {
        await this.output.debug(`Kyber512 shared secret derived (${kyberSharedSecret.length} bytes)`);
      }

      // Phase 3: Master key derivation
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

      // Encode request to wire format
      encodeRequest(request);

      // In production: Send encoded request over QUIC
      // For now: Return mock response
      await this.output.info(`${method} ${path}`);

      // Simulate response
      const mockResponseFrame = new Uint8Array([0, 0, 0, 10, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33]);
      const response = decodeResponse(mockResponseFrame);

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

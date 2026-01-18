/**
 * QUIC client wrapper for ZHTP protocol
 * Manages authenticated connection and request/response cycle
 */

import { TrustConfig, ZhtpIdentity } from '../index.js';
import { Output } from '../output.js';
import { NetworkError } from '../error.js';
import { KeyPair } from '../identity.js';
import { QuicClientConfig, AuthenticatedConnection, ConnectionResult } from './types.js';
import { encodeRequest, decodeResponse, computeRequestMac, incrementSequence } from './wire.js';

/**
 * QUIC client for ZHTP protocol
 * Handles connection lifecycle and authenticated requests
 */
export class ZhtpQuicClient {
  private connection: AuthenticatedConnection | null = null;
  private quicConnection: any = null; // @matrixai/quic QUICConnection
  private config: QuicClientConfig;
  private identity: ZhtpIdentity;
  private keypair: KeyPair;
  private trustConfig: TrustConfig;
  private output: Output;

  constructor(
    identity: ZhtpIdentity,
    keypair: KeyPair,
    trustConfig: TrustConfig,
    quicEndpoint: string,
    output: Output,
    config?: Partial<QuicClientConfig>,
  ) {
    this.identity = identity;
    this.keypair = keypair;
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
   * Establishes QUIC connection then performs cryptographic authentication
   */
  async connect(): Promise<ConnectionResult> {
    try {
      await this.output.info(`Connecting to ${this.config.quicEndpoint}`);

      // Establish real QUIC connection to remote node
      await this.establishQUICConnection();

      // Generate session identifier for this connection
      const sessionId = this.generateSessionId();

      // WARNING: Placeholder key derivation - NOT SECURE FOR PRODUCTION
      // TODO: Implement full UHP v2 handshake with proper Kyber+Dilithium key exchange
      // This uses HKDF-SHA256 as a placeholder until real handshake is implemented
      const { hkdf } = await import('@noble/hashes/hkdf');
      const { sha256 } = await import('@noble/hashes/sha256');
      const encoder = new TextEncoder();
      const identityBytes = encoder.encode(this.identity.id + this.identity.did);
      const salt = encoder.encode('zhtp-sdk-placeholder-v0');
      const appKey = hkdf(sha256, identityBytes, salt, encoder.encode('app-key'), 32);

      await this.output.warning('Using placeholder key derivation - implement UHP v2 handshake for production');

      // Create authenticated connection state
      this.connection = {
        sessionId,
        peerId: this.config.quicEndpoint,
        appKey,
        sequence: 1n,  // Start at 1 (server's last_counter starts at 0, validation requires counter > last)
        establishedAt: Date.now(),
      };

      await this.output.info(`Connected to ${this.config.quicEndpoint} (session: ${sessionId.slice(0, 16)}...)`);

      return {
        connected: true,
        sessionId,
        peerId: this.config.quicEndpoint,
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

      // Convert session ID from hex string to Uint8Array for MAC computation
      const sessionIdBytes = this.hexToBytes(this.connection.sessionId);

      const requestMac = computeRequestMac(
        this.connection.appKey,
        sessionIdBytes,
        method,
        path,
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
      const timeout = options?.timeout ?? this.config.timeout;
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
   * Uses @matrixai/quic Web Streams API for bidirectional communication
   */
  private async sendQUICRequest(encodedRequest: Uint8Array, timeout: number | undefined): Promise<Uint8Array> {
    const actualTimeout = timeout ?? 30000;
    if (!this.quicConnection) {
      throw new NetworkError('QUIC connection not established', {
        endpoint: this.config.quicEndpoint,
      });
    }

    let stream: any = null;
    let writer: any = null;
    let reader: any = null;

    try {
      // Open bidirectional stream for this request
      stream = this.quicConnection.newStream('bidi');

      if (!stream) {
        throw new Error('Failed to open QUIC stream');
      }

      // Get writer and reader from Web Streams
      writer = stream.writable.getWriter();
      reader = stream.readable.getReader();

      // Send the encoded request (4-byte framing + CBOR payload)
      await writer.write(encodedRequest);

      // Read response with timeout
      const deadline = Date.now() + actualTimeout;

      // Read response frame (must have at least 4-byte length header)
      let lengthBuffer = new Uint8Array(4);
      let bytesRead = 0;

      // Read 4-byte length prefix (big-endian)
      while (bytesRead < 4) {
        if (Date.now() > deadline) {
          throw new Error(`QUIC request timeout (${actualTimeout}ms)`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed unexpectedly');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, 4 - bytesRead);
        lengthBuffer.set(value.slice(0, chunkToRead), bytesRead);
        bytesRead += chunkToRead;
      }

      // Parse length
      const view = new DataView(lengthBuffer.buffer);
      const messageLength = view.getUint32(0, false); // big-endian

      if (messageLength > 16 * 1024 * 1024) {
        throw new Error(`Response too large: ${messageLength} bytes (max 16MB)`);
      }

      // Read message body
      let bodyBytesRead = 0;
      const bodyBuffer = new Uint8Array(messageLength);

      while (bodyBytesRead < messageLength) {
        if (Date.now() > deadline) {
          throw new Error(`QUIC request timeout (${actualTimeout}ms)`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed before all data received');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, messageLength - bodyBytesRead);
        bodyBuffer.set(value.slice(0, chunkToRead), bodyBytesRead);
        bodyBytesRead += chunkToRead;
      }

      // Combine length prefix + body
      const fullResponse = new Uint8Array(4 + messageLength);
      fullResponse.set(lengthBuffer);
      fullResponse.set(bodyBuffer, 4);

      // Close stream (don't let cleanup errors mask successful response)
      try {
        if (writer) {
          await writer.close();
        }
        if (reader) {
          await reader.cancel();
        }
      } catch (cleanupError) {
        // Log but don't fail - we have valid response data
        if (this.config.debug) {
          await this.output.debug(
            `Warning: Stream cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : 'unknown'}`,
          );
        }
      }

      return fullResponse;
    } catch (error) {
      // Attempt cleanup before throwing
      try {
        if (writer) {
          await writer.close().catch(() => {
            // Ignore errors during cleanup on exception
          });
        }
        if (reader) {
          await reader.cancel().catch(() => {
            // Ignore errors during cleanup on exception
          });
        }
      } catch {
        // Ignore all cleanup errors when already handling an error
      }
      throw new NetworkError(`QUIC request failed: ${error instanceof Error ? error.message : 'unknown'}`, {
        endpoint: this.config.quicEndpoint,
        requestSize: encodedRequest.length,
      });
    }
  }

  /**
   * Establish real QUIC connection to remote node
   * Uses @matrixai/quic Web Streams API
   */
  private async establishQUICConnection(): Promise<void> {
    try {
      // Dynamically import @matrixai/quic
      // @ts-ignore - dynamic import of @matrixai/quic
      const QuicModule = await import('@matrixai/quic');

      const [host, port] = this.config.quicEndpoint.includes(':')
        ? this.config.quicEndpoint.split(':')
        : [this.config.quicEndpoint, '2048'];

      const portNum = parseInt(port, 10);

      // Validate port number
      if (isNaN(portNum)) {
        throw new Error(`Invalid port number: '${port}' is not a valid integer`);
      }
      if (portNum < 0 || portNum > 65535) {
        throw new Error(`Invalid port number: ${portNum} is outside valid range (0-65535)`);
      }

      // Create QUIC client using factory method
      // Try to use Node.js crypto module first
      let cryptoModule: any;
      try {
        // @ts-ignore
        cryptoModule = await import('crypto');
      } catch {
        // Fallback for browser environment
        cryptoModule = {
          randomBytes: (size: number) => {
            const arr = new Uint8Array(size);
            if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
              globalThis.crypto.getRandomValues(arr);
            }
            return arr;
          },
          getRandomValues: (arr: Uint8Array) => {
            if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
              globalThis.crypto.getRandomValues(arr);
            }
            return arr;
          },
        };
      }

      const quicClient = await QuicModule.QUICClient.createQUICClient(
        {
          host,
          port: portNum,
          crypto: cryptoModule,
        },
        { timer: this.config.timeout },
      );

      // Store the connection object (not the client)
      // @ts-ignore - @matrixai/quic connection property
      this.quicConnection = quicClient.connection;

      if (this.config.debug) {
        await this.output.debug(`QUIC connection established to ${host}:${portNum}`);
      }
    } catch (error) {
      throw new NetworkError(`Failed to establish QUIC connection: ${error instanceof Error ? error.message : 'unknown'}`, {
        endpoint: this.config.quicEndpoint,
      });
    }
  }


  /**
   * Close both authenticated session and QUIC connection
   */
  async disconnect(): Promise<void> {
    if (this.connection) {
      await this.output.info(`Disconnecting from ${this.connection.peerId}`);
      this.connection = null;
    }

    if (this.quicConnection) {
      try {
        // Use @matrixai/quic stop() method instead of destroy()
        // @ts-ignore - @matrixai/quic connection type
        await this.quicConnection.stop();
      } catch (error) {
        if (this.config.debug) {
          await this.output.debug(
            `Warning: QUIC connection stop failed: ${error instanceof Error ? error.message : 'unknown'}`,
          );
        }
      }
      this.quicConnection = null;
      await this.output.info('QUIC connection closed');
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

  /**
   * Convert hex string to Uint8Array
   */
  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
}

/**
 * Helper: Initialize QUIC client for ZHTP
 */
export async function connectClient(
  identity: ZhtpIdentity,
  keypair: KeyPair,
  trustConfig: TrustConfig,
  quicEndpoint: string,
  output: Output,
): Promise<ZhtpQuicClient> {
  const client = new ZhtpQuicClient(identity, keypair, trustConfig, quicEndpoint, output);
  const result = await client.connect();

  if (!result.connected) {
    throw new NetworkError(`Failed to connect: ${result.error}`, {
      endpoint: quicEndpoint,
      trustMode: trustConfig.mode,
    });
  }

  return client;
}

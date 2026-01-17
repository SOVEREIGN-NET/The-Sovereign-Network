/**
 * QUIC client wrapper for ZHTP protocol
 * Manages authenticated connection and request/response cycle
 */

import { TrustConfig, ZhtpIdentity } from '../index.js';
import { Output } from '../output.js';
import { NetworkError } from '../error.js';
import { KeyPair } from '../identity.js';
import { QuicClientConfig, AuthenticatedConnection, ConnectionResult, UhpClientFinish } from './types.js';
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

      // Phase 1: Create ClientHello with real Kyber512 ephemeral public key
      const nonce = this.generateNonce();
      const kyberEphemeralKeypair = await this.generateKyberKeypair();
      const clientHello = createClientHello(this.identity.did, nonce, kyberEphemeralKeypair.publicKey);

      if (this.config.debug) {
        await this.output.debug(`ClientHello: ${this.identity.did}`);
        await this.output.debug(`Kyber512 ephemeral public key (${kyberEphemeralKeypair.publicKey.length} bytes)`);
      }

      // Send ClientHello to server and receive ServerHello with kyberCiphertext
      // This requires actual QUIC handshake negotiation
      const serverHello = await this.performHandshakePhase1(clientHello);

      const phase1Hash = hashHandshakePhase1(clientHello, serverHello);
      const clientSignature = await createDilithium5Signature(phase1Hash);

      const clientFinish = createClientFinish(serverHello.sessionId, clientHello, serverHello, clientSignature);

      if (this.config.debug) {
        await this.output.debug(`Phase 1 hash computed (${phase1Hash.length} bytes)`);
        await this.output.debug(`Dilithium5 signature created (${clientSignature.length} bytes)`);
        await this.output.debug(`ServerHello received: sessionId=${serverHello.sessionId}`);
        await this.output.debug(`Kyber512 ciphertext from server (${serverHello.kyberCiphertext.length} bytes)`);
      }

      // Phase 1b: Send ClientFinish to server and receive ServerFinish confirmation
      // Server verifies client's signature and sends its own signature
      await this.performHandshakePhase1b(clientFinish);

      if (this.config.debug) {
        await this.output.debug(`ClientFinish sent and ServerFinish confirmed`);
      }

      // Phase 2: Kyber512 KEM - decapsulate with real server ciphertext and ephemeral private key
      // Uses kyberCiphertext from ServerHello and ephemeral private key
      const kyberSharedSecret = await kyber512Decapsulate(
        kyberEphemeralKeypair.privateKey,
        serverHello.kyberCiphertext,
      );

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
   * Generate ephemeral Kyber512 keypair for key exchange
   * Returns both public key (1184 bytes) and private key (2400 bytes)
   */
  private async generateKyberKeypair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    try {
      // @ts-ignore - crystals-kyber-js exports Kyber functions directly
      const KyberModule = await import('crystals-kyber-js');
      const KyberClass = (KyberModule as any).Kyber || (KyberModule as any).default;
      const kyber = new KyberClass();

      // Generate new keypair (ephemeral for this handshake)
      const keypair = kyber.generateKeys();

      if (!keypair || !keypair.publicKey || !keypair.secretKey) {
        throw new Error('Kyber keypair generation failed: missing public/secret key');
      }

      return {
        publicKey: keypair.publicKey,
        privateKey: keypair.secretKey,
      };
    } catch (error) {
      throw new NetworkError(
        `Failed to generate Kyber512 ephemeral keypair: ${error instanceof Error ? error.message : 'unknown'}`,
        { endpoint: this.config.quicEndpoint },
      );
    }
  }

  /**
   * Perform UHP Phase 1: Send ClientHello and receive ServerHello with kyberCiphertext
   * This requires actual QUIC handshake message exchange with the server
   * Uses @matrixai/quic Web Streams API
   */
  private async performHandshakePhase1(clientHello: any): Promise<any> {
    let stream: any = null;
    let writer: any = null;
    let reader: any = null;

    try {
      if (!this.quicConnection) {
        throw new Error('QUIC connection not established');
      }

      // Open bidirectional stream for handshake negotiation
      stream = this.quicConnection.newStream('bidi');

      if (!stream) {
        throw new Error('Failed to open QUIC handshake stream');
      }

      // Get writer and reader from Web Streams
      writer = stream.writable.getWriter();
      reader = stream.readable.getReader();

      // Encode ClientHello as CBOR and send with 4-byte framing
      const cborEncode = (await import('cbor')).encode;
      const clientHelloPayload = cborEncode({
        clientDid: clientHello.clientDid,
        timestamp: Number(clientHello.timestamp),
        nonce: Array.from(clientHello.nonce),
        kyberPublicKey: Array.from(clientHello.kyberPublicKey),
      });

      const clientHelloFrame = new Uint8Array(4 + clientHelloPayload.byteLength);
      const view = new DataView(clientHelloFrame.buffer);
      view.setUint32(0, clientHelloPayload.byteLength, false); // big-endian
      clientHelloFrame.set(clientHelloPayload, 4);

      await writer.write(clientHelloFrame);

      // Read ServerHello response (4-byte length + CBOR payload)
      const cborDecode = (await import('cbor')).decode;
      const lengthBuffer = new Uint8Array(4);
      let bytesRead = 0;

      // Read 4-byte length prefix with timeout
      const timeout = this.config.timeout || 30000;
      const deadline = Date.now() + timeout;

      while (bytesRead < 4) {
        if (Date.now() > deadline) {
          throw new Error(`Handshake timeout waiting for ServerHello`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed unexpectedly during handshake');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, 4 - bytesRead);
        lengthBuffer.set(value.slice(0, chunkToRead), bytesRead);
        bytesRead += chunkToRead;
      }

      // Parse length and read ServerHello payload
      const lengthView = new DataView(lengthBuffer.buffer);
      const payloadLength = lengthView.getUint32(0, false);

      if (payloadLength > 16 * 1024) {
        throw new Error(`ServerHello too large: ${payloadLength} bytes`);
      }

      const payloadBuffer = new Uint8Array(payloadLength);
      let payloadBytesRead = 0;

      while (payloadBytesRead < payloadLength) {
        if (Date.now() > deadline) {
          throw new Error(`Handshake timeout reading ServerHello payload`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed before ServerHello received');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, payloadLength - payloadBytesRead);
        payloadBuffer.set(value.slice(0, chunkToRead), payloadBytesRead);
        payloadBytesRead += chunkToRead;
      }

      // Decode ServerHello from CBOR
      const serverHelloData = cborDecode(payloadBuffer);

      // Reconstruct ServerHello with Uint8Array fields
      const serverHello = {
        sessionId: serverHelloData.sessionId,
        serverDid: serverHelloData.serverDid,
        serverEphemeralPk: new Uint8Array(serverHelloData.serverEphemeralPk),
        kyberCiphertext: new Uint8Array(serverHelloData.kyberCiphertext),
        timestamp: BigInt(serverHelloData.timestamp),
      };

      // Close handshake stream (don't let cleanup errors mask successful response)
      try {
        if (writer) {
          await writer.close();
        }
        if (reader) {
          await reader.cancel();
        }
      } catch (cleanupError) {
        // Log but don't fail - we have valid ServerHello data
        if (this.config.debug) {
          await this.output.debug(
            `Warning: Handshake stream cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : 'unknown'}`,
          );
        }
      }

      return serverHello;
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
      throw new NetworkError(
        `UHP Phase 1 handshake failed: ${error instanceof Error ? error.message : 'unknown'}`,
        { endpoint: this.config.quicEndpoint },
      );
    }
  }

  /**
   * Perform UHP Phase 1b: Send ClientFinish and receive ServerFinish confirmation
   * Client sends signature to server, server verifies and responds with its own signature
   * Uses @matrixai/quic Web Streams API
   */
  private async performHandshakePhase1b(clientFinish: UhpClientFinish): Promise<void> {
    let stream: any = null;
    let writer: any = null;
    let reader: any = null;

    try {
      if (!this.quicConnection) {
        throw new Error('QUIC connection not established');
      }

      // Open new bidirectional stream for ClientFinish message
      stream = this.quicConnection.newStream('bidi');

      if (!stream) {
        throw new Error('Failed to open QUIC stream for ClientFinish');
      }

      // Get writer and reader from Web Streams
      writer = stream.writable.getWriter();
      reader = stream.readable.getReader();

      // Encode ClientFinish as CBOR and send with 4-byte framing
      const cborEncode = (await import('cbor')).encode;
      const clientFinishPayload = cborEncode({
        sessionId: clientFinish.sessionId,
        clientSignature: Array.from(clientFinish.clientSignature),
      });

      const clientFinishFrame = new Uint8Array(4 + clientFinishPayload.byteLength);
      const view = new DataView(clientFinishFrame.buffer);
      view.setUint32(0, clientFinishPayload.byteLength, false); // big-endian
      clientFinishFrame.set(clientFinishPayload, 4);

      await writer.write(clientFinishFrame);

      // Read ServerFinish response (server's signature confirmation)
      const cborDecode = (await import('cbor')).decode;
      const lengthBuffer = new Uint8Array(4);
      let bytesRead = 0;

      // Read 4-byte length prefix with timeout
      const timeout = this.config.timeout || 30000;
      const deadline = Date.now() + timeout;

      while (bytesRead < 4) {
        if (Date.now() > deadline) {
          throw new Error(`Handshake timeout waiting for ServerFinish`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed unexpectedly during ServerFinish');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, 4 - bytesRead);
        lengthBuffer.set(value.slice(0, chunkToRead), bytesRead);
        bytesRead += chunkToRead;
      }

      // Parse length and read ServerFinish payload
      const lengthView = new DataView(lengthBuffer.buffer);
      const payloadLength = lengthView.getUint32(0, false);

      if (payloadLength > 16 * 1024) {
        throw new Error(`ServerFinish too large: ${payloadLength} bytes`);
      }

      const payloadBuffer = new Uint8Array(payloadLength);
      let payloadBytesRead = 0;

      while (payloadBytesRead < payloadLength) {
        if (Date.now() > deadline) {
          throw new Error(`Handshake timeout reading ServerFinish payload`);
        }
        const { value, done } = await reader.read();
        if (done) {
          throw new Error('QUIC stream closed before ServerFinish received');
        }
        if (!value || value.length === 0) {
          throw new Error('QUIC stream returned empty chunk');
        }
        const chunkToRead = Math.min(value.length, payloadLength - payloadBytesRead);
        payloadBuffer.set(value.slice(0, chunkToRead), payloadBytesRead);
        payloadBytesRead += chunkToRead;
      }

      // Decode ServerFinish from CBOR
      const serverFinishData = cborDecode(payloadBuffer);

      // In production: verify server's signature using its public key from ServerHello
      // For now: just confirm receipt
      if (!serverFinishData.serverSignature) {
        throw new Error('ServerFinish missing serverSignature field');
      }

      // Close stream (don't let cleanup errors mask successful handshake)
      try {
        if (writer) {
          await writer.close();
        }
        if (reader) {
          await reader.cancel();
        }
      } catch (cleanupError) {
        // Log but don't fail - handshake is complete
        if (this.config.debug) {
          await this.output.debug(
            `Warning: Phase 1b stream cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : 'unknown'}`,
          );
        }
      }
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
      throw new NetworkError(
        `UHP Phase 1b (ClientFinish/ServerFinish) failed: ${error instanceof Error ? error.message : 'unknown'}`,
        { endpoint: this.config.quicEndpoint },
      );
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

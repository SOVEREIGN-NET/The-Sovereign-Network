/**
 * Main ZHTP Client - Entry point for SDK
 * Coordinates identity loading, QUIC connection, and manager initialization
 */

import { ZhtpIdentity, LoadedIdentity, PrivateKeyMaterial } from './identity.js';
import { TrustConfig } from './types.js';
import { Output, ConsoleOutput } from './output.js';
import { ZhtpQuicClient, connectClient } from './quic/client.js';
import { DomainManager } from './managers/domain.js';
import { WalletManager } from './managers/wallet.js';
import { NetworkError } from './error.js';

/**
 * Main ZHTP Client with all managers
 */
export class ZhtpClient {
  private quicClient: ZhtpQuicClient;
  private output: Output;

  /**
   * Domain operations manager
   */
  domains: DomainManager;

  /**
   * Wallet operations manager
   */
  wallet: WalletManager;

  constructor(
    identity: ZhtpIdentity,
    quicClient: ZhtpQuicClient,
    output: Output = new ConsoleOutput(),
  ) {
    this.quicClient = quicClient;
    this.output = output;

    // Initialize managers
    this.domains = new DomainManager(this.quicClient, this.output);
    this.wallet = new WalletManager(this.quicClient, this.output);
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.quicClient.isConnected();
  }

  /**
   * Get current session ID
   */
  getSessionId(): string | null {
    return this.quicClient.getSessionId();
  }

  /**
   * Disconnect from QUIC node
   */
  async disconnect(): Promise<void> {
    await this.quicClient.disconnect();
  }
}

/**
 * Three-layer client initialization pattern (following zhtp-cli)
 *
 * Layer 1: Load identity from keystore
 * Layer 2: Build trust configuration
 * Layer 3: Create authenticated QUIC client
 */

/**
 * Layer 1: Load identity from keystore
 * (Placeholder - file I/O would be implemented here)
 */
export function loadIdentity(
  id: string,
  did: string,
  publicKey: string,
  privateKey: PrivateKeyMaterial,
): LoadedIdentity {
  return {
    identity: {
      id,
      did,
      publicKey,
      createdAt: Math.floor(Date.now() / 1000),
      isActive: true,
    },
    keypair: {
      publicKey,
      privateKey,
    },
  };
}

/**
 * Layer 2: Build trust configuration
 */
export function buildTrustConfig(options: {
  mode?: 'bootstrap' | 'tofu' | 'pinned' | 'default';
  nodeDidExpectation?: string;
  pinnedSpki?: string;
  trustDbPath?: string;
}): TrustConfig {
  return {
    mode: options.mode || 'bootstrap',
    nodeDidExpectation: options.nodeDidExpectation,
    pinnedSpki: options.pinnedSpki,
    trustDbPath: options.trustDbPath,
  };
}

/**
 * Layer 3: Create authenticated QUIC client
 * Performs UHP handshake and returns ready-to-use client
 */
export async function initializeClient(
  identity: ZhtpIdentity,
  trustConfig: TrustConfig,
  quicEndpoint: string,
  output: Output = new ConsoleOutput(),
): Promise<ZhtpClient> {
  // Connect and authenticate
  const quicClient = await connectClient(identity, trustConfig, quicEndpoint, output);

  // Create main client
  return new ZhtpClient(identity, quicClient, output);
}

/**
 * Convenience: Complete initialization flow
 */
export async function connect(
  id: string,
  did: string,
  publicKey: string,
  privateKey: PrivateKeyMaterial,
  quicEndpoint: string,
  trustOptions?: {
    mode?: 'bootstrap' | 'tofu' | 'pinned' | 'default';
    nodeDidExpectation?: string;
  },
  output: Output = new ConsoleOutput(),
): Promise<ZhtpClient> {
  // Layer 1: Load identity
  const loaded = loadIdentity(id, did, publicKey, privateKey);

  // Layer 2: Build trust config
  const trustConfig = buildTrustConfig({
    mode: trustOptions?.mode || 'bootstrap',
    nodeDidExpectation: trustOptions?.nodeDidExpectation,
  });

  // Layer 3: Create authenticated client
  return await initializeClient(loaded.identity, trustConfig, quicEndpoint, output);
}

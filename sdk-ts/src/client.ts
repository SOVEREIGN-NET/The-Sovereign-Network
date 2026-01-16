/**
 * Main ZHTP Client for interacting with the Web4 API
 */

import { Transport } from './transport/types.js';
import { HttpTransport } from './transport/http.js';
import { IdentityManager } from './crypto/identity.js';
import { DomainManager } from './managers/domain.js';
import { ContentManager } from './managers/content.js';
import { DeployManager } from './managers/deploy.js';
import { WalletManager } from './managers/wallet.js';
import { ClientOptions } from './types/domain.js';

export class ZhtpClient {
  private transport: Transport;
  private identity: IdentityManager;
  private options: Required<ClientOptions>;

  // Managers
  readonly domains: DomainManager;
  readonly content: ContentManager;
  readonly deploy: DeployManager;
  readonly wallet: WalletManager;

  constructor(identity: IdentityManager, options: ClientOptions) {
    this.identity = identity;
    this.options = {
      baseUrl: options.baseUrl,
      timeout: options.timeout ?? 30000,
      retryAttempts: options.retryAttempts ?? 3,
      retryDelay: options.retryDelay ?? 100,
      debug: options.debug ?? false,
    };

    // Initialize transport
    this.transport = new HttpTransport({
      baseUrl: this.options.baseUrl,
      timeout: this.options.timeout,
      debug: this.options.debug,
      headers: {
        'User-Agent': 'zhtp-sdk-ts/1.0.0',
        'X-Identity': identity.getDid(),
      },
    });

    // Initialize managers
    this.domains = new DomainManager(this.transport, this.identity, this.options);
    this.content = new ContentManager(this.transport, this.identity, this.options);
    this.deploy = new DeployManager(this.transport, this.identity, this.options);
    this.wallet = new WalletManager(this.transport, this.identity, this.options);
  }

  /**
   * Get the identity associated with this client
   */
  getIdentity(): IdentityManager {
    return this.identity;
  }

  /**
   * Get the underlying transport
   */
  getTransport(): Transport {
    return this.transport;
  }

  /**
   * Set a default header for all requests
   */
  setHeader(name: string, value: string): void {
    this.transport.setHeader(name, value);
  }

  /**
   * Remove a default header
   */
  removeHeader(name: string): void {
    this.transport.removeHeader(name);
  }

  /**
   * Check server connectivity
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.transport.get<{ status: string }>('/api/v1/health');
      return response.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * Get server version information
   */
  async getServerInfo(): Promise<{
    version: string;
    name: string;
    networkId: string;
  }> {
    const response = await this.transport.get<{
      version: string;
      name: string;
      networkId: string;
    }>('/api/v1/info');
    return response.body;
  }
}

/**
 * Create a ZHTP client with default configuration
 */
export function createZhtpClient(
  identity: IdentityManager,
  baseUrl: string = 'http://localhost:8080',
  options?: Partial<ClientOptions>
): ZhtpClient {
  return new ZhtpClient(identity, {
    baseUrl,
    ...options,
  });
}

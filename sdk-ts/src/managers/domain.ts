/**
 * DomainManager - Handles domain registration, lookup, and management
 */

import { Transport } from '../transport/types.js';
import { IdentityManager } from '../crypto/identity.js';
import {
  RegisterOptions,
  RegisterResult,
  DomainInfo,
  DomainStatus,
  DomainHistory,
  Proof,
  ClientOptions,
} from '../types/domain.js';
import { SimpleDomainRegistrationRequest } from '../types/requests.js';
import { SimpleDomainRegistrationResponse, DomainInfo as DomainInfoResponse } from '../types/responses.js';
import { validateDomain, calculateDomainFee } from '../crypto/utils.js';

export class DomainManager {
  constructor(
    private transport: Transport,
    private identity: IdentityManager,
    _options: Required<ClientOptions>
  ) {}

  /**
   * Register a new domain
   */
  async register(domain: string, opts?: RegisterOptions): Promise<RegisterResult> {
    // Validate domain name
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    // Calculate fee if not provided
    const registerOpts = opts || {};
    const fee = registerOpts.fee ?? calculateDomainFee(domain, registerOpts.years ?? 1);

    // Prepare registration request
    const request: SimpleDomainRegistrationRequest = {
      domain,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature when signing endpoint is available
      content: registerOpts.contentCid,
      fee,
      metadata: registerOpts.metadata,
    };

    // Send registration request
    const response = await this.transport.post<SimpleDomainRegistrationResponse>(
      '/api/v1/web4/domains/register',
      request
    );

    return {
      domain: response.body.domain,
      owner: response.body.owner,
      registeredAt: response.body.registeredAt,
      expiresAt: response.body.expiresAt,
      transactionHash: response.body.transactionHash || '',
      contentCid: response.body.contentCid,
    };
  }

  /**
   * Check if a domain is available
   */
  async check(domain: string): Promise<boolean> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const response = await this.transport.get<{ available: boolean }>(
      `/api/v1/web4/domains/check?domain=${encodeURIComponent(domain)}`
    );

    return response.body.available;
  }

  /**
   * Get domain information
   */
  async getInfo(domain: string): Promise<DomainInfo> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const response = await this.transport.get<DomainInfoResponse>(
      `/api/v1/web4/domains/lookup?domain=${encodeURIComponent(domain)}`
    );

    return {
      domain: response.body.domain,
      owner: response.body.owner,
      registeredAt: response.body.registeredAt,
      expiresAt: response.body.expiresAt,
      contentCid: response.body.contentCid,
      contentVersion: response.body.contentVersion,
      governance: response.body.governance,
      metadata: response.body.metadata,
    };
  }

  /**
   * Transfer domain to a new owner
   */
  async transfer(domain: string, newOwner: string, proof: Proof): Promise<boolean> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    await this.transport.post(`/api/v1/web4/domains/transfer`, {
      domain,
      newOwner,
      publicKey: proof.publicKey,
      signature: proof.signature,
    });

    return true;
  }

  /**
   * Release (delete) a domain
   */
  async release(domain: string): Promise<boolean> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    await this.transport.post(`/api/v1/web4/domains/release`, {
      domain,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature
    });

    return true;
  }

  /**
   * Get domain status
   */
  async getStatus(domain: string): Promise<DomainStatus> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const response = await this.transport.get<DomainStatus>(
      `/api/v1/web4/domains/status?domain=${encodeURIComponent(domain)}`
    );

    return response.body;
  }

  /**
   * Get domain operation history
   */
  async getHistory(domain: string, limit?: number): Promise<DomainHistory> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const queryParams = new URLSearchParams({ domain });
    if (limit) {
      queryParams.append('limit', limit.toString());
    }

    const response = await this.transport.get<DomainHistory>(
      `/api/v1/web4/domains/history?${queryParams}`
    );

    return response.body;
  }

  /**
   * Renew a domain
   */
  async renew(domain: string, years: number = 1, fee?: number): Promise<RegisterResult> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const registrationFee = fee ?? calculateDomainFee(domain, years);

    const response = await this.transport.post<SimpleDomainRegistrationResponse>(
      '/api/v1/web4/domains/renew',
      {
        domain,
        years,
        publicKey: this.identity.getPublicKey(),
        signature: '', // TODO: Add actual signature
        fee: registrationFee,
      }
    );

    return {
      domain: response.body.domain,
      owner: response.body.owner,
      registeredAt: response.body.registeredAt,
      expiresAt: response.body.expiresAt,
      transactionHash: response.body.transactionHash || '',
    };
  }

  /**
   * Batch check multiple domains for availability
   */
  async checkBatch(domains: string[]): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    for (const domain of domains) {
      try {
        const available = await this.check(domain);
        results.set(domain, available);
      } catch (error) {
        results.set(domain, false);
      }
    }

    return results;
  }

  /**
   * Get multiple domain infos
   */
  async getInfoBatch(domains: string[]): Promise<Map<string, DomainInfo>> {
    const results = new Map<string, DomainInfo>();

    for (const domain of domains) {
      try {
        const info = await this.getInfo(domain);
        results.set(domain, info);
      } catch (error) {
        // Skip domains that don't exist or have errors
      }
    }

    return results;
  }
}

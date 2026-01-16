/**
 * Domain Manager - handles all domain operations
 * Follows zhtp-cli patterns with pure validation + signed requests
 */

import { Output } from '../output.js';
import { DomainError, ValidationError } from '../error.js';
import { ZhtpQuicClient } from '../quic/client.js';
import { DomainOp, DomainInfo, getDomainOpConfig } from '../types.js';
import {
  validateDomain,
  calculateDomainRegistrationFee,
} from '../validation.js';

/**
 * Domain registration options
 */
export interface RegisterOptions {
  contentCid: string; // IPFS/IPNS content identifier
  years?: number; // Registration period (default 1)
  metadata?: Record<string, string>;
}

/**
 * Domain transfer proof
 */
export interface TransferProof {
  signature: string; // Proof of ownership
  nonce: string;
}

/**
 * Domain Manager
 */
export class DomainManager {
  constructor(private client: ZhtpQuicClient, private output: Output) {}

  /**
   * Register a new domain
   */
  async register(domain: string, options: RegisterOptions): Promise<DomainInfo> {
    // Validate
    const domainValidation = validateDomain(domain);
    if (!domainValidation.valid) {
      throw new ValidationError('Invalid domain name', domainValidation.errors);
    }

    if (!options.contentCid || options.contentCid.length === 0) {
      throw new ValidationError('Content CID required', [
        { field: 'contentCid', message: 'Must provide IPFS content identifier' },
      ]);
    }

    const years = options.years || 1;
    const fee = calculateDomainRegistrationFee(domain, years);

    await this.output.info(`Registering ${domain} for ${years} year(s)`);
    await this.output.info(`Registration fee: ${(Number(fee) / 100_000_000).toFixed(8)} ZHTP`);

    try {
      // Get operation config
      const config = getDomainOpConfig(DomainOp.Register);

      // Build request body
      const body = {
        domain,
        contentCid: options.contentCid,
        years,
        fee: Number(fee),
        metadata: options.metadata || {},
      };

      // Send request
      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new DomainError(`Registration failed: ${response.status}`, {
          domain,
          status: response.status,
          data: response.data,
        });
      }

      await this.output.success(`Domain registered: ${domain}`);

      return {
        domain,
        owner: 'current-user', // Would be actual owner from response
        registeredAt: Math.floor(Date.now() / 1000),
        expiresAt: Math.floor(Date.now() / 1000) + years * 365 * 24 * 3600,
        contentCid: options.contentCid,
        contentVersion: 1,
        metadata: options.metadata,
      };
    } catch (error) {
      if (error instanceof ValidationError || error instanceof DomainError) {
        throw error;
      }
      throw new DomainError(`Registration error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
      });
    }
  }

  /**
   * Check domain availability
   */
  async checkAvailability(domain: string): Promise<boolean> {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain name', validation.errors);
    }

    await this.output.info(`Checking availability: ${domain}`);

    try {
      const config = getDomainOpConfig(DomainOp.Check);
      const response = await this.client.request('GET', `${config.endpointPath}?domain=${domain}`);

      if (response.status === 200) {
        const available = response.data ? JSON.parse(response.data).available : false;
        await this.output.success(`${domain} is ${available ? 'available' : 'taken'}`);
        return available;
      }

      return false;
    } catch (error) {
      throw new DomainError(`Check failed: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
      });
    }
  }

  /**
   * Look up domain information
   */
  async lookup(domain: string): Promise<DomainInfo> {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain name', validation.errors);
    }

    await this.output.info(`Looking up: ${domain}`);

    try {
      const config = getDomainOpConfig(DomainOp.Lookup);
      const response = await this.client.request('GET', `${config.endpointPath}?domain=${domain}`);

      if (response.status !== 200) {
        throw new DomainError(`Lookup failed: ${response.status}`, {
          domain,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      if (!data) {
        throw new DomainError(`Domain not found: ${domain}`, { domain });
      }

      await this.output.success(`Found: ${domain}`);

      return {
        domain,
        owner: data.owner,
        registeredAt: data.registeredAt,
        expiresAt: data.expiresAt,
        contentCid: data.contentCid,
        contentVersion: data.contentVersion || 1,
        metadata: data.metadata,
      };
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      throw new DomainError(`Lookup error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
      });
    }
  }

  /**
   * Transfer domain to new owner
   */
  async transfer(domain: string, newOwner: string, proof: TransferProof): Promise<boolean> {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain name', validation.errors);
    }

    await this.output.info(`Transferring ${domain} to ${newOwner}`);

    try {
      const config = getDomainOpConfig(DomainOp.Transfer);

      const body = {
        domain,
        newOwner,
        proof,
      };

      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200) {
        throw new DomainError(`Transfer failed: ${response.status}`, {
          domain,
          newOwner,
          status: response.status,
        });
      }

      await this.output.success(`Domain transferred: ${domain} → ${newOwner}`);
      return true;
    } catch (error) {
      throw new DomainError(`Transfer error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
        newOwner,
      });
    }
  }

  /**
   * Release/sell domain
   */
  async release(domain: string): Promise<boolean> {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain name', validation.errors);
    }

    await this.output.info(`Releasing domain: ${domain}`);

    try {
      const config = getDomainOpConfig(DomainOp.Release);

      const body = { domain };
      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200) {
        throw new DomainError(`Release failed: ${response.status}`, {
          domain,
          status: response.status,
        });
      }

      await this.output.success(`Domain released: ${domain}`);
      return true;
    } catch (error) {
      throw new DomainError(`Release error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
      });
    }
  }

  /**
   * Renew domain registration
   */
  async renew(domain: string, years: number = 1): Promise<boolean> {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain name', validation.errors);
    }

    const fee = calculateDomainRegistrationFee(domain, years);
    await this.output.info(`Renewing ${domain} for ${years} year(s)`);

    try {
      const config = getDomainOpConfig(DomainOp.Renew);

      const body = {
        domain,
        years,
        fee: Number(fee),
      };

      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200) {
        throw new DomainError(`Renewal failed: ${response.status}`, {
          domain,
          years,
          status: response.status,
        });
      }

      await this.output.success(`Domain renewed: ${domain}`);
      return true;
    } catch (error) {
      throw new DomainError(`Renewal error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain,
        years,
      });
    }
  }
}

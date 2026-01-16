import { describe, it, expect } from 'vitest';
import { DomainOp, WalletOp, getDomainOpConfig, getWalletOpConfig } from '../../src/types.js';

describe('Operation Enums', () => {
  describe('DomainOp', () => {
    it('has all expected operations', () => {
      expect(DomainOp.Register).toBe('register');
      expect(DomainOp.Check).toBe('check');
      expect(DomainOp.Lookup).toBe('lookup');
      expect(DomainOp.Transfer).toBe('transfer');
      expect(DomainOp.Release).toBe('release');
      expect(DomainOp.Renew).toBe('renew');
    });

    it('has correct number of operations', () => {
      const operations = Object.values(DomainOp);
      expect(operations.length).toBe(6);
    });
  });

  describe('WalletOp', () => {
    it('has all expected operations', () => {
      expect(WalletOp.Create).toBe('create');
      expect(WalletOp.List).toBe('list');
      expect(WalletOp.Balance).toBe('balance');
      expect(WalletOp.Transfer).toBe('transfer');
      expect(WalletOp.History).toBe('history');
      expect(WalletOp.Stake).toBe('stake');
      expect(WalletOp.Unstake).toBe('unstake');
    });

    it('has correct number of operations', () => {
      const operations = Object.values(WalletOp);
      expect(operations.length).toBe(7);
    });
  });
});

describe('getDomainOpConfig', () => {
  it('returns config for Register operation', () => {
    const config = getDomainOpConfig(DomainOp.Register);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/register');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Register Domain');
  });

  it('returns config for Check operation', () => {
    const config = getDomainOpConfig(DomainOp.Check);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/check');
    expect(config.method).toBe('GET');
    expect(config.title).toBe('Check Domain Availability');
  });

  it('returns config for Lookup operation', () => {
    const config = getDomainOpConfig(DomainOp.Lookup);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/lookup');
    expect(config.method).toBe('GET');
    expect(config.title).toBe('Lookup Domain');
  });

  it('returns config for Transfer operation', () => {
    const config = getDomainOpConfig(DomainOp.Transfer);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/transfer');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Transfer Domain');
  });

  it('returns config for Release operation', () => {
    const config = getDomainOpConfig(DomainOp.Release);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/release');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Release Domain');
  });

  it('returns config for Renew operation', () => {
    const config = getDomainOpConfig(DomainOp.Renew);
    expect(config.endpointPath).toBe('/api/v1/web4/domains/renew');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Renew Domain');
  });

  it('has all expected config fields', () => {
    const config = getDomainOpConfig(DomainOp.Register);
    expect(config).toHaveProperty('endpointPath');
    expect(config).toHaveProperty('method');
    expect(config).toHaveProperty('title');
  });

  it('returns different configs for different operations', () => {
    const registerConfig = getDomainOpConfig(DomainOp.Register);
    const checkConfig = getDomainOpConfig(DomainOp.Check);

    expect(registerConfig.endpointPath).not.toBe(checkConfig.endpointPath);
    expect(registerConfig.method).not.toBe(checkConfig.method);
    expect(registerConfig.title).not.toBe(checkConfig.title);
  });
});

describe('getWalletOpConfig', () => {
  it('returns config for Create operation', () => {
    const config = getWalletOpConfig(WalletOp.Create);
    expect(config.endpointPath).toBe('/api/v1/wallet/create');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Create Wallet');
  });

  it('returns config for List operation', () => {
    const config = getWalletOpConfig(WalletOp.List);
    expect(config.endpointPath).toBe('/api/v1/wallet/list');
    expect(config.method).toBe('GET');
    expect(config.title).toBe('List Wallets');
  });

  it('returns config for Balance operation', () => {
    const config = getWalletOpConfig(WalletOp.Balance);
    expect(config.endpointPath).toBe('/api/v1/wallet/balance');
    expect(config.method).toBe('GET');
    expect(config.title).toBe('Get Balance');
  });

  it('returns config for Transfer operation', () => {
    const config = getWalletOpConfig(WalletOp.Transfer);
    expect(config.endpointPath).toBe('/api/v1/wallet/send');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Transfer');
  });

  it('returns config for History operation', () => {
    const config = getWalletOpConfig(WalletOp.History);
    expect(config.endpointPath).toBe('/api/v1/wallet/transactions');
    expect(config.method).toBe('GET');
    expect(config.title).toBe('Transaction History');
  });

  it('returns config for Stake operation', () => {
    const config = getWalletOpConfig(WalletOp.Stake);
    expect(config.endpointPath).toBe('/api/v1/wallet/stake');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Stake');
  });

  it('returns config for Unstake operation', () => {
    const config = getWalletOpConfig(WalletOp.Unstake);
    expect(config.endpointPath).toBe('/api/v1/wallet/unstake');
    expect(config.method).toBe('POST');
    expect(config.title).toBe('Unstake');
  });

  it('has all expected config fields', () => {
    const config = getWalletOpConfig(WalletOp.Create);
    expect(config).toHaveProperty('endpointPath');
    expect(config).toHaveProperty('method');
    expect(config).toHaveProperty('title');
  });

  it('returns different configs for different operations', () => {
    const createConfig = getWalletOpConfig(WalletOp.Create);
    const balanceConfig = getWalletOpConfig(WalletOp.Balance);

    expect(createConfig.endpointPath).not.toBe(balanceConfig.endpointPath);
    expect(createConfig.method).not.toBe(balanceConfig.method);
    expect(createConfig.title).not.toBe(balanceConfig.title);
  });
});

describe('Operation Config Patterns', () => {
  it('domain operations use correct HTTP methods', () => {
    // Read operations
    expect(getDomainOpConfig(DomainOp.Check).method).toBe('GET');
    expect(getDomainOpConfig(DomainOp.Lookup).method).toBe('GET');

    // Write operations
    expect(getDomainOpConfig(DomainOp.Register).method).toBe('POST');
    expect(getDomainOpConfig(DomainOp.Transfer).method).toBe('POST');
    expect(getDomainOpConfig(DomainOp.Release).method).toBe('POST');
    expect(getDomainOpConfig(DomainOp.Renew).method).toBe('POST');
  });

  it('wallet operations use correct HTTP methods', () => {
    // Read operations
    expect(getWalletOpConfig(WalletOp.List).method).toBe('GET');
    expect(getWalletOpConfig(WalletOp.Balance).method).toBe('GET');
    expect(getWalletOpConfig(WalletOp.History).method).toBe('GET');

    // Write operations
    expect(getWalletOpConfig(WalletOp.Create).method).toBe('POST');
    expect(getWalletOpConfig(WalletOp.Transfer).method).toBe('POST');
    expect(getWalletOpConfig(WalletOp.Stake).method).toBe('POST');
    expect(getWalletOpConfig(WalletOp.Unstake).method).toBe('POST');
  });

  it('all endpoint paths follow API versioning convention', () => {
    const domainOps = Object.values(DomainOp);
    domainOps.forEach(op => {
      const config = getDomainOpConfig(op);
      expect(config.endpointPath).toMatch(/^\/api\/v1\//);
    });

    const walletOps = Object.values(WalletOp);
    walletOps.forEach(op => {
      const config = getWalletOpConfig(op);
      expect(config.endpointPath).toMatch(/^\/api\/v1\//);
    });
  });

  it('all configs have meaningful titles', () => {
    const domainOps = Object.values(DomainOp);
    domainOps.forEach(op => {
      const config = getDomainOpConfig(op);
      expect(config.title.length).toBeGreaterThan(0);
      expect(config.title).toMatch(/[A-Z]/); // Has uppercase
    });

    const walletOps = Object.values(WalletOp);
    walletOps.forEach(op => {
      const config = getWalletOpConfig(op);
      expect(config.title.length).toBeGreaterThan(0);
      expect(config.title).toMatch(/[A-Z]/); // Has uppercase
    });
  });
});

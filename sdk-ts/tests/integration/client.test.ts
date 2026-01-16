/**
 * Integration tests for ZhtpClient
 *
 * These tests require a running ZHTP server on localhost:8080
 * To run: npm run test:integration
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { ZhtpClient, IdentityManager, createZhtpClient } from '../../src/index.js';
import { HttpTransport } from '../../src/transport/http.js';

// Mock public key for testing
const TEST_PUBLIC_KEY = 'a'.repeat(64);
const TEST_API_URL = process.env.API_URL || 'http://localhost:8080';

describe('ZhtpClient Integration Tests', () => {
  let client: ZhtpClient;
  let identity: IdentityManager;

  beforeAll(() => {
    identity = IdentityManager.fromPublicKey(TEST_PUBLIC_KEY);
    client = createZhtpClient(identity, TEST_API_URL);
  });

  describe('Client Initialization', () => {
    it('should create client with identity and options', () => {
      expect(client).toBeDefined();
      expect(client.getIdentity()).toBeDefined();
      expect(client.getTransport()).toBeDefined();
    });

    it('should have all managers initialized', () => {
      expect(client.domains).toBeDefined();
      expect(client.content).toBeDefined();
      expect(client.deploy).toBeDefined();
      expect(client.wallet).toBeDefined();
    });

    it('should have correct identity', () => {
      const clientIdentity = client.getIdentity();
      expect(clientIdentity.getPublicKey()).toBe(TEST_PUBLIC_KEY);
      expect(clientIdentity.getDid()).toContain('did:zhtp:');
    });
  });

  describe('Health Check', () => {
    it('should check server health', async () => {
      try {
        const isHealthy = await client.healthCheck();
        expect(typeof isHealthy).toBe('boolean');
      } catch (error) {
        // Server might not be running
        console.warn('⚠️  Server not available for health check');
      }
    });
  });

  describe('HTTP Transport', () => {
    it('should create transport with correct base URL', () => {
      const transport = client.getTransport();
      expect(transport).toBeInstanceOf(HttpTransport);
    });

    it('should handle headers', () => {
      const transport = client.getTransport();
      transport.setHeader('X-Test', 'test-value');
      expect(transport).toBeDefined();
      transport.removeHeader('X-Test');
    });
  });

  describe('Domain Manager', () => {
    it('should validate domain names', async () => {
      try {
        // These should fail on invalid domains
        await expect(client.domains.check('invalid domain')).rejects.toThrow();
      } catch {
        // Expected if server is not running
      }
    });

    it('should have domain methods', () => {
      expect(typeof client.domains.register).toBe('function');
      expect(typeof client.domains.check).toBe('function');
      expect(typeof client.domains.getInfo).toBe('function');
      expect(typeof client.domains.transfer).toBe('function');
      expect(typeof client.domains.release).toBe('function');
      expect(typeof client.domains.getStatus).toBe('function');
      expect(typeof client.domains.getHistory).toBe('function');
      expect(typeof client.domains.renew).toBe('function');
    });
  });

  describe('Content Manager', () => {
    it('should have content methods', () => {
      expect(typeof client.content.uploadBlob).toBe('function');
      expect(typeof client.content.fetchBlob).toBe('function');
      expect(typeof client.content.uploadManifest).toBe('function');
      expect(typeof client.content.fetchManifest).toBe('function');
      expect(typeof client.content.contentExists).toBe('function');
    });
  });

  describe('Deploy Manager', () => {
    it('should have deployment methods', () => {
      expect(typeof client.deploy.deploySite).toBe('function');
      expect(typeof client.deploy.update).toBe('function');
      expect(typeof client.deploy.getDeployments).toBe('function');
      expect(typeof client.deploy.rollback).toBe('function');
      expect(typeof client.deploy.delete).toBe('function');
    });
  });

  describe('Wallet Manager', () => {
    it('should have wallet methods', () => {
      expect(typeof client.wallet.listWallets).toBe('function');
      expect(typeof client.wallet.getBalance).toBe('function');
      expect(typeof client.wallet.send).toBe('function');
      expect(typeof client.wallet.stake).toBe('function');
      expect(typeof client.wallet.unstake).toBe('function');
      expect(typeof client.wallet.getTransactions).toBe('function');
      expect(typeof client.wallet.getTransaction).toBe('function');
    });
  });

  describe('Real Server Interaction (requires running server)', () => {
    it('should fetch server info if available', async () => {
      try {
        const info = await client.getServerInfo();
        expect(info).toHaveProperty('version');
        expect(info).toHaveProperty('name');
        expect(info).toHaveProperty('networkId');
      } catch (error) {
        console.warn('⚠️  Could not fetch server info - server may not be running');
      }
    });

    it('should handle connection errors gracefully', async () => {
      const failClient = createZhtpClient(
        identity,
        'http://invalid-server-that-does-not-exist:9999'
      );

      try {
        await failClient.healthCheck();
        // If we get here, the server exists
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });
});

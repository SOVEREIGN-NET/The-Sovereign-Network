import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { ZhtpQuicClient } from '../../src/quic/client.js';
import { createIdentity } from '../../src/identity.js';
import { MockOutput } from '../../src/output.js';

/**
 * Unit tests for channel binding capture functionality
 * Tests the waitForExporterSecret and captureChannelBinding methods
 */
describe('Channel Binding Tests', () => {
  let testKeylogPath: string;
  let client: ZhtpQuicClient;
  let output: MockOutput;

  beforeEach(() => {
    // Create a unique temp file path for each test
    testKeylogPath = path.join(os.tmpdir(), `test-keylog-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.log`);
    
    // Create test identity
    const testPublicKey = '0123456789abcdef0123456789abcdef';
    const testPrivateKeyMaterial = {
      dilithiumSk: 'base64_dilithium_sk',
      kyberSk: 'base64_kyber_sk',
      masterSeed: 'base64_master_seed',
    };
    const loadedIdentity = createIdentity('test-id', testPublicKey, testPrivateKeyMaterial);
    
    output = new MockOutput();
    
    // Create a test client
    client = new ZhtpQuicClient(
      loadedIdentity.identity,
      loadedIdentity.keypair,
      { mode: 'trust-on-first-use', verifyCallback: undefined },
      'localhost:9334',
      output,
      { timeout: 1000, debug: false }
    );
  });

  afterEach(async () => {
    // Clean up test keylog file
    try {
      await fs.unlink(testKeylogPath);
    } catch {
      // Ignore if file doesn't exist
    }
  });

  describe('waitForExporterSecret', () => {
    it('should parse valid EXPORTER_SECRET line correctly', async () => {
      // Write a valid keylog file with EXPORTER_SECRET
      const validSecret = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      const keylogContent = `# TLS Keylog File
CLIENT_RANDOM abc123 def456
EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}
CLIENT_RANDOM xyz789 uvw012`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      // Use reflection to access private method for testing
      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      expect(result).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(result).toString('hex')).toBe(validSecret);
    });

    it('should handle timeout when secret is not found', async () => {
      // Create empty keylog file
      await fs.writeFile(testKeylogPath, '', 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      
      // This should timeout after 8000ms (CHANNEL_BINDING_TIMEOUT_MS)
      await expect(
        waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding')
      ).rejects.toThrow(/not available within/);
    }, 10000); // Allow 10 seconds for this test

    it('should ignore malformed EXPORTER_SECRET lines', async () => {
      // Write keylog with malformed lines followed by a valid one
      const validSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const keylogContent = `EXPORTER_SECRET zhtp-uhp-channel-binding
EXPORTER_SECRET zhtp-uhp-channel-binding 
EXPORTER_SECRET
EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      expect(result).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(result).toString('hex')).toBe(validSecret);
    });

    it('should handle non-existent file gracefully', async () => {
      const nonExistentPath = path.join(os.tmpdir(), 'non-existent-keylog.log');
      
      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      
      // Should timeout without crashing
      await expect(
        waitForExporterSecret(nonExistentPath, 'zhtp-uhp-channel-binding')
      ).rejects.toThrow(/not available within/);
    }, 10000); // Allow 10 seconds for this test

    it('should handle empty file', async () => {
      await fs.writeFile(testKeylogPath, '', 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      
      await expect(
        waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding')
      ).rejects.toThrow(/not available within/);
    }, 10000); // Allow 10 seconds for this test

    it('should handle file with only whitespace', async () => {
      await fs.writeFile(testKeylogPath, '   \n\n  \n   ', 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      
      await expect(
        waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding')
      ).rejects.toThrow(/not available within/);
    }, 10000); // Allow 10 seconds for this test

    it('should find secret in file with multiple labels', async () => {
      const secret1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const secret2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const keylogContent = `EXPORTER_SECRET other-label ${secret1}
EXPORTER_SECRET zhtp-uhp-channel-binding ${secret2}
EXPORTER_SECRET another-label ${secret1}`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      expect(Buffer.from(result).toString('hex')).toBe(secret2);
    });

    it('should return most recent matching secret when multiple exist', async () => {
      const oldSecret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const newSecret = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const keylogContent = `EXPORTER_SECRET zhtp-uhp-channel-binding ${oldSecret}
EXPORTER_SECRET zhtp-uhp-channel-binding ${newSecret}`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      // Should return the most recent (last) one
      expect(Buffer.from(result).toString('hex')).toBe(newSecret);
    });

    it('should handle secrets with different hex lengths', async () => {
      const shortSecret = 'abcd';
      const keylogContent = `EXPORTER_SECRET zhtp-uhp-channel-binding ${shortSecret}`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      expect(Buffer.from(result).toString('hex')).toBe(shortSecret);
      expect(result.length).toBe(2); // 2 bytes from 4 hex chars
    });

    it('should handle Windows-style line endings', async () => {
      const validSecret = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
      const keylogContent = `EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}\r\n`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      expect(Buffer.from(result).toString('hex')).toBe(validSecret);
    });

    it('should ignore lines with invalid hex characters', async () => {
      const validSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const keylogContent = `EXPORTER_SECRET zhtp-uhp-channel-binding INVALID_HEX_CHARS
EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}`;

      await fs.writeFile(testKeylogPath, keylogContent, 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const result = await waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      // Should skip invalid hex and find the valid one
      expect(Buffer.from(result).toString('hex')).toBe(validSecret);
    });

    it('should handle polling behavior by adding secret after initial read', async () => {
      // Start with empty file
      await fs.writeFile(testKeylogPath, '', 'utf8');

      const waitForExporterSecret = (client as any).waitForExporterSecret.bind(client);
      const resultPromise = waitForExporterSecret(testKeylogPath, 'zhtp-uhp-channel-binding');

      // After a short delay, append the secret
      setTimeout(async () => {
        const validSecret = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
        await fs.appendFile(testKeylogPath, `EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}\n`, 'utf8');
      }, 200);

      const result = await resultPromise;
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('captureChannelBinding', () => {
    it('should throw error when keylog path is not initialized', async () => {
      const captureChannelBinding = (client as any).captureChannelBinding.bind(client);
      
      // keylogPath should be null initially
      await expect(captureChannelBinding()).rejects.toThrow(/TLS keylog path was not initialized/);
    });

    it('should successfully capture channel binding when keylog is available', async () => {
      // Set up the keylog path on the client
      (client as any).keylogPath = testKeylogPath;

      const validSecret = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
      await fs.writeFile(testKeylogPath, `EXPORTER_SECRET zhtp-uhp-channel-binding ${validSecret}\n`, 'utf8');

      const captureChannelBinding = (client as any).captureChannelBinding.bind(client);
      await captureChannelBinding();

      // Check that channelBinding was set
      const channelBinding = (client as any).channelBinding;
      expect(channelBinding).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(channelBinding).toString('hex')).toBe(validSecret);
    });
  });
});

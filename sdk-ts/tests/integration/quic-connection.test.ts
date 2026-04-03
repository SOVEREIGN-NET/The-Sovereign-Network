/**
 * Integration tests for QUIC connection with real ZHTP node
 * These tests require a running ZHTP node on localhost:2048
 * Run with: npm run test:integration
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ZhtpQuicClient } from '../../src/quic/client.js';
import { ZhtpIdentity } from '../../src/identity.js';
import { Output } from '../../src/output.js';

describe('QUIC Connection Integration Tests', () => {
  let client: ZhtpQuicClient | null = null;
  let identity: ZhtpIdentity | null = null;
  let output: Output;

  // Check if ZHTP node is available
  const isZhtpNodeAvailable = async (): Promise<boolean> => {
    try {
      const response = await fetch('http://localhost:2048/api/v1/health');
      return response.ok;
    } catch {
      return false;
    }
  };

  beforeAll(async () => {
    // Skip tests if no ZHTP node is available
    const available = await isZhtpNodeAvailable();
    if (!available) {
      console.log(
        'Skipping QUIC integration tests - ZHTP node not available on localhost:2048',
      );
      return;
    }

    // Create output handler
    output = new Output({
      debug: process.env.DEBUG === 'true',
      prefix: '[QUIC-Test]',
    });

    // Create test identity (would load from keystore in real usage)
    identity = new ZhtpIdentity(
      'did:zhtp:test_client_' + Date.now().toString(16),
    );
  });

  afterAll(async () => {
    if (client) {
      try {
        await client.disconnect();
      } catch {
        // Ignore errors during cleanup
      }
    }
  });

  it('should skip tests if ZHTP node unavailable', async () => {
    const available = await isZhtpNodeAvailable();
    if (!available) {
      console.log('ZHTP node not available - tests skipped');
      expect(true).toBe(true);
      return;
    }

    expect(available).toBe(true);
  });

  it('should establish QUIC connection with UHP handshake', async () => {
    const available = await isZhtpNodeAvailable();
    if (!available || !identity) {
      console.log('Skipping - ZHTP node not available or identity not initialized');
      return;
    }

    client = new ZhtpQuicClient(
      identity,
      { publicKey: new Uint8Array(32), secretKey: new Uint8Array(64) },
      { mode: 'trust-on-first-use', verifyCallback: undefined },
      'localhost:2048',
      output,
      { timeout: 10000, debug: true },
    );

    const result = await client.connect();

    expect(result.connected).toBe(true);
    expect(result.error).toBeUndefined();
    expect(client.isConnected()).toBe(true);
    expect(client.getSessionId()).toBeTruthy();
  });

  it('should make authenticated requests over QUIC', async () => {
    const available = await isZhtpNodeAvailable();
    if (!available || !client || !client.isConnected()) {
      console.log('Skipping - QUIC connection not established');
      return;
    }

    // Make a test GET request
    const response = await client.request('GET', '/api/v1/health');

    expect(response).toBeDefined();
    expect(response.status).toBeGreaterThanOrEqual(200);
    expect(response.status).toBeLessThan(500);
  });

  it('should handle multiple requests in sequence', async () => {
    const available = await isZhtpNodeAvailable();
    if (!available || !client || !client.isConnected()) {
      console.log('Skipping - QUIC connection not established');
      return;
    }

    // Make multiple requests
    for (let i = 0; i < 3; i++) {
      const response = await client.request('GET', '/api/v1/health');
      expect(response.status).toBeGreaterThanOrEqual(200);
      expect(response.status).toBeLessThan(500);
    }
  });

  it('should properly close QUIC connection', async () => {
    if (!client) {
      console.log('Skipping - client not initialized');
      return;
    }

    await client.disconnect();
    expect(client.isConnected()).toBe(false);
  });

  it('should handle connection timeout correctly', async () => {
    const available = await isZhtpNodeAvailable();
    if (!available || !identity) {
      console.log('Skipping - ZHTP node not available');
      return;
    }

    const timeoutClient = new ZhtpQuicClient(
      identity,
      { publicKey: new Uint8Array(32), secretKey: new Uint8Array(64) },
      { mode: 'trust-on-first-use', verifyCallback: undefined },
      'localhost:9999', // Non-existent port
      output,
      { timeout: 1000, debug: false },
    );

    const result = await timeoutClient.connect();
    expect(result.connected).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('should validate port numbers correctly', async () => {
    if (!identity) {
      console.log('Skipping - identity not initialized');
      return;
    }

    // Test invalid port
    const invalidClient = new ZhtpQuicClient(
      identity,
      { publicKey: new Uint8Array(32), secretKey: new Uint8Array(64) },
      { mode: 'trust-on-first-use', verifyCallback: undefined },
      'localhost:99999', // Invalid port (> 65535)
      output,
      { timeout: 1000, debug: false },
    );

    const result = await invalidClient.connect();
    expect(result.connected).toBe(false);
    expect(result.error).toBeDefined();
  });
});

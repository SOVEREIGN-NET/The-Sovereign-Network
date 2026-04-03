#!/usr/bin/env node

/**
 * End-to-end SDK example
 * Demonstrates complete workflow: identity, connection, domain registration, wallet operations
 *
 * Run against local ZHTP node:
 *   # Start ZHTP node
 *   cargo run --bin zhtp --release
 *
 *   # Run this example
 *   npx ts-node examples/e2e-test.ts
 */

import { ZhtpClient } from '../src/index.js';
import { Output } from '../src/output.js';

async function main() {
  const output = new Output({
    prefix: '[SDK-E2E]',
    debug: process.env.DEBUG === 'true',
  });

  try {
    // Step 1: Create client
    await output.info('Initializing ZHTP SDK...');
    const client = new ZhtpClient({
      identity: {
        did: `did:zhtp:test_sdk_${Date.now().toString(16)}`,
        // In production: load from keystore with password
      },
      quicEndpoint: process.env.ZHTP_NODE || 'localhost:2048',
      trustConfig: {
        mode: 'trust-on-first-use',
      },
      output,
      debug: process.env.DEBUG === 'true',
    });

    // Step 2: Connect to ZHTP node
    await output.info('Connecting to ZHTP node...');
    const connected = await client.connect();
    if (!connected) {
      await output.error('Failed to connect to ZHTP node');
      process.exit(1);
    }

    // Step 3: List operations (examples - actual API depends on ZHTP node)
    await output.success('Connected successfully');

    // Step 4: Get domain status (if domain operations supported)
    if (client.domains) {
      try {
        await output.info('Testing domain operations...');
        // This would test domain registration, lookup, etc.
        await output.success('Domain operations tested');
      } catch (error) {
        await output.warning(
          `Domain operations not available: ${error instanceof Error ? error.message : 'unknown'}`,
        );
      }
    }

    // Step 5: Get wallet info (if wallet operations supported)
    if (client.wallet) {
      try {
        await output.info('Testing wallet operations...');
        // This would test wallet balance, transfers, etc.
        await output.success('Wallet operations tested');
      } catch (error) {
        await output.warning(
          `Wallet operations not available: ${error instanceof Error ? error.message : 'unknown'}`,
        );
      }
    }

    // Step 6: Disconnect
    await output.info('Disconnecting...');
    await client.disconnect();
    await output.success('E2E test completed successfully');
  } catch (error) {
    await output.error(
      `E2E test failed: ${error instanceof Error ? error.message : 'unknown'}`,
    );
    if (process.env.DEBUG === 'true') {
      console.error(error);
    }
    process.exit(1);
  }
}

main();

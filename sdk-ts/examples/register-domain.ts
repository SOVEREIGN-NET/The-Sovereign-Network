/**
 * Example: Register a Domain
 *
 * This example shows how to register a new domain on ZHTP.
 *
 * Usage:
 *   npx ts-node examples/register-domain.ts
 */

import { IdentityManager, createZhtpClient } from '../src/index.js';

async function main() {
  // Configuration
  const publicKey = process.env.PUBLIC_KEY || 'your-public-key-hex';
  const apiUrl = process.env.API_URL || 'http://localhost:8080';
  const domainName = process.env.DOMAIN || 'myapp.zhtp';

  console.log('ZHTP Domain Registration Example\n');
  console.log(`API URL: ${apiUrl}`);
  console.log(`Domain: ${domainName}\n`);

  // Create identity from public key
  const identity = IdentityManager.fromPublicKey(publicKey);
  console.log(`Identity DID: ${identity.getDid()}\n`);

  // Create client
  const client = createZhtpClient(identity, apiUrl, { debug: true });

  try {
    // Check server connectivity
    console.log('Checking server connectivity...');
    const isHealthy = await client.healthCheck();
    console.log(`Server status: ${isHealthy ? '✅ Online' : '❌ Offline'}\n`);

    if (!isHealthy) {
      console.error('Server is not responding. Make sure ZHTP server is running.');
      return;
    }

    // Check domain availability
    console.log(`Checking if ${domainName} is available...`);
    const available = await client.domains.check(domainName);

    if (!available) {
      console.error(`❌ Domain ${domainName} is already registered.`);
      return;
    }

    console.log(`✅ Domain is available!\n`);

    // Register domain
    console.log(`Registering domain ${domainName}...`);
    const result = await client.domains.register(domainName, {
      fee: 1080, // Standard fee for 5+ char domains
      metadata: {
        description: 'My awesome ZHTP domain',
        author: 'developer@example.com',
      },
    });

    console.log('\n✅ Domain registered successfully!\n');
    console.log('Registration details:');
    console.log(`  Domain:          ${result.domain}`);
    console.log(`  Owner:           ${result.owner}`);
    console.log(`  Registered at:   ${new Date(result.registeredAt).toISOString()}`);
    console.log(`  Expires at:      ${new Date(result.expiresAt).toISOString()}`);
    console.log(`  Transaction:     ${result.transactionHash}`);

    // Get domain info
    console.log('\nFetching domain info...');
    const info = await client.domains.getInfo(domainName);

    console.log('\nDomain information:');
    console.log(`  Domain:         ${info.domain}`);
    console.log(`  Owner:          ${info.owner}`);
    console.log(`  Content CID:    ${info.contentCid}`);
    console.log(`  Content Version: ${info.contentVersion}`);
    console.log(`  Expires:        ${new Date(info.expiresAt).toISOString()}`);

    // Get domain history
    console.log('\nFetching domain history...');
    const history = await client.domains.getHistory(domainName);

    console.log(`\nDomain history (${history.totalEvents} events):`);
    history.events.forEach((event, i) => {
      console.log(
        `  ${i + 1}. ${event.type.toUpperCase()} - ${new Date(event.timestamp).toISOString()}`
      );
      console.log(`     From: ${event.from}`);
      if (event.to) console.log(`     To: ${event.to}`);
    });

    console.log('\n✅ Example completed successfully!');
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : error);
    if (error instanceof Error && 'body' in error) {
      console.error('Details:', (error as any).body);
    }
  }
}

main().catch(console.error);

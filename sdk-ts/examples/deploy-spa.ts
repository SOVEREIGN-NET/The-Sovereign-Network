/**
 * Example: Deploy a Single Page Application (SPA)
 *
 * This example shows how to deploy a built React/Vue/Svelte app to ZHTP.
 *
 * Usage:
 *   npx ts-node examples/deploy-spa.ts
 *
 * Environment variables:
 *   PUBLIC_KEY  - Your public key (hex-encoded)
 *   DOMAIN      - Domain to deploy to (e.g., myapp.zhtp)
 *   BUILD_DIR   - Directory containing built files (default: ./dist)
 *   API_URL     - ZHTP API server URL (default: http://localhost:8080)
 */

import { IdentityManager, createZhtpClient } from '../src/index.js';

async function main() {
  // Configuration from environment
  const publicKey = process.env.PUBLIC_KEY || 'your-public-key-hex';
  const apiUrl = process.env.API_URL || 'http://localhost:8080';
  const domainName = process.env.DOMAIN || 'myapp.zhtp';
  const buildDir = process.env.BUILD_DIR || './dist';

  console.log('ZHTP SPA Deployment Example\n');
  console.log(`API URL:    ${apiUrl}`);
  console.log(`Domain:     ${domainName}`);
  console.log(`Build Dir:  ${buildDir}\n`);

  // Create identity
  const identity = IdentityManager.fromPublicKey(publicKey);
  console.log(`Identity: ${identity.getDid()}\n`);

  // Create client
  const client = createZhtpClient(identity, apiUrl);

  try {
    // Check server connectivity
    console.log('🔍 Checking server connectivity...');
    const isHealthy = await client.healthCheck();

    if (!isHealthy) {
      console.error('❌ Server is not responding.');
      return;
    }

    console.log('✅ Server is online\n');

    // Get server info
    console.log('📋 Getting server information...');
    const serverInfo = await client.getServerInfo();
    console.log(`   Version: ${serverInfo.version}`);
    console.log(`   Network: ${serverInfo.networkId}\n`);

    // Deploy with progress tracking
    console.log(`🚀 Deploying ${domainName}...\n`);

    const deployment = await client.deploy.deploySite(
      domainName,
      buildDir,
      'spa',
      (progress) => {
        // Show progress bar
        const barLength = 40;
        const filledLength = Math.round((barLength * progress.percentage) / 100);
        const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
        console.log(
          `[${bar}] ${progress.percentage.toFixed(0)}% - ${progress.status}`
        );
      },
      {
        name: 'My SPA',
        description: 'Deployed via @zhtp/sdk',
        author: 'developer@example.com',
      }
    );

    console.log('\n✅ Deployment successful!\n');
    console.log('Deployment details:');
    console.log(`  Domain:       ${deployment.domain}`);
    console.log(`  URL:          ${deployment.url}`);
    console.log(`  Manifest CID: ${deployment.manifestCid}`);
    console.log(`  Version:      ${deployment.version}`);
    console.log(`  Files:        ${deployment.filesDeployed}`);
    console.log(`  Total Size:   ${(deployment.totalSize / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Deployed At:  ${new Date(deployment.deployedAt).toISOString()}`);

    // Get deployment info
    console.log('\n📦 Fetching deployment information...');
    const deployments = await client.deploy.getDeployments(domainName);

    console.log(`\nDeployment history (${deployments.length} versions):`);
    deployments.forEach((d, i) => {
      console.log(
        `  v${d.version} - ${new Date(d.deployedAt).toISOString()} (${d.filesCount} files, ${(d.totalSize / 1024).toFixed(0)} KB)`
      );
    });

    console.log('\n💡 Next steps:');
    console.log(`   1. Visit: ${deployment.url}`);
    console.log('   2. Share the URL with friends');
    console.log(`   3. Update: npx ts-node examples/deploy-spa.ts`);
    console.log(`   4. Rollback: client.deploy.rollback("${domainName}", 1)`);

    console.log('\n✅ Example completed successfully!');
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : error);
    if (error instanceof Error && 'body' in error) {
      console.error('Details:', (error as any).body);
    }
  }
}

main().catch(console.error);

/**
 * Deploy Breakroom website to breakroom.sov using ZHTP SDK
 */
import { initializeClient, buildTrustConfig, loadIdentityFromKeystore, ConsoleOutput } from './dist/index.js';
import * as path from 'path';
import * as os from 'os';

// Configuration
const ZHTP_PROD_ENDPOINT = process.env.ZHTP_PROD_ENDPOINT ?? '77.42.37.161:9334';
const DOMAIN = process.env.BREAKROOM_DOMAIN ?? 'breakroom.sov';
const DEFAULT_BUILD_DIR = path.join('..', 'Breakroom-Employee-Dapp', 'out');
const BUILD_DIR = process.env.BREAKROOM_BUILD_DIR
  ? path.resolve(process.env.BREAKROOM_BUILD_DIR)
  : path.resolve(DEFAULT_BUILD_DIR);

async function main() {
  const output = new ConsoleOutput();

  console.log('==========================================');
  console.log('  ZHTP SDK - Breakroom Website Deployment');
  console.log('==========================================\n');

  // Step 1: Load identity from keystore
  const keystorePath = path.join(os.homedir(), '.zhtp', 'keystore');
  console.log('Step 1: Loading identity from keystore...');
  console.log('  Keystore path:', keystorePath);

  const loaded = await loadIdentityFromKeystore(keystorePath);
  console.log('  Identity ID:', loaded.identity.id);
  console.log('  DID:', loaded.identity.did);
  console.log('  Has Dilithium PK:', !!loaded.keypair.dilithiumPk);
  console.log('  Has Kyber PK:', !!loaded.keypair.kyberPk);
  console.log('');

  // Step 2: Build trust configuration
  console.log('Step 2: Building trust configuration...');
  const trustConfig = buildTrustConfig({
    mode: 'bootstrap',
  });
  console.log('  Trust mode:', trustConfig.mode);
  console.log('');

  // Step 3: Connect to ZHTP server with authenticated QUIC
  console.log('Step 3: Connecting to ZHTP server...');
  console.log('  Endpoint:', ZHTP_PROD_ENDPOINT);

  try {
    const client = await initializeClient(
      loaded.identity,
      loaded.keypair,
      trustConfig,
      ZHTP_PROD_ENDPOINT,
      output,
    );

    console.log('\n  Connected successfully!');
    console.log('  Session ID:', client.getSessionId()?.slice(0, 16) + '...');
    console.log('');

    // Step 4: Deploy the site
    console.log('Step 4: Deploying site to', DOMAIN);
    console.log('  Build directory:', BUILD_DIR);
    console.log('');

    const result = await client.deploy.deploySite({
      domain: DOMAIN,
      buildDir: BUILD_DIR,
      mode: 'spa',
      indexFile: 'index.html',
      exclude: ['.txt', '__next.'],  // Exclude Next.js debug files
    });

    console.log('\n==========================================');
    console.log('  DEPLOYMENT COMPLETE');
    console.log('==========================================');
    console.log('  Domain:', result.domain);
    console.log('  URL:', result.url);
    console.log('  Manifest CID:', result.manifestCid);
    console.log('  Files uploaded:', result.fileCount);
    console.log('  Total size:', (result.totalSize / 1024 / 1024).toFixed(2), 'MB');
    console.log('==========================================\n');

    // Cleanup
    await client.disconnect();
  } catch (error) {
    console.error('\nDeployment failed:', error);
    process.exit(1);
  }
}

main();

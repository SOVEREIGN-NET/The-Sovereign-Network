/**
 * Test script to verify keystore loading works
 */
import { loadIdentityFromKeystore } from './src/identity.js';
import * as path from 'path';
import * as os from 'os';

async function main() {
  const keystorePath = path.join(os.homedir(), '.zhtp', 'keystore');

  console.log('Loading identity from:', keystorePath);

  try {
    const loaded = await loadIdentityFromKeystore(keystorePath);

    console.log('\n✅ Identity loaded successfully!');
    console.log('  ID:', loaded.identity.id);
    console.log('  DID:', loaded.identity.did);
    console.log('  Public Key:', loaded.identity.publicKey.substring(0, 32) + '...');
    console.log('  Created At:', new Date(loaded.identity.createdAt * 1000).toISOString());
    console.log('  Is Active:', loaded.identity.isActive);
    console.log('\n  KeyPair:');
    console.log('    Dilithium SK length:', loaded.keypair.privateKey.dilithiumSk.length, 'chars (base64)');
    console.log('    Kyber SK length:', loaded.keypair.privateKey.kyberSk.length, 'chars (base64)');
    console.log('    Master Seed length:', loaded.keypair.privateKey.masterSeed.length, 'chars (base64)');
    if (loaded.keypair.dilithiumPk) {
      console.log('    Dilithium PK length:', loaded.keypair.dilithiumPk.length, 'chars (base64)');
    }
    if (loaded.keypair.kyberPk) {
      console.log('    Kyber PK length:', loaded.keypair.kyberPk.length, 'chars (base64)');
    }
  } catch (error) {
    console.error('❌ Failed to load identity:', error);
    process.exit(1);
  }
}

main();

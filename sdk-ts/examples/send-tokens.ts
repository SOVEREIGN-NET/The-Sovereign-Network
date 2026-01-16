/**
 * Example: Send Tokens and Check Balance
 *
 * This example shows how to manage wallet operations on ZHTP.
 *
 * Usage:
 *   npx ts-node examples/send-tokens.ts
 *
 * Environment variables:
 *   PUBLIC_KEY      - Your public key (hex-encoded)
 *   RECIPIENT       - Recipient address
 *   AMOUNT          - Amount to send in ZHTP
 *   API_URL         - ZHTP API server URL (default: http://localhost:8080)
 */

import { IdentityManager, createZhtpClient } from '../src/index.js';

async function main() {
  // Configuration from environment
  const publicKey = process.env.PUBLIC_KEY || 'your-public-key-hex';
  const apiUrl = process.env.API_URL || 'http://localhost:8080';
  const recipientAddress = process.env.RECIPIENT || 'recipient-address-here';
  const amount = parseInt(process.env.AMOUNT || '100', 10);

  console.log('ZHTP Wallet Operations Example\n');
  console.log(`API URL:           ${apiUrl}`);
  console.log(`Recipient:         ${recipientAddress}`);
  console.log(`Amount to Send:    ${amount} ZHTP\n`);

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

    // List wallets
    console.log('📊 Listing wallets...');
    const wallets = await client.wallet.listWallets();

    if (wallets.length === 0) {
      console.log('No wallets found for this identity.');
      return;
    }

    console.log(`Found ${wallets.length} wallet(s):\n`);
    wallets.forEach((wallet) => {
      console.log(`  📍 ${wallet.walletType.toUpperCase()}`);
      console.log(`     Address:  ${wallet.address}`);
      console.log(`     Balance:  ${wallet.balance} ZHTP`);
      if (wallet.stakedAmount) {
        console.log(`     Staked:   ${wallet.stakedAmount} ZHTP`);
      }
      if (wallet.pendingUnstake) {
        console.log(`     Pending:  ${wallet.pendingUnstake} ZHTP`);
      }
      console.log();
    });

    // Get primary wallet balance
    console.log('💰 Getting primary wallet balance...');
    const balance = await client.wallet.getBalance();

    console.log(`\nBalance information:`);
    console.log(`  Address:      ${balance.address}`);
    console.log(`  Balance:      ${balance.balance} ZHTP`);
    if (balance.stakedAmount) {
      console.log(`  Staked:       ${balance.stakedAmount} ZHTP`);
    }
    if (balance.pendingUnstake) {
      console.log(`  Pending:      ${balance.pendingUnstake} ZHTP`);
    }
    console.log(`  Last Updated: ${new Date(balance.lastUpdated).toISOString()}`);

    // Check if we have enough balance
    if (balance.balance < amount) {
      console.error(
        `\n❌ Insufficient balance. Need ${amount} ZHTP but only have ${balance.balance} ZHTP`
      );
      return;
    }

    // Estimate fee
    console.log('\n📈 Estimating transaction fee...');
    const estimatedFee = await client.wallet.estimateFee(amount);
    console.log(`   Estimated fee: ${estimatedFee} ZHTP`);
    console.log(`   Total cost:    ${amount + estimatedFee} ZHTP\n`);

    // Send tokens
    console.log(`💸 Sending ${amount} ZHTP to ${recipientAddress}...`);
    const txHash = await client.wallet.send(recipientAddress, amount, undefined, {
      memo: 'Payment via @zhtp/sdk example',
    });

    console.log(`\n✅ Transaction sent!\n`);
    console.log(`Transaction Hash: ${txHash}\n`);

    // Get transaction details
    console.log('📋 Fetching transaction details...');
    const tx = await client.wallet.getTransaction(txHash);

    console.log(`\nTransaction details:`);
    console.log(`  Hash:        ${tx.transactionHash}`);
    console.log(`  Status:      ${tx.status}`);
    console.log(`  From:        ${tx.from}`);
    console.log(`  To:          ${tx.to}`);
    console.log(`  Amount:      ${tx.amount} ZHTP`);
    console.log(`  Fee:         ${tx.fee} ZHTP`);
    console.log(`  Timestamp:   ${new Date(tx.timestamp).toISOString()}`);
    if (tx.blockNumber) {
      console.log(`  Block:       ${tx.blockNumber}`);
    }
    if (tx.confirmations) {
      console.log(`  Confirmations: ${tx.confirmations}`);
    }

    // Get transaction history
    console.log('\n📜 Fetching recent transactions...');
    const transactions = await client.wallet.getTransactions(undefined, 5);

    console.log(`\nRecent transactions (${transactions.length}):`);
    transactions.forEach((t, i) => {
      console.log(
        `  ${i + 1}. ${t.type.toUpperCase()} - ${t.amount} ZHTP - ${t.status}`
      );
      console.log(`     Hash: ${t.transactionHash}`);
      console.log(`     Time: ${new Date(t.timestamp).toISOString()}`);
    });

    // Staking example
    console.log('\n\n=== STAKING EXAMPLE ===\n');
    console.log('Staking tokens example (not executed):');
    console.log(`\n  const stakeTx = await client.wallet.stake(1000, {`);
    console.log(`    fee: 10,`);
    console.log(`  });`);
    console.log(`  console.log('Staked! TX:', stakeTx);\n`);

    console.log('Unstaking example (not executed):');
    console.log(`\n  const unstakeTx = await client.wallet.unstake(500);\n`);

    console.log('✅ Example completed successfully!');
  } catch (error) {
    console.error('\n❌ Error:', error instanceof Error ? error.message : error);
    if (error instanceof Error && 'body' in error) {
      console.error('Details:', (error as any).body);
    }
  }
}

main().catch(console.error);

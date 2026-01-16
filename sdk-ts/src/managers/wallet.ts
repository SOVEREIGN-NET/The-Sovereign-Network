/**
 * Wallet Manager - handles all wallet operations
 * Send, receive, stake, check balance, transaction history
 */

import { Output } from '../output.js';
import { WalletError, ValidationError } from '../error.js';
import { ZhtpQuicClient } from '../quic/client.js';
import { WalletOp, WalletInfo, Transaction, getWalletOpConfig } from '../types.js';
import {
  validateWalletAddress,
  validateTransactionAmount,
  validateSufficientBalance,
  calculateTransactionFee,
} from '../validation.js';

/**
 * Wallet Manager
 */
export class WalletManager {
  constructor(private client: ZhtpQuicClient, private output: Output) {}

  /**
   * Get wallet balance
   */
  async getBalance(address: string): Promise<bigint> {
    const validation = validateWalletAddress(address);
    if (!validation.valid) {
      throw new ValidationError('Invalid wallet address', validation.errors);
    }

    await this.output.info(`Checking balance: ${address}`);

    try {
      const config = getWalletOpConfig(WalletOp.Balance);
      const response = await this.client.request('GET', `${config.endpointPath}?address=${address}`);

      if (response.status !== 200) {
        throw new WalletError(`Balance check failed: ${response.status}`, {
          address,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const balance = BigInt(data?.balance || 0);

      await this.output.success(`Balance: ${(Number(balance) / 100_000_000).toFixed(8)} ZHTP`);
      return balance;
    } catch (error) {
      throw new WalletError(`Balance check error: ${error instanceof Error ? error.message : 'unknown'}`, {
        address,
      });
    }
  }

  /**
   * Send tokens
   */
  async send(from: string, to: string, amount: bigint): Promise<string> {
    // Validate
    const fromValidation = validateWalletAddress(from);
    if (!fromValidation.valid) {
      throw new ValidationError('Invalid sender address', fromValidation.errors);
    }

    const toValidation = validateWalletAddress(to);
    if (!toValidation.valid) {
      throw new ValidationError('Invalid recipient address', toValidation.errors);
    }

    const amountValidation = validateTransactionAmount(amount);
    if (!amountValidation.valid) {
      throw new ValidationError('Invalid transaction amount', amountValidation.errors);
    }

    // Calculate fee
    const fee = calculateTransactionFee(128); // Estimate: ~128 byte tx
    const total = amount + fee;

    // Check balance
    const balance = await this.getBalance(from);
    const balanceValidation = validateSufficientBalance(balance, amount, fee);
    if (!balanceValidation.valid) {
      throw new ValidationError('Insufficient balance', balanceValidation.errors, {
        balance,
        amount,
        fee,
        total,
      });
    }

    await this.output.info(`Sending ${(Number(amount) / 100_000_000).toFixed(8)} ZHTP from ${from} to ${to}`);

    try {
      const config = getWalletOpConfig(WalletOp.Transfer);

      const body = {
        from,
        to,
        amount: Number(amount),
        fee: Number(fee),
        timestamp: Math.floor(Date.now() / 1000),
      };

      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new WalletError(`Transfer failed: ${response.status}`, {
          from,
          to,
          amount,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const txHash = data?.txHash || 'pending';

      await this.output.success(`Transfer submitted: ${txHash}`);
      return txHash;
    } catch (error) {
      if (error instanceof ValidationError || error instanceof WalletError) {
        throw error;
      }
      throw new WalletError(`Transfer error: ${error instanceof Error ? error.message : 'unknown'}`, {
        from,
        to,
        amount,
      });
    }
  }

  /**
   * Stake tokens
   */
  async stake(address: string, amount: bigint): Promise<string> {
    const validation = validateWalletAddress(address);
    if (!validation.valid) {
      throw new ValidationError('Invalid wallet address', validation.errors);
    }

    const amountValidation = validateTransactionAmount(amount);
    if (!amountValidation.valid) {
      throw new ValidationError('Invalid stake amount', amountValidation.errors);
    }

    const fee = calculateTransactionFee(64);
    const total = amount + fee;

    const balance = await this.getBalance(address);
    const balanceValidation = validateSufficientBalance(balance, amount, fee);
    if (!balanceValidation.valid) {
      throw new ValidationError('Insufficient balance for staking', balanceValidation.errors);
    }

    await this.output.info(`Staking ${(Number(amount) / 100_000_000).toFixed(8)} ZHTP`);

    try {
      const config = getWalletOpConfig(WalletOp.Stake);

      const body = {
        address,
        amount: Number(amount),
        fee: Number(fee),
      };

      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new WalletError(`Staking failed: ${response.status}`, {
          address,
          amount,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const txHash = data?.txHash || 'pending';

      await this.output.success(`Staking submitted: ${txHash}`);
      return txHash;
    } catch (error) {
      throw new WalletError(`Staking error: ${error instanceof Error ? error.message : 'unknown'}`, {
        address,
        amount,
      });
    }
  }

  /**
   * Unstake tokens
   */
  async unstake(address: string, amount: bigint): Promise<string> {
    const validation = validateWalletAddress(address);
    if (!validation.valid) {
      throw new ValidationError('Invalid wallet address', validation.errors);
    }

    const amountValidation = validateTransactionAmount(amount);
    if (!amountValidation.valid) {
      throw new ValidationError('Invalid unstake amount', amountValidation.errors);
    }

    await this.output.info(`Unstaking ${(Number(amount) / 100_000_000).toFixed(8)} ZHTP`);

    try {
      const config = getWalletOpConfig(WalletOp.Unstake);

      const body = {
        address,
        amount: Number(amount),
      };

      const response = await this.client.request('POST', config.endpointPath, {
        body: new TextEncoder().encode(JSON.stringify(body)),
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new WalletError(`Unstaking failed: ${response.status}`, {
          address,
          amount,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const txHash = data?.txHash || 'pending';

      await this.output.success(`Unstaking submitted: ${txHash}`);
      return txHash;
    } catch (error) {
      throw new WalletError(`Unstaking error: ${error instanceof Error ? error.message : 'unknown'}`, {
        address,
        amount,
      });
    }
  }

  /**
   * Get transaction history
   */
  async getHistory(address: string, limit: number = 50): Promise<Transaction[]> {
    const validation = validateWalletAddress(address);
    if (!validation.valid) {
      throw new ValidationError('Invalid wallet address', validation.errors);
    }

    await this.output.info(`Fetching transaction history: ${address}`);

    try {
      const config = getWalletOpConfig(WalletOp.History);
      const response = await this.client.request('GET', `${config.endpointPath}?address=${address}&limit=${limit}`);

      if (response.status !== 200) {
        throw new WalletError(`History fetch failed: ${response.status}`, {
          address,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const transactions = (data?.transactions || []).map((tx: any) => ({
        hash: tx.hash,
        from: tx.from,
        to: tx.to,
        amount: BigInt(tx.amount),
        fee: BigInt(tx.fee),
        timestamp: tx.timestamp,
        status: tx.status as 'pending' | 'confirmed' | 'failed',
        blockNumber: tx.blockNumber,
        confirmations: tx.confirmations,
      }));

      await this.output.success(`Found ${transactions.length} transactions`);
      return transactions;
    } catch (error) {
      throw new WalletError(`History error: ${error instanceof Error ? error.message : 'unknown'}`, {
        address,
      });
    }
  }

  /**
   * List wallets for identity
   */
  async listWallets(identityId: string): Promise<WalletInfo[]> {
    await this.output.info(`Listing wallets for: ${identityId}`);

    try {
      const config = getWalletOpConfig(WalletOp.List);
      const response = await this.client.request('GET', `${config.endpointPath}?identity=${identityId}`);

      if (response.status !== 200) {
        throw new WalletError(`List failed: ${response.status}`, {
          identityId,
          status: response.status,
        });
      }

      const data = response.data ? JSON.parse(response.data) : null;
      const wallets = (data?.wallets || []).map((w: any) => ({
        address: w.address,
        type: w.type as 'primary' | 'secondary' | 'staking',
        balance: BigInt(w.balance),
        stakedAmount: w.stakedAmount ? BigInt(w.stakedAmount) : undefined,
        pendingUnstake: w.pendingUnstake ? BigInt(w.pendingUnstake) : undefined,
        lastUpdated: w.lastUpdated,
      }));

      await this.output.success(`Found ${wallets.length} wallet(s)`);
      return wallets;
    } catch (error) {
      throw new WalletError(`List error: ${error instanceof Error ? error.message : 'unknown'}`, {
        identityId,
      });
    }
  }
}

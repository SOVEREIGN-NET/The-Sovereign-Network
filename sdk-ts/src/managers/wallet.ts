/**
 * WalletManager - Handles wallet operations and transactions
 */

import { Transport } from '../transport/types.js';
import { IdentityManager } from '../crypto/identity.js';
import {
  Wallet,
  WalletType,
  Balance,
  Transaction,
  SendOptions,
  StakeOptions,
  UnstakeOptions,
  ClientOptions,
} from '../types/domain.js';
import { WalletInfo, TransactionResponse } from '../types/responses.js';

export class WalletManager {
  constructor(
    private transport: Transport,
    private identity: IdentityManager,
    _options: Required<ClientOptions>
  ) {}

  /**
   * List all wallets for an identity
   */
  async listWallets(identityId?: string): Promise<Wallet[]> {
    const id = identityId || this.identity.getId();

    const response = await this.transport.get<WalletInfo[]>(
      `/api/v1/wallet/list?identityId=${encodeURIComponent(id)}`
    );

    return response.body.map((wallet) => ({
      address: wallet.address,
      walletType: wallet.walletType,
      balance: wallet.balance,
      stakedAmount: wallet.stakedAmount,
      pendingUnstake: wallet.pendingUnstake,
      lastUpdated: wallet.lastUpdated,
    }));
  }

  /**
   * Get balance for a wallet
   */
  async getBalance(address?: string, walletType: WalletType = 'primary'): Promise<Balance> {
    const addr = address || (await this.getPrimaryWalletAddress());

    const response = await this.transport.get<Balance>(
      `/api/v1/wallet/balance?address=${encodeURIComponent(addr)}&type=${walletType}`
    );

    return response.body;
  }

  /**
   * Send tokens from one address to another
   */
  async send(
    to: string,
    amount: number,
    from?: string,
    options?: Partial<SendOptions>
  ): Promise<string> {
    const fromAddr = from || (await this.getPrimaryWalletAddress());

    const response = await this.transport.post<TransactionResponse>(
      '/api/v1/wallet/send',
      {
        from: fromAddr,
        to,
        amount,
        publicKey: this.identity.getPublicKey(),
        signature: '', // TODO: Add actual signature
        fee: options?.fee,
        memo: options?.memo,
      }
    );

    return response.body.transactionHash;
  }

  /**
   * Stake tokens
   */
  async stake(amount: number, options?: Partial<StakeOptions>, identityId?: string): Promise<string> {
    const id = identityId || this.identity.getId();

    const response = await this.transport.post<TransactionResponse>(
      '/api/v1/wallet/stake',
      {
        identityId: id,
        amount,
        publicKey: this.identity.getPublicKey(),
        signature: '', // TODO: Add actual signature
        fee: options?.fee,
      }
    );

    return response.body.transactionHash;
  }

  /**
   * Unstake tokens
   */
  async unstake(
    amount: number,
    options?: Partial<UnstakeOptions>,
    identityId?: string
  ): Promise<string> {
    const id = identityId || this.identity.getId();

    const response = await this.transport.post<TransactionResponse>(
      '/api/v1/wallet/unstake',
      {
        identityId: id,
        amount,
        publicKey: this.identity.getPublicKey(),
        signature: '', // TODO: Add actual signature
        fee: options?.fee,
      }
    );

    return response.body.transactionHash;
  }

  /**
   * Get transaction history
   */
  async getTransactions(
    address?: string,
    limit: number = 20,
    offset: number = 0
  ): Promise<Transaction[]> {
    const addr = address || (await this.getPrimaryWalletAddress());

    const response = await this.transport.get<Transaction[]>(
      `/api/v1/wallet/transactions?address=${encodeURIComponent(addr)}&limit=${limit}&offset=${offset}`
    );

    return response.body;
  }

  /**
   * Get transaction details
   */
  async getTransaction(transactionHash: string): Promise<Transaction> {
    const response = await this.transport.get<Transaction>(
      `/api/v1/wallet/transaction/${encodeURIComponent(transactionHash)}`
    );

    return response.body;
  }

  /**
   * Get estimated fee for a transaction
   */
  async estimateFee(amount: number, walletType: WalletType = 'primary'): Promise<number> {
    const response = await this.transport.get<{ estimatedFee: number }>(
      `/api/v1/wallet/estimate-fee?amount=${amount}&type=${walletType}`
    );

    return response.body.estimatedFee;
  }

  /**
   * Check if address exists
   */
  async addressExists(address: string): Promise<boolean> {
    try {
      const response = await this.transport.get<{ exists: boolean }>(
        `/api/v1/wallet/exists?address=${encodeURIComponent(address)}`
      );
      return response.body.exists;
    } catch {
      return false;
    }
  }

  /**
   * Get wallet info for multiple addresses
   */
  async getWalletsBatch(addresses: string[]): Promise<Map<string, Wallet>> {
    const results = new Map<string, Wallet>();

    for (const address of addresses) {
      try {
        const balance = await this.getBalance(address);
        results.set(address, {
          address: balance.address,
          walletType: 'primary',
          balance: balance.balance,
          stakedAmount: balance.stakedAmount,
          pendingUnstake: balance.pendingUnstake,
          lastUpdated: balance.lastUpdated,
        });
      } catch (error) {
        // Skip addresses that don't exist
      }
    }

    return results;
  }

  /**
   * Get primary wallet address for the current identity
   */
  private async getPrimaryWalletAddress(): Promise<string> {
    const wallets = await this.listWallets();
    const primaryWallet = wallets.find((w) => w.walletType === 'primary');

    if (!primaryWallet) {
      throw new Error('No primary wallet found for this identity');
    }

    return primaryWallet.address;
  }
}

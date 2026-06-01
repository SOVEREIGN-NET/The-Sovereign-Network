use super::*;

impl Blockchain {
    /// Process contract deployment and execution transactions from a block.
    pub fn process_contract_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type == TransactionType::ContractDeployment {
                if let Some(output) = transaction.outputs.first() {
                    if let Ok(web4_contract) = serde_json::from_slice::<
                        crate::contracts::web4::Web4Contract,
                    >(output.commitment.as_bytes())
                    {
                        let contract_id = lib_crypto::hash_blake3(web4_contract.domain.as_bytes());
                        self.register_web4_contract(contract_id, web4_contract, block.height());
                        info!(" Processed Web4Contract deployment in block {}", block.height());
                    } else if let Ok(token_contract) =
                        bincode::deserialize::<crate::contracts::TokenContract>(
                            output.commitment.as_bytes(),
                        )
                    {
                        let contract_id = token_contract.token_id;
                        self.register_token_contract(contract_id, token_contract, block.height());
                        info!(" Processed TokenContract deployment in block {}", block.height());
                    } else {
                        debug!(
                            " Could not deserialize contract in transaction {}",
                            transaction.hash()
                        );
                    }
                }
            } else if transaction.transaction_type == TransactionType::ContractExecution {
                if let Err(e) = self.process_contract_execution(transaction, block.height()) {
                    if Self::is_forbidden_contract_execution_transfer(transaction) {
                        return Err(anyhow::anyhow!(
                            "ContractExecution/transfer is prohibited — use TokenTransfer transactions instead"
                        ));
                    }
                    warn!(
                        "ContractExecution rejected (tx {}): {}",
                        transaction.hash(),
                        e
                    );
                }
            }
        }
        Ok(())
    }

    fn is_forbidden_contract_execution_transfer(transaction: &Transaction) -> bool {
        if transaction.transaction_type != TransactionType::ContractExecution {
            return false;
        }

        let call = if transaction
            .memo
            .starts_with(crate::transaction::CONTRACT_EXECUTION_MEMO_PREFIX_V2)
        {
            match crate::transaction::DecodedContractExecutionMemo::decode_compat(&transaction.memo)
            {
                Ok(decoded) => decoded.call,
                Err(_) => return false,
            }
        } else {
            if transaction.memo.len() <= 4 || &transaction.memo[0..4] != b"ZHTP" {
                return false;
            }
            let call_data = &transaction.memo[4..];
            let deserialized: Result<
                (
                    crate::types::ContractCall,
                    crate::integration::crypto_integration::Signature,
                ),
                _,
            > = bincode::deserialize(call_data);
            match deserialized {
                Ok((call, _sig)) => call,
                Err(_) => return false,
            }
        };

        call.contract_type == crate::types::ContractType::Token && call.method == "transfer"
    }

    /// Rebuild the PoUW reward mint index from all in-memory blocks.
    ///
    /// Scans every block for `TokenMint` transactions carrying a `pouw:mint:`
    /// memo and records them keyed by recipient key_id. Clears the index
    /// first, so it is idempotent. Called once after chain load — necessary
    /// because `load_from_store` deliberately skips token-tx processing, so
    /// the incremental hook in `process_token_transactions` does not fire on
    /// that path. The per-block hook still keeps the index current for live
    /// block commits.
    pub fn rebuild_pouw_mint_index(&mut self) {
        self.pouw_mint_index.clear();
        let mut total = 0usize;
        // #2636: materialize the full chain (window + sled) up front. iter_blocks()
        // borrows &self, but the loop body mutates self.pouw_mint_index, so we
        // can't iterate it lazily here; the previous `&self.blocks` scan also
        // silently bounded the rebuild to the hot window on a pruned node.
        let blocks: Vec<crate::block::Block> = self.iter_blocks().collect();
        for block in &blocks {
            let height = block.height();
            for tx in &block.transactions {
                if tx.transaction_type != TransactionType::TokenMint {
                    continue;
                }
                if !tx.memo.starts_with(b"pouw:mint:") {
                    continue;
                }
                let Some(mint) = tx.token_mint_data() else {
                    continue;
                };
                let tx_hash = tx.hash().as_array();
                let entry = self.pouw_mint_index.entry(mint.to).or_default();
                if !entry.iter().any(|r| r.tx_hash == tx_hash) {
                    entry.push(crate::PouwMintRecord {
                        amount: mint.amount,
                        block_height: height,
                        tx_hash,
                    });
                    total += 1;
                }
            }
        }
        tracing::info!(
            "PoUW mint index rebuilt: {} reward payouts across {} recipients",
            total,
            self.pouw_mint_index.len()
        );
    }

    /// Process token transfer and mint transactions from a block, with **full
    /// enforcement** — every error propagates. Used by the new-block commit
    /// paths (`process_and_commit_block`, `finish_block_processing`) and by
    /// tests. For boot replay use [`Self::process_token_transactions_replay`].
    pub fn process_token_transactions(&mut self, block: &Block) -> Result<()> {
        self.process_token_transactions_inner(block, false)
    }

    /// Boot-replay variant: tolerates non-integrity `TokenTransfer` errors.
    ///
    /// During boot-time block replay the in-memory state rebuilt here is
    /// approximate (the sled-backed `BlockExecutor` is the source of truth and
    /// is attached AFTER replay completes). Refusing to boot because a
    /// historical transfer can't be reproduced against this approximate state
    /// would let any live-committed edge case (unsignable mint address,
    /// amount > u64, etc.) bring the node down on restart — so such errors are
    /// downgraded to a warning and the transfer is skipped. Tolerance is scoped
    /// to `TokenTransfer`; every other transaction type still halts replay.
    ///
    /// **Replay-protection (nonce-mismatch) errors are NEVER tolerated**, even
    /// here: they are integrity violations, not approximate-state reproduction
    /// issues, and a committed block can never legitimately carry a duplicate
    /// nonce. Silently skipping one would accept a replayed transfer on boot.
    ///
    /// Tolerance keys off this explicit parameter, NOT `self.store.is_none()` —
    /// unit tests construct store-less blockchains as a harness and must get
    /// full enforcement, not boot-replay tolerance.
    pub(crate) fn process_token_transactions_replay(&mut self, block: &Block) -> Result<()> {
        self.process_token_transactions_inner(block, true)
    }

    fn process_token_transactions_inner(
        &mut self,
        block: &Block,
        replay_tolerant: bool,
    ) -> Result<()> {
        let is_replay = replay_tolerant;
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();

        'tx_loop: for transaction in &block.transactions {
            let tx_type = transaction.transaction_type;
            let arm_result: anyhow::Result<()> = (|| -> anyhow::Result<()> {
            match tx_type {
                TransactionType::TokenTransfer => {
                    let transfer = transaction
                        .token_transfer_data()
                        .ok_or_else(|| anyhow::anyhow!("TokenTransfer missing data"))?;

                    if transfer.amount == 0 {
                        return Err(anyhow::anyhow!("TokenTransfer amount must be > 0"));
                    }

                    let is_sov = Self::is_sov_token_id(&transfer.token_id);
                    let token_id = if is_sov {
                        sov_token_id
                    } else {
                        transfer.token_id
                    };

                    let nonce_key = (token_id, transfer.from);
                    let expected_nonce = self.token_nonces.get(&nonce_key).copied().unwrap_or(0);
                    if transfer.nonce != expected_nonce {
                        return Err(anyhow::anyhow!(
                            "TokenTransfer nonce mismatch: expected {}, got {}",
                            expected_nonce,
                            transfer.nonce
                        ));
                    }

                    let sender_pk = transaction.signature.public_key.clone();

                    if token_id == sov_token_id {
                        self.ensure_sov_token_contract();
                    }

                    let amount_u64: u64 = transfer
                        .amount
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("TokenTransfer amount exceeds u64"))?;

                    let fee_rate_bps = crate::contracts::tokens::constants::SOV_FEE_RATE_BPS;
                    let fee_amount: u64 =
                        (amount_u64 as u128 * fee_rate_bps as u128 / 10_000) as u64;
                    let net_amount: u64 = amount_u64.saturating_sub(fee_amount);

                    let treasury_pk_opt: Option<PublicKey> = self
                        .dao_treasury_wallet_id
                        .as_ref()
                        .and_then(|hex_id| hex::decode(hex_id).ok())
                        .and_then(|bytes| {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                Some(Self::wallet_key_for_sov(&arr))
                            } else {
                                None
                            }
                        });

                    let tx_hash_obj = transaction.hash();
                    let tx_hash_bytes = tx_hash_obj.as_bytes();
                    let mut tx_hash = [0u8; 32];
                    tx_hash.copy_from_slice(tx_hash_bytes);

                    if is_sov {
                        let from_wallet_id = hex::encode(transfer.from);
                        let to_wallet_id = hex::encode(transfer.to);

                        // Wallet lookup with transparent legacy migration.
                        // Pre-fix wallets were registered under an HD-derived wallet_id; the new
                        // wallet_id = blake3(dilithium_pk || kyber_pk) == signer's key_id.
                        // When the sender's key_id is not in the registry, scan for a wallet whose
                        // dilithium_pk matches the sender and migrate it in place — no user action
                        // required.
                        if !self.wallet_registry.contains_key(&from_wallet_id) {
                            let sender_dilithium = sender_pk.dilithium_pk.to_vec();
                            let legacy_key = self
                                .wallet_registry
                                .iter()
                                .find(|(_, w)| {
                                    w.public_key.len() == 2592
                                        && w.public_key == sender_dilithium
                                })
                                .map(|(k, _)| k.clone());

                            if let Some(old_key) = legacy_key {
                                if let Some(mut old_wallet) =
                                    self.wallet_registry.remove(&old_key)
                                {
                                    let old_wallet_id_bytes: [u8; 32] = old_wallet
                                        .wallet_id
                                        .as_bytes()
                                        .try_into()
                                        .unwrap_or([0u8; 32]);
                                    old_wallet.wallet_id = Hash::new(transfer.from);
                                    self.wallet_registry
                                        .insert(from_wallet_id.clone(), old_wallet);

                                    // Migrate SOV balance: move from old wallet address to new
                                    // without changing total_supply (purely a re-keying).
                                    let old_sov_addr =
                                        Self::wallet_key_for_sov(&old_wallet_id_bytes);
                                    let new_sov_addr = Self::wallet_key_for_sov(&transfer.from);
                                    if let Some(token) =
                                        self.token_contracts.get_mut(&token_id)
                                    {
                                        let old_bal = token.balance_of(&old_sov_addr);
                                        if old_bal > 0 {
                                            token.set_balance(&old_sov_addr, 0);
                                            let cur_new = token.balance_of(&new_sov_addr);
                                            token.set_balance(
                                                &new_sov_addr,
                                                cur_new.saturating_add(old_bal),
                                            );
                                        }
                                    }
                                    info!(
                                        "🔄 Migrated SOV wallet {} → {} (transparent key_id migration)",
                                        old_key, from_wallet_id
                                    );
                                }
                            } else {
                                // Transparent migration: wallet not in registry and no legacy
                                // match found. Auto-register using the dilithium_pk from the
                                // transaction signature — the signature itself proves ownership.
                                // This handles wallets from a previous chain without requiring
                                // users to re-register. All nodes execute this at the same block
                                // height so state stays consistent across the network.
                                const SOV_WELCOME_BONUS: u128 = lib_types::sov::atoms(5_000);
                                let wallet_data = crate::transaction::WalletTransactionData {
                                    wallet_id: Hash::new(transfer.from),
                                    owner_identity_id: None,
                                    alias: Some(format!("migrated_{}", &from_wallet_id[..8])),
                                    wallet_name: "Migrated Wallet".to_string(),
                                    wallet_type: "Primary".to_string(),
                                    public_key: sender_pk.dilithium_pk.to_vec(),
                                    capabilities: 0xFFFFFFFF,
                                    created_at: 0,
                                    registration_fee: 0,
                                    initial_balance: SOV_WELCOME_BONUS,
                                    seed_commitment: crate::types::hash::blake3_hash(
                                        format!("migrated:{}", from_wallet_id).as_bytes(),
                                    ),
                                };
                                match self.register_wallet(wallet_data) {
                                    Ok(_) => {
                                        info!(
                                            "🔄 Transparent migration: auto-registered wallet {} with {} SOV at block execution",
                                            &from_wallet_id[..16],
                                            SOV_WELCOME_BONUS / lib_types::sov::SCALE,
                                        );
                                    }
                                    Err(e) => {
                                        return Err(anyhow::anyhow!(
                                            "TokenTransfer SOV sender wallet not found and auto-registration failed: {}",
                                            e
                                        ));
                                    }
                                }
                            }
                        }

                        if !self.wallet_registry.contains_key(&to_wallet_id) {
                            return Err(anyhow::anyhow!(
                                "TokenTransfer SOV recipient wallet not found"
                            ));
                        }

                        // Ownership check: compare dilithium_pk bytes directly.
                        // PublicKey::new() computed key_id = blake3(dilithium_pk) only, ignoring
                        // kyber — broken for kyber-enabled keys. Compare raw bytes instead.
                        let from_wallet = self
                            .wallet_registry
                            .get(&from_wallet_id)
                            .ok_or_else(|| {
                                anyhow::anyhow!("TokenTransfer SOV sender wallet not found")
                            })?;
                        let sender_dilithium = sender_pk.dilithium_pk.as_slice();
                        if from_wallet.public_key.len() != 2592
                            || from_wallet.public_key.as_slice() != sender_dilithium
                        {
                            return Err(anyhow::anyhow!(
                                "TokenTransfer SOV sender does not own wallet"
                            ));
                        }

                        let from_wallet_addr = Self::wallet_key_for_sov(&transfer.from);
                        let to_wallet_addr = Self::wallet_key_for_sov(&transfer.to);

                        let ctx = crate::contracts::executor::ExecutionContext::new(
                            from_wallet_addr.clone(),
                            block.height(),
                            block.header.timestamp,
                            0,
                            tx_hash,
                        );

                        let token = self
                            .token_contracts
                            .get_mut(&token_id)
                            .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                        let from_bal = token.balance_of(&from_wallet_addr);
                        if from_bal < amount_u64 as u128 {
                            return Err(anyhow::anyhow!(
                                "TokenTransfer insufficient balance: have {}, need {}",
                                from_bal,
                                amount_u64
                            ));
                        }
                        token
                            .transfer(&ctx, &to_wallet_addr, net_amount as u128)
                            .map_err(|e| anyhow::anyhow!("TokenTransfer failed: {}", e))?;
                        Self::apply_token_transfer_with_fee(
                            token,
                            &from_wallet_addr,
                            amount_u64,
                            fee_amount,
                            &treasury_pk_opt,
                            block.height(),
                        )?;
                    } else {
                        if sender_pk.key_id != transfer.from {
                            return Err(anyhow::anyhow!("TokenTransfer sender key_id mismatch"));
                        }

                        let recipient_pk_bytes = self
                            .resolve_public_key_by_key_id(&transfer.to)
                            .ok_or_else(|| anyhow::anyhow!("TokenTransfer recipient not found"))?;
                        let recipient_pk = PublicKey::new(
                            recipient_pk_bytes.as_slice().try_into().unwrap_or([0u8; 2592])
                        );

                        let ctx = crate::contracts::executor::ExecutionContext::new(
                            sender_pk.clone(),
                            block.height(),
                            block.header.timestamp,
                            0,
                            tx_hash,
                        );

                        let token = self
                            .token_contracts
                            .get_mut(&token_id)
                            .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                        let sender_bal = token.balance_of(&sender_pk);
                        if sender_bal < amount_u64 as u128 {
                            return Err(anyhow::anyhow!(
                                "TokenTransfer insufficient balance: have {}, need {}",
                                sender_bal,
                                amount_u64
                            ));
                        }
                        token
                            .transfer(&ctx, &recipient_pk, net_amount as u128)
                            .map_err(|e| anyhow::anyhow!("TokenTransfer failed: {}", e))?;
                        Self::apply_token_transfer_with_fee(
                            token,
                            &sender_pk,
                            amount_u64,
                            fee_amount,
                            &treasury_pk_opt,
                            block.height(),
                        )?;
                    };

                    *self.token_nonces.entry(nonce_key).or_insert(0) += 1;

                    if tracing::enabled!(tracing::Level::INFO) {
                        let cbe_token_id = Self::derive_cbe_token_id_pub();
                        let token_label: std::borrow::Cow<'_, str> = if is_sov {
                            "SOV".into()
                        } else if token_id == cbe_token_id {
                            "CBE".into()
                        } else {
                            hex::encode(&token_id[..4]).into()
                        };
                        info!(
                            "[token/transfer] committed: token={} from={} to={} amount={} fee={} net={} nonce={} height={} tx={}",
                            token_label,
                            hex::encode(&transfer.from[..4]),
                            hex::encode(&transfer.to[..4]),
                            amount_u64,
                            fee_amount,
                            net_amount,
                            transfer.nonce,
                            block.height(),
                            hex::encode(&tx_hash[..4]),
                        );
                    }

                    if let Some(store) = &self.store {
                        if let Some(token) = self.token_contracts.get(&token_id) {
                            let store_ref: &dyn crate::storage::BlockchainStore = store.as_ref();
                            if let Err(e) = store_ref.put_token_contract(token) {
                                warn!("[token/transfer] failed to persist token contract: height={} token={} err={}", block.height(), hex::encode(&token_id[..4]), e);
                            }
                        }
                    }
                }
                TransactionType::TokenMint => {
                    if transaction.version < 2 {
                        return Err(anyhow::anyhow!(
                            "TokenMint not supported in this serialization version"
                        ));
                    }

                    let mint = transaction
                        .token_mint_data()
                        .ok_or_else(|| anyhow::anyhow!("TokenMint missing data"))?;

                    if mint.amount == 0 {
                        return Err(anyhow::anyhow!("TokenMint amount must be > 0"));
                    }

                    let is_sov = Self::is_sov_token_id(&mint.token_id);
                    let recipient_pk = if is_sov {
                        Self::wallet_key_for_sov(&mint.to)
                    } else {
                        let recipient_pk_bytes = self
                            .resolve_public_key_by_key_id(&mint.to)
                            .ok_or_else(|| anyhow::anyhow!("TokenMint recipient not found"))?;
                        PublicKey::new(
                            recipient_pk_bytes.as_slice().try_into().unwrap_or([0u8; 2592])
                        )
                    };

                    let mut migration_from: Option<PublicKey> = None;
                    if let Ok(memo_str) = std::str::from_utf8(&transaction.memo) {
                        if let Some(rest) = memo_str.strip_prefix("UBI_DISTRIBUTION_V1:") {
                            let mut parts = rest.split(':');
                            let identity_id = parts.next().unwrap_or("").to_string();
                            let wallet_id = parts.next().unwrap_or("").to_string();

                            let entry = self
                                .ubi_registry
                                .get_mut(&identity_id)
                                .ok_or_else(|| anyhow::anyhow!("UBI mint for unknown identity"))?;
                            if entry.ubi_wallet_id != wallet_id {
                                return Err(anyhow::anyhow!("UBI mint wallet mismatch"));
                            }
                            if Self::is_sov_token_id(&mint.token_id) {
                                let mint_wallet_id = hex::encode(mint.to);
                                if mint_wallet_id != wallet_id {
                                    return Err(anyhow::anyhow!(
                                        "UBI mint recipient wallet mismatch"
                                    ));
                                }
                            }

                            let is_due = match entry.last_payout_block {
                                Some(last_block) => {
                                    block.height().saturating_sub(last_block)
                                        >= Self::BLOCKS_PER_DAY
                                }
                                None => true,
                            };
                            if !is_due {
                                return Err(anyhow::anyhow!("UBI mint not due for identity"));
                            }

                            let mut expected_payout = entry.daily_amount;
                            let mut new_remainder =
                                entry.remainder_balance + (entry.monthly_amount % 30);
                            if new_remainder >= 30 {
                                expected_payout += new_remainder / 30;
                                new_remainder %= 30;
                            }

                            if mint.amount != expected_payout {
                                return Err(anyhow::anyhow!("UBI mint amount mismatch"));
                            }

                            entry.last_payout_block = Some(block.height());
                            entry.total_received =
                                entry.total_received.saturating_add(expected_payout);
                            entry.remainder_balance = new_remainder;

                            if let Some(wallet) = self.wallet_registry.get_mut(&wallet_id) {
                                wallet.initial_balance =
                                    wallet.initial_balance.saturating_add(expected_payout);
                            }
                        } else if let Some(rest) = memo_str.strip_prefix("TOKEN_MIGRATE_V1:") {
                            let old_pk_bytes = hex::decode(rest)
                                .map_err(|_| anyhow::anyhow!("Invalid TOKEN_MIGRATE_V1 memo"))?;
                            migration_from = Some(PublicKey::new(
                                old_pk_bytes.as_slice().try_into().unwrap_or([0u8; 2592])
                            ));
                        }
                    }

                    let token_id = if is_sov { sov_token_id } else { mint.token_id };

                    if token_id == sov_token_id {
                        self.ensure_sov_token_contract();
                    }

                    let is_ubi_mint = std::str::from_utf8(&transaction.memo)
                        .ok()
                        .is_some_and(|s| s.starts_with("UBI_DISTRIBUTION_V1:"));
                    let is_migration = migration_from.is_some();

                    let amount_u64: u64 = mint
                        .amount
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("TokenMint amount exceeds u64"))?;

                    let is_kernel_controlled = self
                        .token_contracts
                        .get(&token_id)
                        .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?
                        .kernel_mint_authority
                        .is_some();

                    if !is_sov && !is_ubi_mint && !is_migration && !is_kernel_controlled {
                        let token = self
                            .token_contracts
                            .get(&token_id)
                            .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                        token
                            .check_mint_authorization(&transaction.signature.public_key)
                            .map_err(|e| anyhow::anyhow!("{}", e))?;
                    }

                    if let Some(from_pk) = migration_from {
                        if is_kernel_controlled {
                            let mut kernel = self.treasury_kernel.take().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Treasury Kernel not initialized - kernel-controlled token operations require kernel"
                                )
                            })?;
                            let burn_result = {
                                let token = self
                                    .token_contracts
                                    .get_mut(&token_id)
                                    .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                                kernel.debit(
                                    token,
                                    &transaction.signature.public_key,
                                    &from_pk,
                                    amount_u64,
                                    crate::contracts::treasury_kernel::DebitReason::Burn,
                                )
                            };
                            self.treasury_kernel = Some(kernel);
                            burn_result.map_err(|e| {
                                anyhow::anyhow!("Token migration burn failed: {}", e)
                            })?;
                        } else {
                            let token = self
                                .token_contracts
                                .get_mut(&token_id)
                                .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                            token.burn(&from_pk, amount_u64 as u128).map_err(|e| {
                                anyhow::anyhow!("Token migration burn failed: {}", e)
                            })?;
                        }
                    }

                    if is_kernel_controlled {
                        let mut kernel = self.treasury_kernel.take().ok_or_else(|| {
                            anyhow::anyhow!(
                                "Treasury Kernel not initialized - kernel-controlled token operations require kernel"
                            )
                        })?;
                        let mint_result = {
                            let token = self
                                .token_contracts
                                .get_mut(&token_id)
                                .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                            kernel.credit(
                                token,
                                &transaction.signature.public_key,
                                &recipient_pk,
                                amount_u64,
                                crate::contracts::treasury_kernel::CreditReason::Mint,
                            )
                        };
                        self.treasury_kernel = Some(kernel);
                        mint_result.map_err(|e| anyhow::anyhow!("TokenMint failed: {}", e))?;
                    } else {
                        let token = self
                            .token_contracts
                            .get_mut(&token_id)
                            .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                        token
                            .mint(&recipient_pk, amount_u64 as u128)
                            .map_err(|e| anyhow::anyhow!("TokenMint failed: {}", e))?;
                    }

                    if let Some(store) = &self.store {
                        let token = self
                            .token_contracts
                            .get(&token_id)
                            .ok_or_else(|| anyhow::anyhow!("Token contract not found"))?;
                        let store_ref: &dyn crate::storage::BlockchainStore = store.as_ref();
                        if let Err(e) = store_ref.put_token_contract(token) {
                            warn!("Failed to persist token contract after mint: {}", e);
                        }
                    }

                    // PoUW reward index (option A): a TokenMint carrying a
                    // `pouw:mint:` memo is a proof-of-useful-work payout. Record
                    // it keyed by recipient key_id so /api/v1/pouw/rewards can
                    // report consensus-derived history. This runs in every
                    // block-processing path (live commit + replay), so the
                    // index is rebuilt deterministically and is identical on
                    // every node. Dedup by tx_hash guards against a block being
                    // processed twice.
                    if transaction.memo.starts_with(b"pouw:mint:") {
                        let tx_hash = transaction.hash().as_array();
                        let entry = self.pouw_mint_index.entry(mint.to).or_default();
                        if !entry.iter().any(|r| r.tx_hash == tx_hash) {
                            entry.push(crate::PouwMintRecord {
                                amount: mint.amount,
                                block_height: block.height(),
                                tx_hash,
                            });
                        }
                    }
                }
                TransactionType::TokenCreation => {
                    let payload =
                        crate::transaction::TokenCreationPayloadV1::decode_memo(&transaction.memo)
                            .map_err(|e| anyhow::anyhow!("Invalid TokenCreation memo: {}", e))?;
                    let (creator_allocation, treasury_allocation) = payload.split_initial_supply();

                    let creator = transaction.signature.public_key.clone();
                    if payload.treasury_recipient == creator.key_id {
                        return Err(anyhow::anyhow!(
                            "TokenCreation treasury_recipient must differ from creator"
                        ));
                    }

                    let symbol_upper = payload.symbol.to_uppercase();
                    for existing_token in self.token_contracts.values() {
                        if existing_token.symbol.to_uppercase() == symbol_upper {
                            return Err(anyhow::anyhow!(
                                "Token symbol '{}' already exists",
                                payload.symbol
                            ));
                        }
                    }

                    let mut token = crate::contracts::TokenContract::new_custom(
                        payload.name.clone(),
                        payload.symbol.clone(),
                        0,
                        creator.clone(),
                    );
                    token.decimals = if payload.decimals == 0 {
                        8
                    } else {
                        payload.decimals
                    };
                    token.max_supply = payload.initial_supply;
                    token
                        .mint(&creator, creator_allocation)
                        .map_err(|e| anyhow::anyhow!("TokenCreation mint failed: {}", e))?;
                    let treasury_pk = lib_crypto::types::keys::PublicKey {
                        dilithium_pk: [0u8; 2592],
                        kyber_pk: [0u8; 1568],
                        key_id: payload.treasury_recipient,
                    };
                    token.mint(&treasury_pk, treasury_allocation).map_err(|e| {
                        anyhow::anyhow!("TokenCreation treasury mint failed: {}", e)
                    })?;

                    let token_id = token.token_id;
                    if self.token_contracts.contains_key(&token_id) {
                        return Err(anyhow::anyhow!(
                            "Token with same name and symbol already exists"
                        ));
                    }

                    self.contract_blocks.insert(token_id, block.height());
                    self.token_contracts.insert(token_id, token.clone());

                    if let Some(store) = &self.store {
                        let store_ref: &dyn crate::storage::BlockchainStore = store.as_ref();
                        if let Err(e) = store_ref.put_token_contract(&token) {
                            warn!("Failed to persist token contract after creation: {}", e);
                        }
                    }
                }
                TransactionType::BondingCurveDeploy => {
                    return Err(anyhow::anyhow!(
                        "BondingCurveDeploy requires BlockExecutor; legacy bonding-curve mutation path is disabled"
                    ));
                }
                TransactionType::BondingCurveBuy => {
                    return Err(anyhow::anyhow!(
                        "BondingCurveBuy requires BlockExecutor; legacy bonding-curve mutation path is disabled"
                    ));
                }
                TransactionType::BondingCurveSell => {
                    return Err(anyhow::anyhow!(
                        "BondingCurveSell requires BlockExecutor; legacy bonding-curve mutation path is disabled"
                    ));
                }
                TransactionType::BondingCurveGraduate => {
                    return Err(anyhow::anyhow!(
                        "BondingCurveGraduate requires BlockExecutor; legacy bonding-curve mutation path is disabled"
                    ));
                }
                _ => {}
            }
            Ok(())
            })();
            if let Err(e) = arm_result {
                // Replay tolerance covers transfers that can't be reproduced
                // against approximate in-memory state (insufficient balance,
                // unsignable address, amount overflow). It must NEVER cover
                // replay-protection (nonce) errors: a duplicate/replayed nonce
                // is an integrity violation, and a committed block can never
                // legitimately contain one, so silently skipping it would accept
                // a replayed transfer during boot. Those always propagate.
                let is_replay_protection = e.to_string().contains("nonce mismatch");
                if is_replay
                    && tx_type == TransactionType::TokenTransfer
                    && !is_replay_protection
                {
                    warn!(
                        "Replay: skipping TokenTransfer at height={} tx={}: {}",
                        block.height(),
                        hex::encode(&transaction.hash().as_bytes()[..4]),
                        e,
                    );
                    continue 'tx_loop;
                }
                return Err(e);
            }
        }

        Ok(())
    }

    pub(super) fn process_contract_execution(
        &mut self,
        transaction: &Transaction,
        block_height: u64,
    ) -> Result<()> {
        let call = if transaction
            .memo
            .starts_with(crate::transaction::CONTRACT_EXECUTION_MEMO_PREFIX_V2)
        {
            let decoded =
                crate::transaction::DecodedContractExecutionMemo::decode_compat(&transaction.memo)
                    .map_err(|e| {
                        anyhow::anyhow!("Invalid contract execution memo format: {}", e)
                    })?;
            decoded.call
        } else {
            if transaction.memo.len() <= 4 || &transaction.memo[0..4] != b"ZHTP" {
                return Err(anyhow::anyhow!("Invalid contract execution memo format"));
            }
            let call_data = &transaction.memo[4..];
            let (call, _sig): (
                crate::types::ContractCall,
                crate::integration::crypto_integration::Signature,
            ) = bincode::deserialize(call_data)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize contract call: {}", e))?;
            call
        };

        let caller = transaction.signature.public_key.clone();

        match call.contract_type {
            crate::types::ContractType::Token => {
                self.execute_token_contract_call(&call, &caller, block_height)?;
            }
            _ => {
                debug!(
                    "Skipping non-token contract execution: {:?}",
                    call.contract_type
                );
            }
        }

        Ok(())
    }

    pub(super) fn reprocess_contract_executions(&mut self) -> Result<()> {
        // #2636: full chain (window + sled), materialized up front since the
        // loop mutates self. The previous `self.blocks` scan only reprocessed
        // the hot window on a pruned node.
        let blocks: Vec<crate::block::Block> = self.iter_blocks().collect();
        let block_count = blocks.len();
        if block_count == 0 {
            return Ok(());
        }

        info!(
            "🔄 Reprocessing contract executions from {} blocks (current tokens: {})...",
            block_count,
            self.token_contracts.len()
        );
        let mut tokens_found = 0;
        let mut contract_txs_found = 0;

        for block in &blocks {
            for transaction in &block.transactions {
                if transaction.transaction_type == TransactionType::ContractExecution {
                    contract_txs_found += 1;
                    match self.process_contract_execution(transaction, block.height()) {
                        Ok(()) => {
                            tokens_found += 1;
                        }
                        Err(e) => {
                            warn!(
                                "⚠️ Failed to reprocess contract execution at block {}: {}",
                                block.height(),
                                e
                            );
                        }
                    }
                }
            }
        }

        info!(
            "🔄 Found {} ContractExecution transactions, processed {} successfully, tokens: {}",
            contract_txs_found,
            tokens_found,
            self.token_contracts.len()
        );

        if tokens_found > 0 {
            info!(
                "🔄 Reprocessed {} contract executions, total tokens: {}",
                tokens_found,
                self.token_contracts.len()
            );
        }

        Ok(())
    }

    fn execute_token_contract_call(
        &mut self,
        call: &crate::types::ContractCall,
        caller: &lib_crypto::types::keys::PublicKey,
        block_height: u64,
    ) -> Result<()> {
        match call.method.as_str() {
            "create_custom_token" => {
                #[derive(serde::Deserialize)]
                struct CreateTokenParams {
                    name: String,
                    symbol: String,
                    initial_supply: u64,
                    decimals: u8,
                }
                let params: CreateTokenParams = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid create_custom_token params: {}", e))?;
                let CreateTokenParams {
                    name,
                    symbol,
                    initial_supply,
                    decimals,
                } = params;

                let symbol_upper = symbol.to_uppercase();
                for existing_token in self.token_contracts.values() {
                    if existing_token.symbol.to_uppercase() == symbol_upper {
                        return Err(anyhow::anyhow!(
                            "Token symbol '{}' already exists (used by token '{}')",
                            symbol,
                            existing_token.name
                        ));
                    }
                }

                let mut token = crate::contracts::TokenContract::new_custom(
                    name.clone(),
                    symbol.clone(),
                    initial_supply,
                    caller.clone(),
                );
                token.decimals = if decimals == 0 { 8 } else { decimals };

                let token_id = token.token_id;
                if self.token_contracts.contains_key(&token_id) {
                    return Err(anyhow::anyhow!(
                        "Token with same name and symbol already exists"
                    ));
                }

                info!(
                    "Creating token contract: {} ({}) with supply {} at block {}",
                    name, symbol, initial_supply, block_height
                );
                self.token_contracts.insert(token_id, token);
                self.contract_blocks.insert(token_id, block_height);
                info!(
                    "Token contract created: {} ({}), token_id: {}",
                    name,
                    symbol,
                    hex::encode(token_id)
                );
            }
            "mint" => {
                #[derive(serde::Deserialize)]
                struct MintParams {
                    token_id: [u8; 32],
                    to: Vec<u8>,
                    amount: u64,
                }
                let params: MintParams = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid mint params: {}", e))?;
                let MintParams {
                    token_id,
                    to: to_bytes,
                    amount,
                } = params;
                if Self::is_sov_token_id(&token_id) {
                    return Err(anyhow::anyhow!("SOV mints must use TokenMint transactions"));
                }

                let to: lib_crypto::types::keys::PublicKey = if to_bytes.len() == 32 {
                    lib_crypto::types::keys::PublicKey {
                        dilithium_pk: [0u8; 2592],
                        kyber_pk: [0u8; 1568],
                        key_id: to_bytes.try_into().unwrap_or([0u8; 32]),
                    }
                } else {
                    bincode::deserialize(&to_bytes).unwrap_or_else(|_| {
                        lib_crypto::types::keys::PublicKey {
                            dilithium_pk: [0u8; 2592],
                            kyber_pk: [0u8; 1568],
                            key_id: [0u8; 32],
                        }
                    })
                };

                let token = self
                    .token_contracts
                    .get_mut(&token_id)
                    .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

                if token.kernel_mint_authority.is_some() {
                    return Err(anyhow::anyhow!(
                        "Protected token mint must route through Treasury Kernel"
                    ));
                }

                if token.creator != *caller {
                    return Err(anyhow::anyhow!("Only token creator can mint"));
                }

                #[allow(deprecated)]
                crate::contracts::tokens::functions::mint_tokens(token, &to, amount)
                    .map_err(|e| anyhow::anyhow!("Mint failed: {}", e))?;
                info!("Minted {} tokens to {:?}", amount, to.key_id);
            }
            "transfer" => {
                return Err(anyhow::anyhow!(
                    "ContractExecution/transfer is prohibited — use TokenTransfer transactions instead"
                ));
            }
            "burn" => {
                return Err(anyhow::anyhow!(
                    "ContractExecution/burn is prohibited — use TokenBurn transactions instead"
                ));
            }
            _ => {
                debug!("Unknown token method: {}", call.method);
            }
        }

        Ok(())
    }

    /// Register a token contract in the blockchain.
    pub fn register_token_contract(
        &mut self,
        contract_id: [u8; 32],
        contract: crate::contracts::TokenContract,
        block_height: u64,
    ) {
        self.token_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(
            " Registered token contract {} at block {}",
            hex::encode(contract_id),
            block_height
        );
    }

    /// Reads from BlockchainStore if available, otherwise falls back to the in-memory map.
    pub fn get_token_contract(
        &self,
        contract_id: &[u8; 32],
    ) -> Option<crate::contracts::TokenContract> {
        if let Some(store) = self.get_store() {
            let token_id = crate::storage::TokenId::new(*contract_id);
            if let Ok(Some(contract)) = store.get_token_contract(&token_id) {
                return Some(contract);
            }
        }
        self.token_contracts.get(contract_id).cloned()
    }

    /// WARNING: This mutates the in-memory HashMap. For BlockExecutor, prefer store APIs.
    pub fn get_token_contract_mut(
        &mut self,
        contract_id: &[u8; 32],
    ) -> Option<&mut crate::contracts::TokenContract> {
        self.token_contracts.get_mut(contract_id)
    }

    /// Sled-first balance facade (state-unification #2635 / #2637).
    ///
    /// `token_id` and `address` are 32-byte ids (the address is a `key_id`, the
    /// same form the executor's `StateMutator` uses as the sled `Address`). When
    /// a `BlockchainStore` is attached it is the authoritative source and a sled
    /// failure is **propagated as an error** — we do NOT silently fall back to a
    /// possibly-stale in-memory balance (that masks corrupt-tree / disk-full /
    /// unmounted-store failures, exactly the class that leads to authorizing a
    /// transfer on a wrong balance). The in-memory `TokenContract` map is read
    /// only in store-less mode (unit tests, pre-store bootstrap).
    ///
    /// # Mid-block invariant (CR #2658 / blocks Phase 3)
    ///
    /// This reads **committed** sled state. Writes staged in the current block's
    /// `tx_batch` (between `begin_block` and `commit_block`) are NOT visible
    /// here. HTTP read handlers (the current callers) are never inside a block
    /// boundary, so this is correct for them. **Before any consensus-path /
    /// mid-`apply_block` caller uses this facade (Phase 3), a `tx_batch`-aware
    /// read must be added to `SledStore::get_token_balance`** or that caller
    /// will see the pre-block value and could authorize a double-spend.
    pub fn token_balance(
        &self,
        token_id: &[u8; 32],
        address: &[u8; 32],
    ) -> crate::storage::StorageResult<u128> {
        if let Some(store) = self.get_store() {
            let token = crate::storage::TokenId::new(*token_id);
            let addr = crate::storage::Address::new(*address);
            // sled is authoritative — propagate errors instead of serving stale in-mem.
            return store.get_token_balance(&token, &addr);
        }
        Ok(self
            .token_contracts
            .get(token_id)
            .and_then(|c| c.find_balance_by_key_id(address))
            .map(|(_, balance)| balance)
            .unwrap_or(0))
    }

    /// Sled-first iterator facade over all token contracts — **METADATA ONLY**
    /// (#2637).
    ///
    /// Returns the authoritative contract set from the store when attached,
    /// falling back to the in-memory map in store-less mode. Use for listing /
    /// counting / finding tokens by name/symbol/decimals/supply.
    ///
    /// # ⚠️ Balances are NOT populated on these results
    ///
    /// Per-address balances live in a **separate** sled tree (`token_balances`),
    /// not inside the serialized `TokenContract`. A contract deserialized from
    /// sled has an **empty** `balances` map, so `c.balance_of(addr)` on a result
    /// of this method **always returns 0**. The name encodes the contract: this
    /// is metadata only. For balances call [`Self::token_balance`]. (This is the
    /// footgun the renamed-from-`iter_token_contracts` CR flagged.)
    pub fn iter_token_contract_metadata(&self) -> Vec<crate::contracts::TokenContract> {
        if let Some(store) = self.get_store() {
            if let Ok(iter) = store.iter_token_contracts() {
                return iter.map(|(_, c)| c).collect();
            }
        }
        self.token_contracts.values().cloned().collect()
    }

    pub fn register_web4_contract(
        &mut self,
        contract_id: [u8; 32],
        contract: crate::contracts::web4::Web4Contract,
        block_height: u64,
    ) {
        self.web4_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(
            " Registered Web4 contract {} at block {}",
            hex::encode(contract_id),
            block_height
        );
    }

    pub fn get_web4_contract(
        &self,
        contract_id: &[u8; 32],
    ) -> Option<&crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get(contract_id)
    }

    pub fn get_web4_contract_mut(
        &mut self,
        contract_id: &[u8; 32],
    ) -> Option<&mut crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get_mut(contract_id)
    }

    pub fn get_all_token_contracts(&self) -> &HashMap<[u8; 32], crate::contracts::TokenContract> {
        &self.token_contracts
    }

    pub fn get_all_web4_contracts(
        &self,
    ) -> &HashMap<[u8; 32], crate::contracts::web4::Web4Contract> {
        &self.web4_contracts
    }

    /// Process DomainRegistration and DomainUpdate transactions from a block.
    /// Writes authoritative records into `self.domain_registry`.
    pub fn process_domain_transactions(&mut self, block: &Block) {
        let block_ts = block.header.timestamp;
        let block_height = block.height();

        for tx in &block.transactions {
            if tx.transaction_type == TransactionType::DomainRegistration {
                match crate::transaction::DomainRegistrationPayload::decode_memo(&tx.memo) {
                    Ok(payload) => {
                        let expires_at =
                            block_ts + payload.duration_days.saturating_mul(86_400);
                        let record = crate::transaction::OnChainDomainRecord {
                            domain: payload.domain.clone(),
                            owner_did: payload.owner_did,
                            manifest_cid: payload.manifest_cid,
                            build_hash: payload.build_hash,
                            title: payload.title,
                            description: payload.description,
                            category: payload.category,
                            tags: payload.tags,
                            registered_at: block_ts,
                            expires_at,
                            version: 1,
                            updated_at: block_ts,
                            fee_tx_hash: payload.fee_tx_hash,
                        };
                        info!(
                            "⛓️  Domain registered on-chain: {} at height {}",
                            record.domain, block_height
                        );
                        self.domain_registry.insert(payload.domain, record);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to decode DomainRegistration memo at height {}: {}",
                            block_height, e
                        );
                    }
                }
            } else if tx.transaction_type == TransactionType::DomainUpdate {
                match crate::transaction::DomainUpdatePayload::decode_memo(&tx.memo) {
                    Ok(payload) => {
                        if let Some(record) = self.domain_registry.get_mut(&payload.domain) {
                            // CAS check
                            if record.manifest_cid != payload.expected_previous_manifest_cid {
                                warn!(
                                    "DomainUpdate CAS mismatch for {} at height {}: expected {}, got {}",
                                    payload.domain,
                                    block_height,
                                    payload.expected_previous_manifest_cid,
                                    record.manifest_cid
                                );
                                continue;
                            }
                            record.manifest_cid = payload.new_manifest_cid;
                            record.build_hash = payload.build_hash;
                            record.version += 1;
                            record.updated_at = block_ts;
                            record.fee_tx_hash = payload.fee_tx_hash;
                            info!(
                                "⛓️  Domain updated on-chain: {} v{} at height {}",
                                record.domain, record.version, block_height
                            );
                        } else {
                            warn!(
                                "DomainUpdate for unknown domain {} at height {}",
                                payload.domain, block_height
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to decode DomainUpdate memo at height {}: {}",
                            block_height, e
                        );
                    }
                }
            }
        }
    }

    /// Process NFT transactions from a committed block.
    pub fn process_nft_transactions(&mut self, block: &Block) {
        use crate::contracts::nft::{NftContract, NftMetadata};

        for tx in &block.transactions {
            match tx.transaction_type {
                TransactionType::NftCreateCollection => {
                    if let Some(data) = tx.nft_create_collection_data() {
                        let collection_id = lib_crypto::hash_blake3(
                            &format!(
                                "nft_collection:{}:{}:{}",
                                data.name,
                                data.symbol,
                                hex::encode(tx.signature.public_key.key_id)
                            )
                            .as_bytes(),
                        );
                        let contract = NftContract::new(
                            collection_id,
                            data.name.clone(),
                            data.symbol.clone(),
                            format!("did:zhtp:{}", hex::encode(
                                lib_crypto::hashing::hash_blake3(&tx.signature.public_key.dilithium_pk)
                            )),
                            tx.signature.public_key.key_id,
                            data.max_supply,
                            tx.signature.timestamp,
                        );
                        if self.nft_collections.contains_key(&collection_id) {
                            warn!(
                                "NFT collection already exists, skipping: id={}",
                                hex::encode(&collection_id[..8]),
                            );
                        } else {
                            info!(
                                "🎨 NFT collection created: {} ({}) id={}",
                                data.name,
                                data.symbol,
                                hex::encode(&collection_id[..8]),
                            );
                            self.nft_collections.insert(collection_id, contract);
                        }
                    }
                }
                TransactionType::NftMint => {
                    if let Some(data) = tx.nft_mint_data() {
                        if let Some(collection) = self.nft_collections.get_mut(&data.collection_id) {
                            let metadata = NftMetadata {
                                name: data.name.clone(),
                                description: data.description.clone(),
                                image_cid: data.image_cid.clone(),
                                attributes: data.attributes.clone(),
                                creator_did: collection.creator_did.clone(),
                                created_at: tx.signature.timestamp,
                            };
                            match collection.mint(
                                &tx.signature.public_key.key_id,
                                data.recipient,
                                metadata,
                            ) {
                                Ok(token_id) => {
                                    info!(
                                        "🎨 NFT minted: collection={} token_id={} to={}",
                                        hex::encode(&data.collection_id[..8]),
                                        token_id,
                                        hex::encode(&data.recipient[..8]),
                                    );
                                }
                                Err(e) => {
                                    warn!("NFT mint failed: {}", e);
                                }
                            }
                        }
                    }
                }
                TransactionType::NftTransfer => {
                    if let Some(data) = tx.nft_transfer_data() {
                        if tx.signature.public_key.key_id != data.from {
                            warn!(
                                "NFT transfer rejected: signer {} is not the owner {}",
                                hex::encode(&tx.signature.public_key.key_id[..8]),
                                hex::encode(&data.from[..8]),
                            );
                        } else if let Some(collection) = self.nft_collections.get_mut(&data.collection_id) {
                            if let Err(e) = collection.transfer(data.token_id, &data.from, data.to) {
                                warn!("NFT transfer failed: {}", e);
                            } else {
                                info!(
                                    "🎨 NFT transferred: collection={} token={} to={}",
                                    hex::encode(&data.collection_id[..8]),
                                    data.token_id,
                                    hex::encode(&data.to[..8]),
                                );
                            }
                        }
                    }
                }
                TransactionType::NftBurn => {
                    if let Some(data) = tx.nft_burn_data() {
                        if tx.signature.public_key.key_id != data.owner {
                            warn!(
                                "NFT burn rejected: signer {} is not the owner {}",
                                hex::encode(&tx.signature.public_key.key_id[..8]),
                                hex::encode(&data.owner[..8]),
                            );
                        } else if let Some(collection) = self.nft_collections.get_mut(&data.collection_id) {
                            if let Err(e) = collection.burn(data.token_id, &data.owner) {
                                warn!("NFT burn failed: {}", e);
                            } else {
                                info!(
                                    "🎨 NFT burned: collection={} token={}",
                                    hex::encode(&data.collection_id[..8]),
                                    data.token_id,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Get the authoritative on-chain domain registry.
    pub fn get_all_domains(&self) -> &HashMap<String, crate::transaction::OnChainDomainRecord> {
        &self.domain_registry
    }

    /// Look up a single domain record from chain state.
    pub fn get_domain(&self, domain: &str) -> Option<&crate::transaction::OnChainDomainRecord> {
        self.domain_registry.get(domain)
    }

    pub fn contract_exists(&self, contract_id: &[u8; 32]) -> bool {
        self.token_contracts.contains_key(contract_id)
            || self.web4_contracts.contains_key(contract_id)
    }

    pub fn get_contract_block_height(&self, contract_id: &[u8; 32]) -> Option<u64> {
        self.contract_blocks.get(contract_id).copied()
    }
}

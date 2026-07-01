use super::*;

impl Blockchain {
    /// Ensure the native SOV token contract exists in the in-memory shadow (#2640).
    pub(super) fn ensure_sov_token_contract(&mut self) {
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        if !self.token_contracts.contains_key(&sov_token_id) {
            let sov_token = crate::contracts::TokenContract::new_sov_native();
            self.token_contracts.insert(sov_token_id, sov_token);
            info!("🪙 Initialized native SOV token contract");
        }
    }

    /// Initialize the Treasury Kernel from the first council member's identity
    /// if not already loaded from persistence. No-op if kernel is present or
    /// if council data is unavailable.
    pub fn init_treasury_kernel_if_missing(&mut self) {
        if self.treasury_kernel.is_some() {
            info!("🏛️ Treasury Kernel restored from persistence");
            return;
        }

        let kernel_init_data: Option<(lib_crypto::PublicKey, String)> = self
            .council_members
            .first()
            .and_then(|cm| {
                let did = cm.identity_id.clone();
                // #2639: sled-first, consensus-pinned key (in-mem fallback). On a
                // restarted store-backed node the in-memory shadow is empty, so the
                // council authority key would not be found and the treasury kernel
                // would silently fail to initialize.
                self.identity_public_key(&did).and_then(|pk| {
                    match pk.as_slice().try_into() {
                        Ok(pk_bytes) => Some((lib_crypto::PublicKey::new(pk_bytes), did)),
                        Err(_) => {
                            warn!("Treasury Kernel skip: council pk length {}", pk.len());
                            None
                        }
                    }
                })
            });

        if let Some((authority_pk, authority_did)) = kernel_init_data {
            self.initialize_treasury_kernel(authority_pk);
            info!(
                "🏛️ Treasury Kernel initialized with council authority {}",
                &authority_did[..40.min(authority_did.len())]
            );
        } else if self.council_members.is_empty() {
            warn!("Treasury Kernel not initialized: no council members configured");
        } else {
            warn!("Treasury Kernel not initialized: council member not in identity registry");
        }
    }

    /// Initialize the 5 welfare DAO sector tokens if not already present.
    /// Each token is kernel-controlled (mint/burn only via Treasury Kernel),
    /// 1:1 SOV-backed, and identified by a deterministic token_id derived from
    /// (name, symbol). The DAO key_id is used by the executor during
    /// stake/unstake operations, not by the token itself.
    pub fn ensure_welfare_dao_tokens(&mut self) {
        use crate::contracts::economics::fee_router::{
            DAO_HEALTHCARE_KEY_ID, DAO_EDUCATION_KEY_ID, DAO_ENERGY_KEY_ID,
            DAO_HOUSING_KEY_ID, DAO_FOOD_KEY_ID,
        };

        let kernel_authority = match &self.treasury_kernel {
            Some(kernel) => kernel.governance_authority().clone(),
            None => {
                warn!("Cannot initialize welfare DAO tokens: Treasury Kernel not initialized");
                return;
            }
        };

        let tokens: &[(&str, &str, &[u8; 32])] = &[
            ("HealthToken", "HEAL", &DAO_HEALTHCARE_KEY_ID),
            ("EduToken", "EDU", &DAO_EDUCATION_KEY_ID),
            ("EnergyToken", "ENRG", &DAO_ENERGY_KEY_ID),
            ("HousingToken", "HOME", &DAO_HOUSING_KEY_ID),
            ("FoodToken", "FOOD", &DAO_FOOD_KEY_ID),
        ];

        let mut created = 0;
        for (name, symbol, _dao_key_id) in tokens {
            let token_id =
                crate::contracts::utils::generate_custom_token_id(name, symbol);
            if self.token_contracts.contains_key(&token_id) {
                continue;
            }
            let token = crate::contracts::TokenContract::new_welfare_token(
                name.to_string(),
                symbol.to_string(),
                kernel_authority.clone(),
            );
            info!(
                "🏥 Welfare DAO token created: {} ({}) id={}",
                name,
                symbol,
                hex::encode(&token_id[..8])
            );
            self.token_contracts.insert(token_id, token);
            created += 1;
        }
        if created > 0 {
            info!("🏛️ Initialized {} welfare DAO sector tokens", created);
        }
    }

    pub(super) fn ensure_treasury_wallet(&mut self) {
        let wallet_id_bytes = Self::deterministic_treasury_wallet_id().as_array();
        let wallet_id_hex = hex::encode(wallet_id_bytes);

        if !self.wallet_registry.contains_key(&wallet_id_hex) {
            let wallet_data = crate::transaction::WalletTransactionData {
                wallet_id: crate::types::Hash::new(wallet_id_bytes),
                wallet_type: "treasury".to_string(),
                wallet_name: "DAO Treasury".to_string(),
                alias: None,
                public_key: vec![],
                owner_identity_id: None,
                seed_commitment: crate::types::Hash::zero(),
                created_at: 0,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 0,
            };
            self.wallet_registry
                .insert(wallet_id_hex.clone(), wallet_data);
        }

        if self.dao_treasury_wallet_id.is_none() {
            self.dao_treasury_wallet_id = Some(wallet_id_hex);
            info!("🏦 DAO treasury wallet initialized (deterministic bootstrap)");
        }
    }

    pub fn deterministic_treasury_wallet_id() -> crate::types::Hash {
        crate::types::hash::blake3_hash(b"SOV_DAO_TREASURY_V1")
    }

    pub fn wallet_exists_in_canonical_history(&self, wallet_id: &crate::types::Hash) -> bool {
        let wallet_id_hex = hex::encode(wallet_id.as_bytes());
        if self.wallet_blocks.get(&wallet_id_hex).copied() == Some(0) {
            return true;
        }

        // #2636: scan the full chain (window + sled). The previous self.blocks
        // scan only saw the hot window, so a wallet registered in an aged-out
        // block was wrongly reported as absent from canonical history.
        self.iter_blocks().any(|block| {
            block.transactions.iter().any(|tx| {
                tx.wallet_data()
                    .map(|wallet_data| wallet_data.wallet_id == *wallet_id)
                    .unwrap_or(false)
            })
        })
    }

    pub fn collect_noncanonical_wallets(&self) -> Vec<crate::transaction::WalletTransactionData> {
        let mut wallets: Vec<_> = self
            .wallet_registry
            .values()
            .filter(|wallet| !self.wallet_exists_in_canonical_history(&wallet.wallet_id))
            .cloned()
            .collect();
        wallets.sort_by_key(|wallet| hex::encode(wallet.wallet_id.as_bytes()));
        wallets
    }

    pub fn dao_treasury_wallet_is_canonical(&self) -> bool {
        self.dao_treasury_wallet_id
            .as_ref()
            .and_then(|wallet_id_hex| self.wallet_registry.get(wallet_id_hex))
            .map(|wallet| self.wallet_exists_in_canonical_history(&wallet.wallet_id))
            .unwrap_or(false)
    }

    fn resolve_credit_pubkey_from_parts(
        &self,
        public_key: Vec<u8>,
        owner_identity_id: Option<Hash>,
    ) -> Option<Vec<u8>> {
        if public_key.len() >= Self::MIN_DILITHIUM_PK_LEN {
            return Some(public_key);
        }

        if let Some(owner) = owner_identity_id {
            let did = format!("did:zhtp:{}", hex::encode(owner.as_bytes()));
            if let Some(pk) = self.identity_public_key(&did) {
                if pk.len() >= Self::MIN_DILITHIUM_PK_LEN {
                    return Some(pk);
                }
            }
        }

        warn!(
            "SOV credit skipped: short public key (len={}) and no full identity key",
            public_key.len()
        );
        None
    }

    pub(super) fn resolve_wallet_credit_pubkey(
        &self,
        wallet: &crate::transaction::WalletTransactionData,
    ) -> Option<Vec<u8>> {
        self.resolve_credit_pubkey_from_parts(
            wallet.public_key.clone(),
            wallet.owner_identity_id.clone(),
        )
    }

    pub(super) fn is_sov_token_id(token_id: &[u8; 32]) -> bool {
        *token_id == [0u8; 32] || *token_id == crate::contracts::utils::generate_lib_token_id()
    }

    pub(crate) fn wallet_key_for_sov(wallet_id: &[u8; 32]) -> PublicKey {
        crate::contracts::utils::wallet_key_for_sov(*wallet_id)
    }

    pub fn initialize_treasury_kernel(&mut self, kernel_authority: PublicKey) {
        use crate::contracts::treasury_kernel::TreasuryKernel;

        let governance_authority = kernel_authority.clone();
        self.treasury_kernel = Some(TreasuryKernel::new(
            kernel_authority,
            governance_authority,
            100,
        ));
        info!("Treasury Kernel initialized");
    }

    fn is_kernel_controlled_token(&self, token: &crate::contracts::TokenContract) -> bool {
        token.kernel_mint_authority.is_some()
    }

    pub(super) fn credit_tokens(
        &mut self,
        token: &mut crate::contracts::TokenContract,
        to: &PublicKey,
        amount: u64,
        reason: crate::contracts::treasury_kernel::CreditReason,
    ) -> Result<(), String> {
        if self.is_kernel_controlled_token(token) {
            let kernel = self.treasury_kernel.as_mut().ok_or_else(|| {
                "Treasury Kernel not initialized - kernel-controlled token operations require kernel"
                    .to_string()
            })?;
            let caller = kernel.governance_authority().clone();
            kernel
                .credit(token, &caller, to, amount, reason)
                .map_err(|e| e.to_string())
        } else {
            token.credit_balance(to, amount as u128)
        }
    }

    pub(super) fn debit_tokens(
        &mut self,
        token: &mut crate::contracts::TokenContract,
        from: &PublicKey,
        amount: u64,
        reason: crate::contracts::treasury_kernel::DebitReason,
    ) -> Result<(), String> {
        if self.is_kernel_controlled_token(token) {
            let kernel = self.treasury_kernel.as_mut().ok_or_else(|| {
                "Treasury Kernel not initialized - kernel-controlled token operations require kernel"
                    .to_string()
            })?;
            let caller = kernel.governance_authority().clone();
            kernel
                .debit(token, &caller, from, amount, reason)
                .map_err(|e| e.to_string())
        } else {
            token.debit_balance(from, amount as u128)
        }
    }

    pub(super) fn wallet_id_bytes(wallet_id_hex: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(wallet_id_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    pub fn primary_wallet_for_signer(&self, signer_key_id: &[u8; 32]) -> Option<[u8; 32]> {
        for (wallet_id, wallet) in &self.wallet_registry {
            if wallet.wallet_type != "Primary" {
                continue;
            }
            let pk = PublicKey::new(
                wallet.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
            );
            if &pk.key_id == signer_key_id {
                return Self::wallet_id_bytes(wallet_id);
            }
        }
        None
    }

    pub fn primary_wallet_id_for_signer(&self, signer_key_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.primary_wallet_for_signer(signer_key_id)
    }

    pub fn sov_key_from_wallet_id(wallet_id: &[u8; 32]) -> PublicKey {
        Self::wallet_key_for_sov(wallet_id)
    }

    pub(super) fn migrate_sov_key_balances_to_wallets(&mut self) {
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let token = match self.token_contracts.get_mut(&sov_token_id) {
            Some(token) => token,
            None => return,
        };

        let mut key_to_wallet: std::collections::HashMap<[u8; 32], [u8; 32]> =
            std::collections::HashMap::new();
        for (wallet_id, wallet) in &self.wallet_registry {
            if wallet.wallet_type != "Primary" {
                continue;
            }
            if let Some(wallet_id_bytes) = Self::wallet_id_bytes(wallet_id) {
                let pk = PublicKey::new(
                wallet.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
            );
                key_to_wallet.insert(pk.key_id, wallet_id_bytes);
            }
        }

        let mut migrated_total: u128 = 0;
        let balances: Vec<(PublicKey, u128)> = token
            .balances_iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        for (pk, bal) in balances {
            if bal == 0 {
                continue;
            }
            let key_hex = hex::encode(pk.key_id);
            if self.wallet_registry.contains_key(&key_hex) {
                continue;
            }
            if let Some(wallet_id_bytes) = key_to_wallet.get(&pk.key_id) {
                token.remove_balance(&pk);
                let wallet_key = Self::wallet_key_for_sov(wallet_id_bytes);
                let existing = token.balance_of(&wallet_key);
                token
                    .set_balance(&wallet_key, existing.saturating_add(bal));
                migrated_total = migrated_total.saturating_add(bal);
            }
        }

        if migrated_total > 0 {
            info!(
                "🪙 Migrated {} SOV from key-based balances to Primary wallets",
                migrated_total
            );
        }
    }

    pub(super) fn resolve_public_key_by_key_id(&self, key_id: &[u8; 32]) -> Option<Vec<u8>> {
        for wallet in self.wallet_registry.values() {
            if wallet.public_key.is_empty() {
                continue;
            }
            let pk = PublicKey::new(
                wallet.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
            );
            if &pk.key_id == key_id {
                return Some(wallet.public_key.clone());
            }
        }

        // #2639: resolve from sled identity metadata first. The in-memory
        // identity_registry is empty on a store-backed node after restart, which
        // would fail to resolve a recipient's public key by key_id during
        // TokenTransfer / TokenMint execution (consensus path).
        if let Some(store) = self.get_store() {
            match store.iter_identity_metadata() {
                Ok(iter) => {
                    for meta in iter {
                        if let Ok(pk_arr) = meta.public_key.as_slice().try_into() {
                            let pk = PublicKey::new(pk_arr);
                            if &pk.key_id == key_id {
                                return Some(meta.public_key);
                            }
                        }
                    }
                }
                // Scan error on a store-backed node: on the consensus path
                // (TokenTransfer / TokenMint execution), masking this as
                // "not found" would silently fail recipient resolution and
                // looks identical to "unknown identity" — exactly the silent
                // post-restart failure mode #2639 exists to remove. Log
                // loudly so operators see the underlying error rather than
                // blaming consensus; still fall through to the in-memory
                // shadow so the legitimate pending pre-commit path keeps
                // working (CR PR #2678).
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "resolve_public_key_by_key_id: iter_identity_metadata failed; falling back to in-memory shadow"
                    );
                }
            }
        }
        // In-memory fallback (store-less, or a pending pre-commit identity).
        for identity in self.identity_registry.values() {
            if let Ok(pk_arr) = identity.public_key.as_slice().try_into() {
                let pk = PublicKey::new(pk_arr);
                if &pk.key_id == key_id {
                    return Some(identity.public_key.clone());
                }
            }
        }

        None
    }

    pub fn collect_sov_backfill_entries(&self) -> Vec<([u8; 32], u128, String)> {
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let token_opt = self.token_contracts.get(&sov_token_id);

        let mut entries: Vec<([u8; 32], u128, String)> = Vec::new();
        for (wallet_id, wallet) in &self.wallet_registry {
            let is_on_chain = self
                .wallet_blocks
                .get(wallet_id)
                .map(|h| *h <= self.height)
                .unwrap_or(false);
            if !is_on_chain || wallet.initial_balance == 0 {
                continue;
            }
            let wallet_key = match Self::wallet_id_bytes(wallet_id) {
                Some(bytes) => bytes,
                None => {
                    warn!(
                        "Skipping SOV backfill for wallet {}: invalid wallet_id",
                        &wallet_id[..16.min(wallet_id.len())]
                    );
                    continue;
                }
            };

            let recipient = Self::wallet_key_for_sov(&wallet_key);
            let current_balance: u128 = if let Some(store) = self.get_store() {
                let sov_storage_token_id = crate::storage::TokenId(sov_token_id);
                let addr = crate::storage::Address::new(wallet_key);
                store
                    .get_token_balance(&sov_storage_token_id, &addr)
                    .unwrap_or(0) as u128
            } else {
                token_opt
                    .map(|token| token.balance_of(&recipient))
                    .unwrap_or(0)
            };
            if current_balance > 0 {
                continue;
            }
            entries.push((wallet_key, wallet.initial_balance, wallet_id.clone()));
        }
        entries
    }

    /// Idempotently persist in-memory genesis SOV mints to sled before the first
    /// executor block apply (fresh-node import pins block 0 in-memory only).
    pub fn persist_genesis_sov_allocations_to_store(&self) -> Result<()> {
        let Some(store) = self.get_store() else {
            return Ok(());
        };
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let entries: Vec<([u8; 32], u128)> = self
            .token_contracts
            .get(&sov_token_id)
            .map(|token| {
                token
                    .balances_iter()
                    .map(|(pk, &bal)| (pk.key_id, bal))
                    .collect()
            })
            .unwrap_or_default();
        if entries.is_empty() {
            return Ok(());
        }
        let token_id = crate::storage::TokenId::new(sov_token_id);
        match store.backfill_token_balances_from_contract(&token_id, &entries) {
            Ok(n) if n > 0 => info!(
                "💰 Persisted {} genesis SOV balances to token_balances tree",
                n
            ),
            Ok(_) => {}
            Err(e) => warn!(
                "⚠️ Failed to persist genesis SOV balances to sled: {}",
                e
            ),
        }
        Ok(())
    }

    /// Zero out SOV balances that were incorrectly minted to UBI and Savings wallets
    /// by a bug in the recovery migration.  The bug set `initial_balance = 5 000 SOV`
    /// for every wallet whose sled balance was 0, regardless of wallet type.  Only
    /// Primary wallets should have received the welcome bonus.
    ///
    /// Safe to call at startup (before block processing) or during load_from_file.
    /// Wallets with a balance that differs from the canonical bonus (meaning they
    /// received legitimate transfers on top) are left untouched.
    pub fn correct_ubi_savings_misbalances(&mut self) -> usize {
        const WRONG_BONUS: u128 = 500_000_000_000; // 5 000 SOV in old 8-decimal atomic units

        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let sov_storage_token_id = crate::storage::TokenId(sov_token_id);

        // Collect wallet_ids that need correction first (avoid borrow conflicts).
        let to_correct: Vec<([u8; 32], String)> = self
            .wallet_registry
            .iter()
            .filter_map(|(wallet_id_hex, w)| {
                if w.wallet_type == "Primary" {
                    return None;
                }
                if w.initial_balance != WRONG_BONUS {
                    return None;
                }
                let bytes = Self::wallet_id_bytes(wallet_id_hex)?;
                Some((bytes, wallet_id_hex.clone()))
            })
            .collect();

        if to_correct.is_empty() {
            return 0;
        }

        let mut corrected = 0usize;

        // Build sled correction entries (balance = 0 → removes the key).
        // TokenId is Copy so we can use it directly in the closure.
        let sled_entries: Vec<(crate::storage::TokenId, crate::storage::Address, u128)> = to_correct
            .iter()
            .map(|(bytes, _)| (sov_storage_token_id, crate::storage::Address::new(*bytes), 0u128))
            .collect();

        // Apply sled correction outside of block transaction.
        if let Some(store) = self.get_store() {
            match store.force_set_token_balances(&sled_entries) {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(
                            "correct_ubi_savings_misbalances: zeroed {} sled balance entries for non-Primary wallets",
                            n
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    "correct_ubi_savings_misbalances: sled correction failed: {}",
                    e
                ),
            }
        }

        // Correct the in-memory token_contracts balances.
        for (bytes, wallet_id_hex) in &to_correct {
            let wallet_key = Self::wallet_key_for_sov(bytes);
            if let Some(token) = self.token_contracts.get_mut(&sov_token_id) {
                let bal = token.balance_of(&wallet_key);
                if bal == WRONG_BONUS as u128 {
                    if let Err(e) = token.burn(&wallet_key, WRONG_BONUS as u128) {
                        tracing::warn!(
                            "correct_ubi_savings_misbalances: burn failed for {}: {}",
                            &wallet_id_hex[..16.min(wallet_id_hex.len())],
                            e
                        );
                        continue;
                    }
                    corrected += 1;
                }
            }
            // Reset the registry record so collect_sov_backfill_entries doesn't re-mint it.
            if let Some(w) = self.wallet_registry.get_mut(wallet_id_hex.as_str()) {
                w.initial_balance = 0;
            }
        }

        if corrected > 0 {
            tracing::info!(
                "correct_ubi_savings_misbalances: corrected {} UBI/Savings wallets (removed erroneous 5 000 SOV bonus)",
                corrected
            );
        }

        corrected
    }

    pub fn repair_backfill_inflation(&self) -> usize {
        let store = match self.get_store() {
            Some(s) => s,
            None => return 0,
        };

        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let sov_storage_token_id = crate::storage::TokenId(sov_token_id);
        let mut mint_history: std::collections::HashMap<[u8; 32], Vec<u128>> =
            std::collections::HashMap::new();

        for h in 0..=self.height {
            let block = match store.get_block_by_height(h) {
                Ok(Some(b)) => b,
                _ => continue,
            };
            for tx in &block.transactions {
                if tx.transaction_type != crate::types::transaction_type::TransactionType::TokenMint
                {
                    continue;
                }
                let is_backfill = std::str::from_utf8(&tx.memo)
                    .map(|s| s.starts_with("TOKEN_BACKFILL_V1:"))
                    .unwrap_or(false);
                if !is_backfill {
                    continue;
                }
                if let Some(mint_data) = tx.token_mint_data() {
                    mint_history
                        .entry(mint_data.to)
                        .or_default()
                        .push(mint_data.amount);
                }
            }
        }

        let mut corrections: Vec<(crate::storage::TokenId, crate::storage::Address, u128)> =
            Vec::new();

        for (wallet_key, amounts) in &mint_history {
            if amounts.len() == 1 {
                let mint_amount = amounts[0];
                let wallet_id_hex = hex::encode(wallet_key);
                let initial_balance = self
                    .wallet_registry
                    .get(&wallet_id_hex)
                    .map(|w| w.initial_balance as u128)
                    .unwrap_or(0);
                if initial_balance > 0 && mint_amount < initial_balance {
                    let addr = crate::storage::Address::new(*wallet_key);
                    let current = store
                        .get_token_balance(&sov_storage_token_id, &addr)
                        .unwrap_or(0);
                    if current > initial_balance {
                        let corrected = current - mint_amount;
                        info!(
                            "🔧 Correcting spurious partial backfill for wallet {}: {} → {} (removed spurious partial mint of {})",
                            hex::encode(&wallet_key[..8]),
                            current,
                            corrected,
                            mint_amount
                        );
                        corrections.push((sov_storage_token_id, addr, corrected));
                    }
                }
                continue;
            }
            let excess: u128 = amounts[1..].iter().sum();
            let addr = crate::storage::Address::new(*wallet_key);
            let current = store
                .get_token_balance(&sov_storage_token_id, &addr)
                .unwrap_or(0);
            if current >= excess {
                let corrected = current - excess;
                info!(
                    "🔧 Correcting backfill inflation for wallet {}: {} → {} ({} duplicate mints, removing {} excess)",
                    hex::encode(&wallet_key[..8]),
                    current,
                    corrected,
                    amounts.len() - 1,
                    excess
                );
                corrections.push((sov_storage_token_id, addr, corrected));
            } else {
                warn!(
                    "⚠️ Cannot correct backfill inflation for wallet {}: current {} < excess {}",
                    hex::encode(&wallet_key[..8]),
                    current,
                    excess
                );
            }
        }

        let count = corrections.len();
        if count > 0 {
            match store.force_set_token_balances(&corrections) {
                Ok(_) => info!("🔧 Repaired backfill inflation for {} wallets", count),
                Err(e) => warn!("⚠️ Failed to write backfill corrections: {}", e),
            }
        }
        count
    }

    /// Legacy in-memory shadow insert — genesis/bootstrap only (#2640).
    pub fn insert_wallet_shadow(
        &mut self,
        wallet_id: String,
        data: crate::transaction::WalletTransactionData,
    ) {
        self.wallet_registry.insert(wallet_id, data);
    }

    /// Cardinality of the in-memory wallet shadow only (audit / divergence tooling).
    pub fn wallet_registry_shadow_len(&self) -> usize {
        self.wallet_registry.len()
    }

    /// Patch initial_balance on an in-memory wallet shadow entry (welcome-bonus warmup).
    pub fn update_wallet_shadow_initial_balance(&mut self, wallet_id: &str, balance: u128) -> bool {
        if let Some(entry) = self.wallet_registry.get_mut(wallet_id) {
            entry.initial_balance = balance;
            true
        } else {
            false
        }
    }

    /// Wallets owned by an identity in the in-memory shadow only (O(N) over
    /// `wallet_registry`, not sled). Do not call per-identity inside tight loops
    /// on store-backed nodes with large wallet projections.
    pub fn wallets_for_owner(
        &self,
        owner_identity_id: &crate::types::Hash,
    ) -> Vec<(String, crate::transaction::WalletTransactionData)> {
        self.wallet_registry
            .iter()
            .filter(|(_, wallet)| wallet.owner_identity_id.as_ref() == Some(owner_identity_id))
            .map(|(wallet_id, wallet)| (wallet_id.clone(), wallet.clone()))
            .collect()
    }

    /// Register a wallet via the trusted system-injection path.
    ///
    /// **Trusted callers** (in-process only — not mempool-admitted):
    /// - `zhtp` citizenship / identity handlers (`identity/mod.rs`)
    /// - `zhtp` runtime wallet bootstrap (`runtime/mod.rs`, `runtime/components/identity.rs`)
    /// - `zhtp` mesh identity API (`server/mesh/identity_api.rs`)
    /// - `zhtp` wallet provisioning handler (`api/handlers/wallet/mod.rs`)
    /// - Genesis allocation replay (`blockchain/contracts.rs`)
    ///
    /// Welcome-bonus SOV (`initial_balance > 0`) is only minted in-memory during
    /// `apply_genesis_state`. At `height > 0`, callers must set `initial_balance = 0`
    /// and submit a separate treasury-signed [`TransactionType::TokenMint`].
    pub fn register_wallet(
        &mut self,
        wallet_data: crate::transaction::WalletTransactionData,
    ) -> Result<Hash> {
        let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
        if self.wallet_exists(&wallet_id_str) {
            return Err(anyhow::anyhow!(
                "Wallet {} already exists on blockchain",
                wallet_id_str
            ));
        }

        // Never embed SOV mint amount in the WalletRegistration tx — executor and
        // mempool reject initial_balance > 0 unless treasury-authorized. Bonus
        // SOV is credited via the trusted in-memory mint path below.
        let mut registration_data = wallet_data.clone();
        registration_data.initial_balance = 0;

        let registration_tx = Transaction::new_wallet_registration(
            registration_data,
            vec![],
            Signature {
                signature: wallet_data.public_key.clone(),
                public_key: PublicKey::new(
                    wallet_data.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
                ),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: wallet_data.created_at,
            },
            format!("Wallet registration for {}", wallet_data.wallet_name).into_bytes(),
        );

        self.add_system_transaction(registration_tx.clone(), "auto_wallet_registration")?;
        self.wallet_registry
            .insert(wallet_id_str.clone(), wallet_data.clone());
        self.wallet_blocks
            .insert(wallet_id_str.clone(), self.height + 1);

        if wallet_data.initial_balance > 0 {
            if !self.is_applying_genesis_state() {
                return Err(anyhow::anyhow!(
                    "register_wallet initial_balance={} rejected at height {}: \
                     submit a treasury-signed TokenMint instead of in-memory mint",
                    wallet_data.initial_balance,
                    self.height
                ));
            }
            let sov_token_id = crate::contracts::utils::generate_lib_token_id();
            self.ensure_sov_token_contract();
            let mut wallet_id_bytes_arr = [0u8; 32];
            wallet_id_bytes_arr.copy_from_slice(wallet_data.wallet_id.as_bytes());
            let recipient_pk = Self::wallet_key_for_sov(&wallet_id_bytes_arr);
            if let Some(token) = self.token_contracts.get_mut(&sov_token_id) {
                if token.balance_of(&recipient_pk) == 0 {
                    if let Err(e) = token.mint(&recipient_pk, wallet_data.initial_balance as u128) {
                        warn!(
                            "register_wallet: genesis bootstrap mint failed {} SOV for {}: {}",
                            wallet_data.initial_balance,
                            &wallet_id_str[..16.min(wallet_id_str.len())],
                            e
                        );
                    } else {
                        info!(
                            "💰 register_wallet: genesis bootstrap minted {} SOV for wallet {}",
                            wallet_data.initial_balance,
                            &wallet_id_str[..16.min(wallet_id_str.len())]
                        );
                    }
                }
            }
        }

        Ok(registration_tx.hash())
    }

    pub fn create_funding_utxo(
        &mut self,
        wallet_id: &str,
        recipient_identity: &[u8],
        amount: u128,
    ) -> Hash {
        let utxo_output = crate::transaction::TransactionOutput {
            commitment: crate::types::hash::blake3_hash(
                format!("funding_commitment_{}_{}", wallet_id, amount).as_bytes(),
            ),
            note: crate::types::hash::blake3_hash(format!("funding_note_{}", wallet_id).as_bytes()),
            recipient: PublicKey::new(
                recipient_identity.try_into().unwrap_or([0u8; 2592])
            ),
                        merkle_leaf: Hash::default(),
};
        let utxo_hash = crate::types::hash::blake3_hash(
            format!("funding_utxo:{}:{}", wallet_id, amount).as_bytes(),
        );
        self.utxo_set.insert(utxo_hash, utxo_output);
        info!(
            "💰 Created funding UTXO: {} SOV for wallet {}",
            amount,
            &wallet_id[..16.min(wallet_id.len())]
        );
        utxo_hash
    }

    pub fn get_wallet(
        &self,
        wallet_id: &str,
    ) -> Option<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.get(wallet_id)
    }

    fn wallet_id_bytes_from_hex(wallet_id_hex: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(wallet_id_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    /// Union existence check across the in-memory shadow and durable sled (#2639).
    ///
    /// Checks the in-memory `wallet_registry` FIRST, then sled wallet projections.
    /// Same ordering rationale as `identity_exists`: same-block / mempool wallets
    /// are visible in-mem before commit; sled catches post-restart durable state.
    pub fn wallet_exists(&self, wallet_id: &str) -> bool {
        if self.wallet_registry.contains_key(wallet_id) {
            return true;
        }
        if let Some(store) = self.get_store() {
            let Some(wallet_id_bytes) = Self::wallet_id_bytes_from_hex(wallet_id) else {
                tracing::warn!(
                    wallet_id = %wallet_id,
                    "wallet_exists: invalid wallet_id hex; treating as absent"
                );
                return false;
            };
            match store.get_wallet_projection(&wallet_id_bytes) {
                Ok(found) => return found.is_some(),
                Err(e) => {
                    tracing::warn!(
                        wallet_id = %wallet_id,
                        error = %e,
                        "wallet_exists: sled read failed; treating as not-in-sled"
                    );
                }
            }
        }
        false
    }

    /// Sled-first wallet record for handlers needing full `WalletTransactionData` (#2639).
    ///
    /// Returns an owned record from durable wallet projections when the store
    /// is attached, with the in-memory shadow as the pre-commit / store-less fallback.
    pub fn wallet_transaction_data(
        &self,
        wallet_id_hex: &str,
    ) -> Option<crate::transaction::WalletTransactionData> {
        if let Some(store) = self.get_store() {
            if let Some(wallet_id_bytes) = Self::wallet_id_bytes_from_hex(wallet_id_hex) {
                if let Ok(Some(record)) = store.get_wallet_projection(&wallet_id_bytes) {
                    return Some(record.wallet_data);
                }
            }
        }
        self.wallet_registry.get(wallet_id_hex).cloned()
    }

    /// Sled-first snapshot for backfill / iteration (#2639).
    ///
    /// Builds a map from durable wallet projections, then overlays the in-memory
    /// shadow (pending / same-block registrations win).
    pub fn wallet_registry_snapshot(
        &self,
    ) -> HashMap<String, crate::transaction::WalletTransactionData> {
        let mut out = HashMap::new();
        if let Some(store) = self.get_store() {
            match store.iter_wallet_projections() {
                Ok(iter) => {
                    for (wallet_id, record) in iter {
                        out.insert(hex::encode(wallet_id), record.wallet_data);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "wallet_registry_snapshot: sled iter failed; using in-memory shadow only"
                    );
                }
            }
        }
        for (wallet_id_hex, data) in &self.wallet_registry {
            out.insert(wallet_id_hex.clone(), data.clone());
        }
        out
    }

    /// Authoritative wallet count from sled when attached (#2639).
    ///
    /// Returns durable sled cardinality only — NOT a union with the in-memory
    /// shadow (unlike [`wallet_registry_snapshot`].len()). Pending same-block
    /// wallets are visible via the snapshot, not this count.
    pub fn wallet_count(&self) -> usize {
        if let Some(store) = self.get_store() {
            match store.count_wallet_projections() {
                Ok(n) => return n,
                Err(e) => {
                    tracing::warn!(error = %e, "wallet_count: sled count failed; using in-memory shadow");
                }
            }
        }
        self.wallet_registry.len()
    }

    pub fn list_all_wallets(&self) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.values().collect()
    }

    pub fn get_all_wallets(&self) -> &HashMap<String, crate::transaction::WalletTransactionData> {
        &self.wallet_registry
    }

    pub fn get_wallet_confirmations(&self, wallet_id: &str) -> Option<u64> {
        self.wallet_blocks.get(wallet_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    pub fn get_wallets_for_owner(
        &self,
        owner_identity_id: &Hash,
    ) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry
            .values()
            .filter(|wallet| wallet.owner_identity_id.as_ref() == Some(owner_identity_id))
            .collect()
    }

    pub fn process_wallet_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if matches!(
                transaction.transaction_type,
                TransactionType::WalletRegistration | TransactionType::WalletUpdate
            ) {
                if let Some(wallet_data) = transaction.wallet_data() {
                    let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
                    self.wallet_registry
                        .insert(wallet_id_str.clone(), wallet_data.clone());
                    self.wallet_blocks
                        .insert(wallet_id_str.clone(), block.height());

                    // Executor mode mints initial SOV to sled in apply_block; in-memory
                    // mint here would be a second write source (#2641).
                    if !self.has_executor()
                        && transaction.transaction_type == TransactionType::WalletRegistration
                        && wallet_data.initial_balance > 0
                    {
                        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
                        self.ensure_sov_token_contract();

                        let mut wallet_id_bytes = [0u8; 32];
                        wallet_id_bytes.copy_from_slice(wallet_data.wallet_id.as_bytes());
                        let recipient_pk = Self::wallet_key_for_sov(&wallet_id_bytes);

                        let current_balance = self
                            .token_contracts
                            .get(&sov_token_id)
                            .map(|token| token.balance_of(&recipient_pk))
                            .unwrap_or(0);
                        let target = wallet_data.initial_balance as u128;
                        let deficit = target.saturating_sub(current_balance);
                        if deficit > 0 {
                            if let Some(token) = self.token_contracts.get_mut(&sov_token_id) {
                                if let Err(e) = token.mint(&recipient_pk, deficit) {
                                    warn!(
                                        "Failed to mint {} SOV for wallet {}: {}",
                                        deficit,
                                        &wallet_id_str[..16.min(wallet_id_str.len())],
                                        e
                                    );
                                }
                            }
                        }
                        // In-memory mint is sufficient — the block commit persists all state.
                        // Do NOT call put_token_contract here: it requires an active sled
                        // block transaction which may not exist when register_wallet() is
                        // called from the API handler outside block processing.
                    }
                }
            }
        }
        Ok(())
    }
}

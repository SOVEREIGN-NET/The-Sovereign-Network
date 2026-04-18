use super::*;

/// Minimum stake required for gateway registration (micro-SOV).
/// 10 000 SOV = 10 000_000_000 micro-SOV.
pub const GATEWAY_MIN_STAKE: u64 = 10_000_000_000;

/// Minimum stake for testnet / genesis (micro-SOV).
pub const GATEWAY_MIN_STAKE_GENESIS: u64 = 1_000;

/// Number of blocks without heartbeat before a gateway is considered stale.
pub const GATEWAY_HEARTBEAT_BLOCKS: u64 = 720; // ~1 hour at 5s block time

/// Number of slash events before a gateway is permanently removed.
pub const GATEWAY_MAX_SLASHES: u32 = 3;

impl Blockchain {
    /// Register a new gateway on-chain.
    ///
    /// Requirements:
    /// - Identity must already exist in `identity_registry`.
    /// - Gateway key must be a full Dilithium5 public key (2592 bytes).
    /// - Stake must meet minimum.
    pub fn register_gateway(&mut self, gateway_info: GatewayInfo) -> Result<Hash> {
        if self.gateway_registry.contains_key(&gateway_info.identity_id) {
            return Err(anyhow::anyhow!(
                "Gateway {} already exists on blockchain",
                gateway_info.identity_id
            ));
        }

        if !self.identity_registry.contains_key(&gateway_info.identity_id) {
            return Err(anyhow::anyhow!(
                "Identity {} must be registered before becoming a gateway",
                gateway_info.identity_id
            ));
        }

        if gateway_info.gateway_key == [0u8; 2592] {
            return Err(anyhow::anyhow!("Gateway key must not be empty"));
        }

        let min_stake = if self.height == 0 {
            GATEWAY_MIN_STAKE_GENESIS
        } else {
            GATEWAY_MIN_STAKE
        };
        if gateway_info.stake < min_stake {
            return Err(anyhow::anyhow!(
                "Insufficient stake for gateway: {} micro-SOV (minimum: {} required)",
                gateway_info.stake,
                min_stake
            ));
        }

        let gateway_tx_data = IdentityTransactionData {
            did: gateway_info.identity_id.clone(),
            display_name: format!("Gateway: {}", gateway_info.endpoints),
            public_key: gateway_info.gateway_key.to_vec(),
            ownership_proof: vec![],
            identity_type: "gateway".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!(
                    "gateway:{}:{}",
                    gateway_info.identity_id, gateway_info.registered_at
                )
                .as_bytes(),
            ),
            created_at: gateway_info.registered_at,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        let registration_tx = Transaction::new_identity_registration(
            gateway_tx_data,
            vec![],
            Signature {
                signature: gateway_info.gateway_key.to_vec(),
                public_key: PublicKey::new(gateway_info.gateway_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: gateway_info.registered_at,
            },
            format!(
                "Gateway registration for {} with stake {}",
                gateway_info.identity_id, gateway_info.stake
            )
            .into_bytes(),
        );

        self.add_pending_transaction(registration_tx.clone())?;
        self.gateway_registry
            .insert(gateway_info.identity_id.clone(), gateway_info.clone());
        self.gateway_blocks
            .insert(gateway_info.identity_id.clone(), self.height + 1);

        info!(
            " Gateway {} registered with {} micro-SOV stake at endpoints {}",
            gateway_info.identity_id, gateway_info.stake, gateway_info.endpoints
        );

        Ok(registration_tx.hash())
    }

    pub fn get_gateway(&self, identity_id: &str) -> Option<&GatewayInfo> {
        self.gateway_registry.get(identity_id)
    }

    pub fn gateway_exists(&self, identity_id: &str) -> bool {
        self.gateway_registry.contains_key(identity_id)
    }

    pub fn list_all_gateways(&self) -> Vec<&GatewayInfo> {
        self.gateway_registry.values().collect()
    }

    pub fn get_active_gateways(&self) -> Vec<&GatewayInfo> {
        self.gateway_registry
            .values()
            .filter(|g| g.status == "active")
            .collect()
    }

    pub fn get_all_gateways(&self) -> &HashMap<String, GatewayInfo> {
        &self.gateway_registry
    }

    pub fn update_gateway(
        &mut self,
        identity_id: &str,
        updated_info: GatewayInfo,
    ) -> Result<Hash> {
        if !self.gateway_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!(
                "Gateway {} not found on blockchain",
                identity_id
            ));
        }

        let gateway_tx_data = IdentityTransactionData {
            did: updated_info.identity_id.clone(),
            display_name: format!("Gateway Update: {}", updated_info.endpoints),
            public_key: updated_info.gateway_key.to_vec(),
            ownership_proof: vec![],
            identity_type: "gateway".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!(
                    "gateway_update:{}:{}",
                    updated_info.identity_id, updated_info.last_activity
                )
                .as_bytes(),
            ),
            created_at: updated_info.last_activity,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        let update_tx = Transaction::new_identity_update(
            gateway_tx_data,
            vec![],
            vec![],
            100,
            Signature {
                signature: updated_info.gateway_key.to_vec(),
                public_key: PublicKey::new(updated_info.gateway_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: updated_info.last_activity,
            },
            format!("Gateway update for {}", identity_id).into_bytes(),
        );

        self.add_pending_transaction(update_tx.clone())?;
        self.gateway_registry
            .insert(identity_id.to_string(), updated_info);

        Ok(update_tx.hash())
    }

    pub fn unregister_gateway(&mut self, identity_id: &str) -> Result<Hash> {
        if !self.gateway_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!(
                "Gateway {} not found on blockchain",
                identity_id
            ));
        }

        let mut gateway_info = self.gateway_registry.get(identity_id).unwrap().clone();
        gateway_info.status = "inactive".to_string();

        let unregister_tx = Transaction::new_identity_revocation(
            identity_id.to_string(),
            vec![],
            100,
            Signature {
                signature: gateway_info.gateway_key.to_vec(),
                public_key: PublicKey::new(gateway_info.gateway_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: gateway_info.last_activity,
            },
            format!("Gateway unregistration for {}", identity_id).into_bytes(),
        );

        self.add_pending_transaction(unregister_tx.clone())?;
        self.gateway_registry
            .insert(identity_id.to_string(), gateway_info);

        info!("Gateway {} unregistered", identity_id);

        Ok(unregister_tx.hash())
    }

    /// Slash a gateway for misbehavior.
    ///
    /// Each slash increments `slash_count`. After `GATEWAY_MAX_SLASHES`
    /// the gateway status is set to "slashed" and it can no longer forward
    /// traffic.  A portion of stake may be burned or redirected to the DAO
    /// treasury (governance decides exact economics).
    pub fn slash_gateway(&mut self, identity_id: &str, _reason: &str) -> Result<()> {
        let gateway_info = self
            .gateway_registry
            .get_mut(identity_id)
            .ok_or_else(|| anyhow::anyhow!("Gateway {} not found", identity_id))?;

        gateway_info.slash_count += 1;
        gateway_info.last_activity = self.height;

        if gateway_info.slash_count >= GATEWAY_MAX_SLASHES {
            gateway_info.status = "slashed".to_string();
            warn!(
                "Gateway {} slashed permanently ({} / {} offenses)",
                identity_id, gateway_info.slash_count, GATEWAY_MAX_SLASHES
            );
        } else {
            gateway_info.status = "jailed".to_string();
            warn!(
                "Gateway {} jailed ({} / {} offenses)",
                identity_id, gateway_info.slash_count, GATEWAY_MAX_SLASHES
            );
        }

        Ok(())
    }

    pub fn get_gateway_confirmations(&self, identity_id: &str) -> Option<u64> {
        self.gateway_blocks.get(identity_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    pub fn is_gateway_active(&self, identity_id: &str) -> bool {
        self.gateway_registry
            .get(identity_id)
            .map(|g| g.status == "active" && g.stake > 0)
            .unwrap_or(false)
    }

    pub fn is_gateway_heartbeat_current(&self, identity_id: &str) -> bool {
        self.gateway_registry
            .get(identity_id)
            .map(|g| {
                g.status == "active"
                    && self.height.saturating_sub(g.last_activity) <= GATEWAY_HEARTBEAT_BLOCKS
            })
            .unwrap_or(false)
    }

    /// Process gateway transactions from a block (registration / update / unregister).
    pub fn process_gateway_transactions(&mut self, block: &Block) {
        let height = block.height();
        for tx in &block.transactions {
            if let Some(gateway_data) = tx.gateway_data() {
                let status = match gateway_data.operation {
                    crate::transaction::GatewayOperation::Register => "active",
                    crate::transaction::GatewayOperation::Update => "active",
                    crate::transaction::GatewayOperation::Unregister => "inactive",
                };
                let gateway_info = GatewayInfo {
                    identity_id: gateway_data.identity_id.clone(),
                    stake: gateway_data.stake,
                    gateway_key: gateway_data.gateway_key.as_slice().try_into().unwrap_or([0u8; 2592]),
                    endpoints: gateway_data.endpoints.clone(),
                    commission_rate: gateway_data.commission_rate,
                    status: status.to_string(),
                    registered_at: height,
                    last_activity: height,
                    requests_forwarded: 0,
                    slash_count: 0,
                    accumulated_revenue: 0,
                    admission_source: ADMISSION_SOURCE_ONCHAIN_GOVERNANCE.to_string(),
                };
                self.gateway_registry
                    .insert(gateway_data.identity_id.clone(), gateway_info);
                self.gateway_blocks
                    .insert(gateway_data.identity_id.clone(), height);
                info!(
                    "Registered new gateway {} with {} micro-SOV stake at {}",
                    &gateway_data.identity_id[..gateway_data.identity_id.len().min(40)],
                    gateway_data.stake,
                    gateway_data.endpoints
                );
            }
        }
    }

    /// Record a forwarded request for revenue tracking.
    /// Called by validators when they receive traffic with valid gateway context.
    pub fn record_gateway_request(&mut self, identity_id: &str) {
        if let Some(gateway) = self.gateway_registry.get_mut(identity_id) {
            gateway.requests_forwarded = gateway.requests_forwarded.saturating_add(1);
        }
    }

    /// Accrue revenue to a gateway (in micro-SOV).
    pub fn accrue_gateway_revenue(&mut self, identity_id: &str, amount: u64) {
        if let Some(gateway) = self.gateway_registry.get_mut(identity_id) {
            gateway.accumulated_revenue = gateway.accumulated_revenue.saturating_add(amount);
        }
    }
}

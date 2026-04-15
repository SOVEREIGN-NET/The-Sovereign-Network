//! CBE Token API Handler
//!
//! Three endpoints for Bootstrap Council and operator CBE operations:
//!
//! | Method | Path                              | Description                         |
//! |--------|-----------------------------------|-------------------------------------|
//! | POST   | /api/v1/cbe/init                  | InitCbeToken — one-time pool init   |
//! | POST   | /api/v1/cbe/employment/create     | CreateEmploymentContract            |
//! | POST   | /api/v1/cbe/payroll/process       | ProcessPayroll + CBE transfer       |

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use lib_blockchain::transaction::Transaction;
use lib_blockchain::types::transaction_type::TransactionType;
use lib_blockchain::Blockchain;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

// ============================================================================
// Shared helpers
// ============================================================================

fn json_ok(data: serde_json::Value) -> Result<ZhtpResponse> {
    Ok(ZhtpResponse::success_with_content_type(
        serde_json::to_vec(&data)?,
        "application/json".to_string(),
        None,
    ))
}

fn err(status: ZhtpStatus, msg: impl Into<String>) -> ZhtpResponse {
    ZhtpResponse::error(status, msg.into())
}

// ============================================================================
// CbeHandler
// ============================================================================

pub struct CbeHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl CbeHandler {
    pub fn new() -> Self {
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });
        Self { blockchain }
    }

    fn decode_tx(&self, signed_tx: &str) -> Result<Transaction> {
        let bytes =
            hex::decode(signed_tx).map_err(|_| anyhow::anyhow!("signed_tx is not valid hex"))?;
        bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("signed_tx deserialization failed: {}", e))
    }

    async fn submit(&self, tx: Transaction) -> Result<()> {
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("mempool rejected tx: {}", e))
    }

    // ------------------------------------------------------------------
    // POST /api/v1/cbe/init
    // ------------------------------------------------------------------

    async fn handle_init(&self, req: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }

        let body: Req = serde_json::from_slice(&req.body)
            .map_err(|e| anyhow::anyhow!("invalid request body: {}", e))?;

        let tx = match self.decode_tx(&body.signed_tx) {
            Ok(t) => t,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, e.to_string())),
        };

        if tx.transaction_type != TransactionType::InitCbeToken {
            return Ok(err(
                ZhtpStatus::BadRequest,
                format!(
                    "expected InitCbeToken transaction, got {:?}",
                    tx.transaction_type
                ),
            ));
        }

        // Reject if CBE token is already initialized
        {
            let bc = self.blockchain.read().await;
            // CBE token state removed from Blockchain struct (EPIC-001).
            // InitCbeToken transactions are always rejected now.
            if true {
                return Ok(err(
                    ZhtpStatus::Conflict,
                    "CBE token is already initialized".to_string(),
                ));
            }
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        if let Err(e) = self.submit(tx).await {
            return Ok(err(ZhtpStatus::BadRequest, e.to_string()));
        }

        info!("InitCbeToken submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }

    // ------------------------------------------------------------------
    // POST /api/v1/cbe/employment/create
    // ------------------------------------------------------------------

    async fn handle_create_employment(&self, req: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }

        let body: Req = serde_json::from_slice(&req.body)
            .map_err(|e| anyhow::anyhow!("invalid request body: {}", e))?;

        let tx = match self.decode_tx(&body.signed_tx) {
            Ok(t) => t,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, e.to_string())),
        };

        if tx.transaction_type != TransactionType::CreateEmploymentContract {
            return Ok(err(
                ZhtpStatus::BadRequest,
                format!(
                    "expected CreateEmploymentContract transaction, got {:?}",
                    tx.transaction_type
                ),
            ));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        if let Err(e) = self.submit(tx).await {
            return Ok(err(ZhtpStatus::BadRequest, e.to_string()));
        }

        info!("CreateEmploymentContract submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }

    // ------------------------------------------------------------------
    // POST /api/v1/cbe/payroll/process
    // ------------------------------------------------------------------

    async fn handle_process_payroll(&self, req: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }

        let body: Req = serde_json::from_slice(&req.body)
            .map_err(|e| anyhow::anyhow!("invalid request body: {}", e))?;

        let tx = match self.decode_tx(&body.signed_tx) {
            Ok(t) => t,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, e.to_string())),
        };

        if tx.transaction_type != TransactionType::ProcessPayroll {
            return Ok(err(
                ZhtpStatus::BadRequest,
                format!(
                    "expected ProcessPayroll transaction, got {:?}",
                    tx.transaction_type
                ),
            ));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        if let Err(e) = self.submit(tx).await {
            return Ok(err(ZhtpStatus::BadRequest, e.to_string()));
        }

        info!("ProcessPayroll submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for CbeHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("CBE handler: {} {}", request.method, request.uri);

        let result = match (request.method.clone(), request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/cbe/init") => self.handle_init(request).await,
            (ZhtpMethod::Post, "/api/v1/cbe/employment/create") => {
                self.handle_create_employment(request).await
            }
            (ZhtpMethod::Post, "/api/v1/cbe/payroll/process") => {
                self.handle_process_payroll(request).await
            }
            _ => Ok(err(
                ZhtpStatus::NotFound,
                "Unknown CBE endpoint".to_string(),
            )),
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => Ok(err(ZhtpStatus::InternalServerError, e.to_string())),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/cbe")
    }
}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wasmi::{self, Engine, Module, Store, Linker};

/// Contract metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Contract unique identifier
    pub id: String,
    /// Contract owner address
    pub owner: String,
    /// Contract WASM bytecode
    pub bytecode: Vec<u8>,
    /// Contract interface (ABI)
    pub interface: ContractInterface,
    /// Contract state
    pub state: HashMap<String, Vec<u8>>,
}

/// Contract interface definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInterface {
    /// Contract name
    pub name: String,
    /// Contract version
    pub version: String,
    /// Contract methods
    pub methods: Vec<ContractMethod>,
    /// Contract events
    pub events: Vec<ContractEvent>,
}

/// Contract method definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMethod {
    /// Method name
    pub name: String,
    /// Method inputs
    pub inputs: Vec<MethodParam>,
    /// Method outputs
    pub outputs: Vec<MethodParam>,
    /// Is method payable
    pub payable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodParam {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
}

/// Contract event definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    /// Event name
    pub name: String,
    /// Event parameters
    pub parameters: Vec<MethodParam>,
}

/// WASM Contract executor
pub struct ContractExecutor {
    /// Contracts storage
    contracts: Arc<RwLock<HashMap<String, ContractInfo>>>,
    /// WASM engine
    engine: Engine,
    /// WASM store
    store: Store<()>,
}

fn define_memory(linker: &mut Linker<()>, store: &mut Store<()>) -> Result<()> {
    // Define minimal memory
    let mem_type = wasmi::MemoryType::new(1, None).map_err(|e| anyhow::anyhow!("Memory type error: {:?}", e))?;
    let memory = wasmi::Memory::new(&mut *store, mem_type).map_err(|e| anyhow::anyhow!("Memory creation error: {:?}", e))?;
    linker.define("env", "memory", memory)?;

    Ok(())
}

impl ContractExecutor {
    pub fn new() -> Self {
        let engine = Engine::default();
        let store = Store::new(&engine, ());
        Self {
            contracts: Arc::new(RwLock::new(HashMap::new())),
            engine,
            store,
        }
    }

    /// Deploy new contract
    pub async fn deploy_contract(&mut self,
        id: String,
        owner: String,
        bytecode: Vec<u8>,
        interface: ContractInterface
    ) -> Result<()> {
        // Create new module
        let module = Module::new(&self.engine, &bytecode[..])?;
        let mut linker = Linker::new(&self.engine);
        
        // Define memory
        define_memory(&mut linker, &mut self.store)?;

        // Create instance
        let pre_instance = linker.instantiate(&mut self.store, &module)?;
        let _instance = pre_instance.start(&mut self.store)?;

        // Store contract info
        let contract = ContractInfo {
            id: id.clone(),
            owner,
            bytecode,
            interface,
            state: HashMap::new(),
        };

        let mut contracts = self.contracts.write().await;
        contracts.insert(id, contract);

        Ok(())
    }

    /// Call contract method
    pub async fn call_method(
        &mut self,
        contract_id: &str,
        method: &str,
        params: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        // Get contract info
        let bytecode = {
            let contracts = self.contracts.read().await;
            let contract = contracts.get(contract_id)
                .ok_or_else(|| anyhow::anyhow!("Contract not found"))?;
            contract.bytecode.clone()
        };

        // Load WASM module and create instance
        let module = Module::new(&self.engine, &bytecode[..])?;
        let mut linker = Linker::new(&self.engine);
        define_memory(&mut linker, &mut self.store)?;
        
        let pre_instance = linker.instantiate(&mut self.store, &module)?;
        let instance = pre_instance.start(&mut self.store)?;

        // Get the function and call it
        if let Some(export) = instance.get_export(&mut self.store, method) {
            if let Some(func) = export.into_func() {
                let wasm_params = params.iter()
                    .map(|p| wasmi::Value::I32(i32::from_le_bytes(p[..4].try_into().unwrap())))
                    .collect::<Vec<_>>();

                let mut results = vec![wasmi::Value::I32(0)];
                func.call(&mut self.store, &wasm_params, &mut results)?;
                
                Ok(if let Some(wasmi::Value::I32(val)) = results.get(0) {
                    val.to_le_bytes().to_vec()
                } else {
                    vec![]
                })
            } else {
                Err(anyhow::anyhow!("Export is not a function"))
            }
        } else {
            Err(anyhow::anyhow!("Method not found"))
        }
    }

    /// Get contract state
    pub async fn get_state(&self, contract_id: &str) -> Result<HashMap<String, Vec<u8>>> {
        let contracts = self.contracts.read().await;
        let contract = contracts.get(contract_id)
            .ok_or_else(|| anyhow::anyhow!("Contract not found"))?;
        
        Ok(contract.state.clone())
    }
}

/// Contains token contract ABI
#[cfg(test)]
const TOKEN_INTERFACE: &str = include_str!("../../contracts/token.json");

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_contract_deployment() {
        let mut executor = ContractExecutor::new();

        // Create simple contract
        let bytecode = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00
        ];

        let interface: ContractInterface = serde_json::from_str(TOKEN_INTERFACE).unwrap();

        assert!(executor.deploy_contract(
            "test".to_string(),
            "owner".to_string(),
            bytecode,
            interface
        ).await.is_ok());
    }
}
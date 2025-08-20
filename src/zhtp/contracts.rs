use anyhow::Result;
use wasmi::{
    self,
    Engine,
    Instance,
    Linker,
    Module,
    Store,
    Value,
};

/// Contract execution environment
#[derive(Debug)]
pub struct WasmRuntime {
    engine: Engine,
    store: Store<()>,
    instance: Option<Instance>,
}

impl WasmRuntime {
    pub fn new() -> Self {
        let engine = Engine::default();
        let store = Store::new(&engine, ());
        Self {
            engine,
            store,
            instance: None,
        }
    }

    pub fn deploy(&mut self, bytecode: &[u8]) -> Result<()> {
        let module = Module::new(&self.engine, bytecode)?;
        let linker = Linker::new(&self.engine);
        self.instance = Some(
            linker.instantiate(&mut self.store, &module)?
                .start(&mut self.store)?
        );
        Ok(())
    }

    pub fn call_function(&mut self, method: &str, params: &[Value]) -> Result<Vec<u8>> {
        let instance = self.instance.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No contract deployed"))?;
            
        let func = instance.get_func(&mut self.store, method)
            .ok_or_else(|| anyhow::anyhow!("Method not found"))?;
            
        let mut results = vec![Value::I32(0)];
        func.call(&mut self.store, params, &mut results)?;
            
        Ok(match results.first() {
            Some(&Value::I32(val)) => val.to_le_bytes().to_vec(),
            _ => vec![0],
        })
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_runtime() -> Result<()> {
        let mut runtime = WasmRuntime::new();
        
        // Test contract in WAT format
        let wat = r#"
            (module
                (func (export "add") (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.add)
            )
        "#;
        
        // Convert WAT to WASM
        let wasm = wat::parse_str(wat)?;
        
        // Deploy contract
        runtime.deploy(&wasm)?;
        
        // Test function call
        let result = runtime.call_function(
            "add",
            &[Value::I32(40), Value::I32(2)]
        )?;
        
        assert_eq!(i32::from_le_bytes(result.try_into().unwrap()), 42);
        Ok(())
    }
}
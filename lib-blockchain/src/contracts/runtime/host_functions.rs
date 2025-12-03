//! Host functions for WASM contracts
//! Provides safe, sandboxed access to blockchain functionality

use anyhow::Result;
use std::collections::HashMap;
#[cfg(feature = "wasmtime")]
use wasmtime::{Caller, Extern};

const MAX_LOG_SIZE: i32 = 1024;
const MAX_STORAGE_KEY_SIZE: usize = 64;
const MAX_STORAGE_VALUE_SIZE: usize = 1024;
const MAX_EVENT_SIZE: usize = 512;

use super::RuntimeContext;

/// Host function statistics and limits
#[derive(Debug, Clone, Default)]
pub struct HostFunctionStats {
    pub log_count: u32,
    pub storage_ops: u32,
    pub event_count: u32,
    pub max_logs: u32,
    pub max_storage_ops: u32,
    pub max_events: u32,
}

/// Host functions accessible to WASM contracts
#[derive(Debug)]
pub struct HostFunctions {
    pub context: RuntimeContext,
    pub stats: HostFunctionStats,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
}

impl HostFunctions {
    pub fn new(context: RuntimeContext) -> Self {
        Self {
            context,
            stats: HostFunctionStats {
                max_logs: 100,
                max_storage_ops: 50,
                max_events: 25,
                ..Default::default()
            },
            storage: HashMap::new(),
        }
    }

    pub fn get_stats(&self) -> &HostFunctionStats {
        &self.stats
    }

    /// Register all safe host functions with the linker
    #[cfg(feature = "wasmtime")]
    pub fn register_functions(linker: &mut wasmtime::Linker<Self>) -> Result<()> {
        // Safe logging function
        linker.func_wrap("env", "zhtp_log", |mut caller: Caller<'_, Self>, ptr: i32, len: i32| -> i32 {
            if len < 0 || len > MAX_LOG_SIZE {
                return -1; // Invalid length
            }

            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -2, // No memory export
            };

            // Read the message from WASM memory
            let mut buffer = vec![0u8; len as usize];
            match memory.read(&caller, ptr as usize, &mut buffer) {
                Ok(_) => {},
                Err(_) => return -3, // Read failed
            }

            let message = match std::str::from_utf8(&buffer) {
                Ok(s) => s,
                Err(_) => return -4, // Invalid UTF-8
            };

            // Safe logging
            log::info!("WASM Contract Log: {}", message);
            0 // Success
        })?;

        // Get caller public key
        linker.func_wrap("env", "zhtp_get_caller", |mut caller: Caller<'_, Self>, ptr: i32| -> i32 {
            let host_data = caller.data();
            let caller_bytes = host_data.context.caller.as_bytes();

            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -1,
            };

            // Write caller public key to WASM memory
            match memory.write(&mut caller, ptr as usize, &caller_bytes) {
                Ok(_) => caller_bytes.len() as i32,
                Err(_) => -1,
            }
        })?;

        // Get current block number
        linker.func_wrap("env", "zhtp_get_block_number", |caller: Caller<'_, Self>| -> u64 {
            caller.data().context.block_number
        })?;

        // Get current timestamp
        linker.func_wrap("env", "zhtp_get_timestamp", |caller: Caller<'_, Self>| -> u64 {
            caller.data().context.timestamp
        })?;

        // Simple storage get function
        linker.func_wrap("env", "zhtp_storage_get", 
            |mut caller: Caller<'_, Self>, key_ptr: i32, key_len: i32, value_ptr: i32| -> i32 {
            if key_len < 0 || key_len > MAX_STORAGE_KEY_SIZE as i32 {
                return -1; // Invalid key size
            }

            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -2, // No memory export
            };

            // Read the key from WASM memory
            let mut key_buffer = vec![0u8; key_len as usize];
            match memory.read(&caller, key_ptr as usize, &mut key_buffer) {
                Ok(_) => {},
                Err(_) => return -3, // Read failed
            }

            // Clone the value to avoid borrowing issues
            let value_opt = {
                let host_data = caller.data();
                host_data.storage.get(&key_buffer).cloned()
            };

            match value_opt {
                Some(value) => {
                    // Write value to WASM memory
                    match memory.write(&mut caller, value_ptr as usize, &value) {
                        Ok(_) => value.len() as i32,
                        Err(_) => -4, // Write failed
                    }
                },
                None => 0, // Key not found
            }
        })?;

        // Simple storage set function
        linker.func_wrap("env", "zhtp_storage_set", 
            |mut caller: Caller<'_, Self>, key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32| -> i32 {
            if key_len < 0 || key_len > MAX_STORAGE_KEY_SIZE as i32 ||
               value_len < 0 || value_len > MAX_STORAGE_VALUE_SIZE as i32 {
                return -1; // Invalid size
            }

            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -2, // No memory export
            };

            // Read key and value from WASM memory
            let mut key_buffer = vec![0u8; key_len as usize];
            let mut value_buffer = vec![0u8; value_len as usize];
            
            if memory.read(&caller, key_ptr as usize, &mut key_buffer).is_err() ||
               memory.read(&caller, value_ptr as usize, &mut value_buffer).is_err() {
                return -3; // Read failed
            }

            // Store in host storage
            caller.data_mut().storage.insert(key_buffer, value_buffer);
            0 // Success
        })?;

        // Emit event function
        linker.func_wrap("env", "zhtp_emit_event", 
            |mut caller: Caller<'_, Self>, event_ptr: i32, event_len: i32| -> i32 {
            if event_len < 0 || event_len > MAX_EVENT_SIZE as i32 {
                return -1; // Invalid size
            }

            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -2, // No memory export
            };

            // Read event data from WASM memory
            let mut event_buffer = vec![0u8; event_len as usize];
            match memory.read(&caller, event_ptr as usize, &mut event_buffer) {
                Ok(_) => {},
                Err(_) => return -3, // Read failed
            }

            let event_data = match std::str::from_utf8(&event_buffer) {
                Ok(s) => s,
                Err(_) => return -4, // Invalid UTF-8
            };

            // Emit event (would integrate with actual event system)
            log::info!("WASM Contract Event: {}", event_data);
            0 // Success
        })?;

        Ok(())
    }
}

/// Check if a function name is a safe host function
pub fn is_safe_host_function(name: &str) -> bool {
    matches!(name,
        "zhtp_log" |
        "zhtp_get_caller" |
        "zhtp_get_block_number" |
        "zhtp_get_timestamp" |
        "zhtp_storage_get" |
        "zhtp_storage_set" |
        "zhtp_emit_event"
    )
}
use std::env;
use std::io::{self, Read};

use lib_blockchain::types::ContractCall;
use lib_blockchain::transaction::core::Transaction;
use lib_blockchain::transaction::creation::utils::calculate_minimum_fee;
use lib_blockchain::transaction::DecodedContractExecutionMemo;
use lib_blockchain::TransactionType;
use lib_blockchain::types::ContractType;
use lib_crypto::types::signatures::Signature;

fn main() {
    let hex = read_hex_arg_or_stdin();
    match decode_and_inspect(&hex) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}

fn read_hex_arg_or_stdin() -> String {
    let mut args = env::args().skip(1);
    if let Some(hex) = args.next() {
        return hex.trim().to_string();
    }

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap_or(0);
    input.trim().to_string()
}

fn decode_and_inspect(hex_tx: &str) -> Result<(), String> {
    if hex_tx.is_empty() {
        return Err("no hex provided (arg or stdin)".to_string());
    }

    let tx_bytes = hex::decode(hex_tx).map_err(|e| format!("invalid hex: {e}"))?;
    let tx: Transaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| format!("bincode Transaction deserialize failed: {e}"))?;

    println!("decoded Transaction:");
    println!("  type: {:?}", tx.transaction_type);
    println!("  version: {}", tx.version);
    println!("  inputs: {}", tx.inputs.len());
    println!("  outputs: {}", tx.outputs.len());
    println!("  fee: {}", tx.fee);
    println!("  size: {}", tx.size());
    println!("  memo.len: {}", tx.memo.len());
    println!(
        "  signature.len: {}",
        tx.signature.signature.len()
    );
    println!(
        "  public_key.len: {} (dilithium_pk={}, kyber_pk={})",
        tx.signature.public_key.as_bytes().len(),
        tx.signature.public_key.dilithium_pk.len(),
        tx.signature.public_key.kyber_pk.len()
    );
    let min_fee = calculate_minimum_fee(tx.size());
    println!("  min_fee: {}", min_fee);
    if tx.fee < min_fee {
        println!("  fee_check: FAIL ({} < {})", tx.fee, min_fee);
    } else {
        println!("  fee_check: OK");
    }

    println!();
    println!("is_token_contract_execution() diagnostic:");
    match is_token_contract_execution_diagnostic(&tx) {
        Ok((call, _sig)) => {
            println!("  RESULT: true");
            println!("  contract_type: {:?}", call.contract_type);
            println!("  method: {}", call.method);
            println!("  params.len: {}", call.params.len());
        }
        Err(reason) => {
            println!("  RESULT: false");
            println!("  reason: {reason}");
        }
    }

    Ok(())
}

fn is_token_contract_execution_diagnostic(
    transaction: &Transaction,
) -> Result<(ContractCall, Signature), String> {
    if transaction.transaction_type != TransactionType::ContractExecution {
        return Err(format!(
            "wrong transaction type: {:?}",
            transaction.transaction_type
        ));
    }

    let decoded = DecodedContractExecutionMemo::decode_compat(&transaction.memo)
        .map_err(|e| format!("memo decode failed: {e}"))?;
    let call = decoded.call;
    let sig = decoded.signature;

    if call.contract_type != ContractType::Token {
        return Err(format!("contract_type is {:?}, not Token", call.contract_type));
    }

    let is_token_method = matches!(
        call.method.as_str(),
        "create_custom_token" | "mint" | "transfer" | "burn"
    );

    if !is_token_method {
        return Err(format!("method '{}' is not a token method", call.method));
    }

    Ok((call, sig))
}

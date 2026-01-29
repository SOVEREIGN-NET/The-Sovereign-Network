use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use lib_crypto::post_quantum::dilithium_verify;
use lib_crypto::post_quantum::dilithium_sign;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
struct InputPayload {
    mode: String,
    message_b64: String,
    dilithium_sk_b64: Option<String>,
    dilithium_pk_b64: Option<String>,
    signature_b64: Option<String>,
}

#[derive(Serialize)]
struct SignOutput {
    signature_b64: String,
}

#[derive(Serialize)]
struct VerifyOutput {
    valid: bool,
}

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Err(anyhow!("Empty input"));
    }
    Ok(buf)
}

fn main() -> Result<()> {
    let input = read_stdin()?;
    let payload: InputPayload = serde_json::from_str(&input)?;

    match payload.mode.as_str() {
        "sign" => {
            let sk_b64 = payload
                .dilithium_sk_b64
                .ok_or_else(|| anyhow!("Missing dilithium_sk_b64"))?;
            let message = general_purpose::STANDARD.decode(payload.message_b64)?;
            let sk = general_purpose::STANDARD.decode(sk_b64)?;
            let signature = dilithium_sign(&message, &sk)?;
            let output = SignOutput {
                signature_b64: general_purpose::STANDARD.encode(signature),
            };
            println!("{}", serde_json::to_string(&output)?);
        }
        "verify" => {
            let pk_b64 = payload
                .dilithium_pk_b64
                .ok_or_else(|| anyhow!("Missing dilithium_pk_b64"))?;
            let sig_b64 = payload
                .signature_b64
                .ok_or_else(|| anyhow!("Missing signature_b64"))?;
            let message = general_purpose::STANDARD.decode(payload.message_b64)?;
            let pk = general_purpose::STANDARD.decode(pk_b64)?;
            let signature = general_purpose::STANDARD.decode(sig_b64)?;
            let valid = dilithium_verify(&message, &signature, &pk)?;
            let output = VerifyOutput { valid };
            println!("{}", serde_json::to_string(&output)?);
        }
        other => {
            return Err(anyhow!("Unknown mode: {}", other));
        }
    }

    Ok(())
}

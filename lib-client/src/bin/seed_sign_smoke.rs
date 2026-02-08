use std::io::{self, Read};
use std::time::Instant;

use zhtp_client::identity;

fn read_seed_phrase_from_stdin() -> anyhow::Result<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let phrase = input.trim().to_string();
    if phrase.is_empty() {
        anyhow::bail!("Seed phrase is empty. Provide the 24 words via stdin.");
    }
    Ok(phrase)
}

fn main() -> anyhow::Result<()> {
    // Usage:
    //   echo "24 words ..." | cargo run -p lib-client --bin seed_sign_smoke -- --message-len 5219
    //
    // Notes:
    // - Does NOT print the seed phrase.
    // - Prints DID preview + lengths + timings only.

    let mut message_len: usize = 5219;
    let mut device_id = "seed-sign-smoke-device".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--message-len" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--message-len requires a value"))?;
                message_len = v.parse()?;
            }
            "--device-id" => {
                device_id = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--device-id requires a value"))?;
            }
            "--help" | "-h" => {
                eprintln!(
                    "seed_sign_smoke\n\n\
Reads a 24-word seed phrase from stdin, restores identity, and signs a message.\n\n\
Options:\n\
  --message-len N   Message length to sign (default: 5219)\n\
  --device-id ID    Device id used for restore (default: seed-sign-smoke-device)\n\n\
Example:\n\
  echo \"<24 words>\" | cargo run -p lib-client --bin seed_sign_smoke -- --message-len 5219\n"
                );
                return Ok(());
            }
            other => anyhow::bail!("Unknown arg: {}", other),
        }
    }

    let phrase = read_seed_phrase_from_stdin()?;

    let t0 = Instant::now();
    let identity_obj = identity::restore_identity_from_phrase(&phrase, device_id)?;
    let restore_ms = t0.elapsed().as_millis();

    let public = identity::get_public_identity(&identity_obj);

    // Deterministic filler message so we can reproduce the same code path without logging real data.
    let message = vec![b'a'; message_len];

    let t1 = Instant::now();
    let sig = identity::sign_message(&identity_obj, &message)?;
    let sign_ms = t1.elapsed().as_millis();

    // Print only non-sensitive diagnostics.
    let did = public.did;
    let did_tail = did.strip_prefix("did:zhtp:").unwrap_or(&did);
    let did_preview = if did_tail.len() > 12 {
        format!("{}…{}", &did_tail[..6], &did_tail[did_tail.len() - 6..])
    } else {
        did_tail.to_string()
    };

    println!("restore_ms={restore_ms} sign_ms={sign_ms}");
    println!("did_preview={did_preview}");
    println!(
        "pk_len={} sk_len={} sig_len={} msg_len={}",
        identity_obj.public_key.len(),
        identity_obj.private_key.len(),
        sig.len(),
        message_len
    );

    Ok(())
}


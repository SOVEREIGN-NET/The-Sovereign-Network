//! Network commands for ZHTP orchestrator

use anyhow::Result;
use crate::argument_parsing::{NetworkArgs, NetworkAction, ZhtpCli, format_output};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub async fn handle_network_command(args: NetworkArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        NetworkAction::Status => {
            println!("Orchestrating network status check...");
            
            let response = client
                .get(&format!("{}/network/status", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network status orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate network status: {}", response.status());
            }
        }
        NetworkAction::Peers => {
            println!("Orchestrating peer list request...");
            
            let response = client
                .get(&format!("{}/network/peers", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network peers orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate peer list: {}", response.status());
            }
        }
        NetworkAction::Test => {
            println!(" Orchestrating network connectivity test...");
            
            let response = client
                .post(&format!("{}/network/test", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network test orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate network test: {}", response.status());
            }
        }
        NetworkAction::Ping { target, count } => {
            ping_peer(&target, count).await?;
        }
    }
    
    Ok(())
}

/// Ping a peer node directly via UDP
async fn ping_peer(target: &str, count: u32) -> Result<()> {
    use lib_network::types::mesh_message::ZhtpMeshMessage;
    use lib_crypto::PublicKey;
    
    println!("🏓 ZHTP Mesh Ping to {}", target);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Parse target address
    let target_addr: SocketAddr = target.parse()
        .map_err(|_| anyhow::anyhow!("Invalid target address format. Use IP:PORT (e.g., 192.168.1.164:9002)"))?;
    
    // Bind to a random local port
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    println!("📡 Sending from {}", local_addr);
    println!();
    
    let mut successful_pings = 0;
    let mut total_rtt = Duration::ZERO;
    let mut min_rtt = Duration::MAX;
    let mut max_rtt = Duration::ZERO;
    
    for seq in 1..=count {
        let request_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Create a ping message
        let ping_msg = ZhtpMeshMessage::DhtPing {
            requester: PublicKey::new(vec![0u8; 32]), // Placeholder - real impl would use actual key
            request_id,
            timestamp,
        };
        
        let ping_data = bincode::serialize(&ping_msg)?;
        let start = Instant::now();
        
        // Send ping
        socket.send_to(&ping_data, target_addr).await?;
        
        // Wait for pong with timeout
        let mut buf = [0u8; 4096];
        let timeout = Duration::from_secs(2);
        
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                let rtt = start.elapsed();
                
                // Try to deserialize as DhtPong
                if let Ok(response) = bincode::deserialize::<ZhtpMeshMessage>(&buf[..len]) {
                    match response {
                        ZhtpMeshMessage::DhtPong { request_id: resp_id, timestamp: resp_ts } => {
                            if resp_id == request_id {
                                successful_pings += 1;
                                total_rtt += rtt;
                                min_rtt = min_rtt.min(rtt);
                                max_rtt = max_rtt.max(rtt);
                                
                                println!("✅ Reply from {}: seq={} time={:.2}ms request_id={}",
                                    from, seq, rtt.as_secs_f64() * 1000.0, resp_id);
                            } else {
                                println!("⚠️  seq={}: Request ID mismatch (expected {}, got {})",
                                    seq, request_id, resp_id);
                            }
                        }
                        other => {
                            println!("📨 seq={}: Received {:?} (expected DhtPong)", seq, 
                                std::mem::discriminant(&other));
                        }
                    }
                } else {
                    println!("⚠️  seq={}: Received {} bytes from {} (invalid message format)",
                        seq, len, from);
                }
            }
            Ok(Err(e)) => {
                println!("❌ seq={}: Socket error: {}", seq, e);
            }
            Err(_) => {
                println!("❌ seq={}: Request timeout (>{}ms)", seq, timeout.as_millis());
            }
        }
        
        // Wait 1 second between pings
        if seq < count {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    
    // Print statistics
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 Ping statistics for {}:", target);
    println!("   {} packets transmitted, {} received, {:.1}% packet loss",
        count, successful_pings, 
        (count - successful_pings) as f64 / count as f64 * 100.0);
    
    if successful_pings > 0 {
        let avg_rtt = total_rtt / successful_pings;
        println!("   Round-trip min/avg/max = {:.2}/{:.2}/{:.2} ms",
            min_rtt.as_secs_f64() * 1000.0,
            avg_rtt.as_secs_f64() * 1000.0,
            max_rtt.as_secs_f64() * 1000.0);
    }
    
    Ok(())
}

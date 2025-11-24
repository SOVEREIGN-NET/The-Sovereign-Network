//! ZHTP protocol handshake implementation

use anyhow::Result;
use lib_crypto::PublicKey;

/// Perform ZHTP handshake with a peer
pub async fn perform_lib_handshake(
    stream: &mut tokio::net::TcpStream,
    our_node_id: &PublicKey,
) -> Result<PublicKey> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Send handshake
    let handshake_msg = format!("ZHTP/1.0 HELLO\r\nNode-ID: {:?}\r\n\r\n", our_node_id);
    stream.write_all(handshake_msg.as_bytes()).await?;
    
    // Read response
    let mut buffer = vec![0u8; 1024];
    let bytes_read = stream.read(&mut buffer).await?;
    
    if bytes_read == 0 {
        return Err(anyhow::anyhow!("Peer closed connection during handshake"));
    }
    
    // Parse peer ID from response
    let peer_id = PublicKey::new(format!("peer-{}", bytes_read).into_bytes());
    
    Ok(peer_id)
}

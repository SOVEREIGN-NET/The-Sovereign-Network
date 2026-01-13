//! Local Network Discovery via Multicast
//! 
//! Automatically discovers ZHTP nodes on the same local network without needing bootstrap peers

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, interval};
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use crate::network_utils::get_local_ip;
use crate::socket_utils::enable_socket_reuse;

/// Multicast address for ZHTP local discovery (224.0.0.251 is mDNS standard)
const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75"; // Custom ZHTP multicast address
const ZHTP_MULTICAST_PORT: u16 = 37775; // Custom port for ZHTP discovery

/// Local ZHTP node announcement (sent via multicast UDP)
///
/// # Security: TLS Certificate Pinning (Issue #739)
///
/// Discovery records now include cryptographic binding to the node's TLS certificate:
/// - `dilithium_pk`: Long-term Dilithium public key for identity verification
/// - `tls_spki_sha256`: SHA256 hash of the TLS certificate's SubjectPublicKeyInfo (SPKI)
/// - `expires_at`: Record expiration to prevent replay attacks
/// - `record_sig`: Dilithium signature over canonical encoding of all fields
///
/// Peers verify the signature before caching the TLS pin. During QUIC handshake,
/// the peer's TLS certificate SPKI must match the cached pin, or the connection
/// is immediately terminated before any UHP work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    pub node_id: Uuid,
    pub mesh_port: u16,
    #[serde(default = "default_quic_port")]
    pub quic_port: u16,
    #[serde(default = "default_local_ip")]
    pub local_ip: IpAddr,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub announced_at: u64,

    // === TLS Certificate Pinning Fields (Issue #739) ===

    /// Dilithium public key for verifying record signature (1312 bytes for Dilithium2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dilithium_pk: Option<Vec<u8>>,

    /// SHA256 hash of the TLS certificate's SubjectPublicKeyInfo (SPKI)
    /// This binds the discovery record to the node's TLS identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_spki_sha256: Option<[u8; 32]>,

    /// Expiration timestamp (Unix epoch seconds) to limit replay attacks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Dilithium signature over canonical encoding of:
    /// node_id || dilithium_pk || tls_spki_sha256 || expires_at || protocols
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_sig: Option<Vec<u8>>,
}

/// Default QUIC port (9334)
fn default_quic_port() -> u16 {
    9334
}

/// Default local IP (loopback)
fn default_local_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

impl Default for NodeAnnouncement {
    fn default() -> Self {
        Self {
            node_id: Uuid::nil(),
            mesh_port: 0,
            quic_port: default_quic_port(),
            local_ip: default_local_ip(),
            protocols: Vec::new(),
            announced_at: 0,
            dilithium_pk: None,
            tls_spki_sha256: None,
            expires_at: None,
            record_sig: None,
        }
    }
}

/// Default record validity duration (1 hour)
const DEFAULT_RECORD_VALIDITY_SECS: u64 = 3600;

impl NodeAnnouncement {
    /// Create canonical bytes for signing (deterministic encoding)
    ///
    /// Format: node_id (16) || dilithium_pk || tls_spki_sha256 (32) || expires_at (8) || protocols_hash (32)
    ///
    /// This canonical encoding is stable and independent of serialization format.
    pub fn canonical_bytes_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);

        // node_id as big-endian bytes (16 bytes)
        data.extend_from_slice(self.node_id.as_bytes());

        // dilithium_pk (variable length, prefixed with 4-byte length)
        if let Some(ref pk) = self.dilithium_pk {
            data.extend_from_slice(&(pk.len() as u32).to_be_bytes());
            data.extend_from_slice(pk);
        } else {
            data.extend_from_slice(&0u32.to_be_bytes());
        }

        // tls_spki_sha256 (32 bytes, or 32 zeros if not set)
        if let Some(ref spki) = self.tls_spki_sha256 {
            data.extend_from_slice(spki);
        } else {
            data.extend_from_slice(&[0u8; 32]);
        }

        // expires_at (8 bytes big-endian)
        let expires = self.expires_at.unwrap_or(0);
        data.extend_from_slice(&expires.to_be_bytes());

        // protocols as sorted, concatenated strings with null separators, then hashed
        let mut sorted_protocols = self.protocols.clone();
        sorted_protocols.sort();
        let protocols_str = sorted_protocols.join("\0");
        let protocols_hash = blake3::hash(protocols_str.as_bytes());
        data.extend_from_slice(protocols_hash.as_bytes());

        data
    }

    /// Sign this announcement with a Dilithium secret key
    ///
    /// Sets the `dilithium_pk`, `tls_spki_sha256`, `expires_at`, and `record_sig` fields.
    pub fn sign(
        &mut self,
        dilithium_sk: &[u8],
        dilithium_pk: Vec<u8>,
        tls_spki_sha256: [u8; 32],
    ) -> anyhow::Result<()> {
        use lib_crypto::post_quantum::dilithium::dilithium2_sign;

        // Set the fields that will be signed
        self.dilithium_pk = Some(dilithium_pk);
        self.tls_spki_sha256 = Some(tls_spki_sha256);
        self.expires_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + DEFAULT_RECORD_VALIDITY_SECS,
        );

        // Compute canonical bytes and sign
        let canonical = self.canonical_bytes_for_signing();
        let signature = dilithium2_sign(&canonical, dilithium_sk)?;
        self.record_sig = Some(signature);

        Ok(())
    }

    /// Verify the signature on this announcement
    ///
    /// Returns Ok(true) if signature is valid, Ok(false) if invalid, Err if missing fields.
    pub fn verify_signature(&self) -> anyhow::Result<bool> {
        use lib_crypto::post_quantum::dilithium::dilithium2_verify;

        let dilithium_pk = self
            .dilithium_pk
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing dilithium_pk in announcement"))?;
        let record_sig = self
            .record_sig
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing record_sig in announcement"))?;

        let canonical = self.canonical_bytes_for_signing();
        dilithium2_verify(&canonical, record_sig, dilithium_pk)
    }

    /// Check if this announcement is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now < expires_at
        } else {
            // Legacy announcements without expiry are considered valid
            // but should not be used for TLS pinning
            true
        }
    }

    /// Check if this announcement has TLS pinning data
    pub fn has_tls_pin(&self) -> bool {
        self.dilithium_pk.is_some()
            && self.tls_spki_sha256.is_some()
            && self.record_sig.is_some()
            && self.expires_at.is_some()
    }

    /// Verify signature and expiry in one call
    pub fn verify_and_check_expiry(&self) -> anyhow::Result<bool> {
        if !self.has_tls_pin() {
            return Ok(false);
        }

        if !self.is_valid() {
            return Err(anyhow::anyhow!("Announcement has expired"));
        }

        self.verify_signature()
    }
}

/// Context for signing discovery announcements (Issue #739)
#[derive(Clone)]
pub struct DiscoverySigningContext {
    /// Dilithium secret key for signing announcements
    pub dilithium_sk: Vec<u8>,
    /// Dilithium public key (included in announcements)
    pub dilithium_pk: Vec<u8>,
    /// SHA256 hash of this node's TLS certificate SPKI
    pub tls_spki_sha256: [u8; 32],
}

/// Start local network discovery service
/// Optional peer_discovered_callback will be called when a peer is found (for coordinator integration)
/// Optional signing_ctx enables TLS certificate pinning (Issue #739)
pub async fn start_local_discovery(
    node_id: Uuid,
    mesh_port: u16,
    public_key: lib_crypto::PublicKey,
    peer_discovered_callback: Option<std::sync::Arc<dyn Fn(String, lib_crypto::PublicKey) + Send + Sync>>,
    signing_ctx: Option<DiscoverySigningContext>,
) -> Result<()> {
    info!(" Starting UDP Multicast discovery...");
    info!("   Multicast address: {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Node ID: {}", node_id);
    info!("   Mesh port: {}", mesh_port);
    if signing_ctx.is_some() {
        info!("   TLS certificate pinning: ENABLED");
    }

    // Send an immediate announcement BEFORE spawning background task
    // This ensures other nodes can discover us right away
    if let Err(e) = send_immediate_announcement(node_id, mesh_port, signing_ctx.clone()).await {
        warn!("Failed to send immediate announcement: {}", e);
    }

    // Start announcement broadcaster (background task)
    let announce_node_id = node_id;
    let broadcast_signing_ctx = signing_ctx.clone();
    tokio::spawn(async move {
        if let Err(e) = broadcast_announcements(announce_node_id, mesh_port, broadcast_signing_ctx).await {
            error!(" Local announcement broadcaster failed: {}", e);
        }
    });

    // Start discovery listener (background task)
    let listen_node_id = node_id;
    let listen_public_key = public_key.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_for_announcements(listen_node_id, listen_public_key, peer_discovered_callback).await {
            error!(" Local discovery listener failed: {}", e);
        }
    });

    info!(" UDP Multicast discovery active on {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Broadcasting announcements every 30 seconds");
    info!("   Listening for peer announcements");
    Ok(())
}

/// Send a single immediate announcement (synchronous, before background task starts)
async fn send_immediate_announcement(
    node_id: Uuid,
    mesh_port: u16,
    signing_ctx: Option<DiscoverySigningContext>,
) -> Result<()> {
    use socket2::{Socket, Domain, Type, Protocol};

    // Create ephemeral socket for immediate announcement
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;

    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    let local_ip = get_local_ip().await.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let mut announcement = NodeAnnouncement {
        node_id,
        mesh_port,
        quic_port: 9334, // QUIC-only nodes use port 9334
        local_ip,
        protocols: vec!["quic".to_string(), "tcp".to_string(), "bluetooth".to_string(), "wifi_direct".to_string()],
        announced_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ..Default::default()
    };

    // Sign announcement if signing context provided (Issue #739)
    if let Some(ctx) = signing_ctx {
        if let Err(e) = announcement.sign(&ctx.dilithium_sk, ctx.dilithium_pk, ctx.tls_spki_sha256) {
            warn!("Failed to sign announcement: {}", e);
        } else {
            debug!("Signed announcement with TLS pin");
        }
    }

    let announcement_json = serde_json::to_string(&announcement)?;
    socket.send_to(announcement_json.as_bytes(), multicast_addr).await?;
    info!(" Sent immediate announcement to {} (QUIC port: {}, signed: {})",
        multicast_addr, 9334, announcement.has_tls_pin());
    
    Ok(())
}

/// Broadcast this node's presence on local network
async fn broadcast_announcements(
    node_id: Uuid,
    mesh_port: u16,
    signing_ctx: Option<DiscoverySigningContext>,
) -> Result<()> {
    // Bind to the multicast port with SO_REUSEADDR to allow multiple processes
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    enable_socket_reuse(&socket)?;

    // Bind to the multicast port (not ephemeral) for proper multicast routing
    socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;

    // Configure multicast socket options
    let multicast_ipv4: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.set_multicast_ttl_v4(2)?; // TTL=2 allows crossing one router (subnet-local)
    socket.set_multicast_loop_v4(true)?; // Enable loopback for testing on same machine
    socket.join_multicast_v4(multicast_ipv4, Ipv4Addr::UNSPECIFIED)?;

    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;

    // Get local IP address
    let local_ip = get_local_ip().await.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    info!(" Broadcasting from local IP: {}", local_ip);

    let mut interval = interval(Duration::from_secs(30)); // Announce every 30 seconds

    let mut announcement_count = 0;
    loop {
        // Send announcement immediately on first iteration, then wait 30s between
        if announcement_count > 0 {
            interval.tick().await;
        }

        let mut announcement = NodeAnnouncement {
            node_id,
            mesh_port,
            quic_port: 9334, // QUIC-only nodes use port 9334
            local_ip,
            protocols: vec!["quic".to_string(), "tcp".to_string(), "bluetooth".to_string(), "wifi_direct".to_string()],
            announced_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        };

        // Sign announcement if signing context provided (Issue #739)
        if let Some(ref ctx) = signing_ctx {
            if let Err(e) = announcement.sign(&ctx.dilithium_sk, ctx.dilithium_pk.clone(), ctx.tls_spki_sha256) {
                warn!("Failed to sign announcement: {}", e);
            }
        }

        match serde_json::to_string(&announcement) {
            Ok(announcement_json) => {
                announcement_count += 1;
                if announcement_count == 1 || announcement_count % 10 == 0 {
                    info!(" Broadcasting announcement #{} to {} (QUIC: 9334, mesh: {}, signed: {})",
                        announcement_count, multicast_addr, mesh_port, announcement.has_tls_pin());
                } else {
                    debug!("Broadcasting ZHTP node announcement to {}", multicast_addr);
                }

                if let Err(e) = socket.send_to(announcement_json.as_bytes(), multicast_addr).await {
                    warn!("Failed to send multicast announcement: {}", e);
                }
            },
            Err(e) => {
                warn!("Failed to serialize announcement: {}", e);
            }
        }

        // Wait 30 seconds before next announcement
        interval.tick().await;
    }
}

/// Listen for other ZHTP nodes on local network
async fn listen_for_announcements(
    our_node_id: Uuid, 
    our_public_key: lib_crypto::PublicKey,
    peer_discovered_callback: Option<std::sync::Arc<dyn Fn(String, lib_crypto::PublicKey) + Send + Sync>>,
) -> Result<()> {
    // Use SO_REUSEADDR to allow multiple listeners on the same port
    // This lets both the persistent listener and temporary discovery scans coexist
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    enable_socket_reuse(&socket)?;
    socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(socket)?;
    
    // Configure multicast socket options
    let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.set_multicast_loop_v4(true)?; // Enable loopback for testing on same machine
    socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED)?;
    
    info!(" Listening for ZHTP node announcements on multicast {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Joined multicast group successfully");
    
    let mut buf = [0; 1024];
    let mut discovery_count = 0;
    let mut packet_count = 0;
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                packet_count += 1;
                
                // Log every packet received for debugging
                if packet_count == 1 || packet_count % 10 == 0 {
                    debug!(" Received multicast packet #{} from {} ({} bytes)", packet_count, addr, len);
                }
                
                let announcement_str = String::from_utf8_lossy(&buf[..len]);
                debug!("Packet content: {}", announcement_str);
                
                match serde_json::from_str::<NodeAnnouncement>(&announcement_str) {
                    Ok(announcement) => {
                        // Ignore our own announcements (check node_id)
                        if announcement.node_id == our_node_id {
                            debug!("Ignoring our own multicast announcement (node_id={})", our_node_id);
                            continue;
                        }

                        if announcement.local_ip != addr.ip() {
                            warn!(
                                "Announcement IP mismatch from {}: announced {}, source {}",
                                addr,
                                announcement.local_ip,
                                addr.ip()
                            );
                            continue;
                        }

                        // SECURITY: Validate source IP matches announced local_ip
                        // Rejects spoofed multicast packets trying to force arbitrary QUIC connects (SSRF/scanning)
                        let source_ip = addr.ip();
                        if announcement.local_ip != source_ip {
                            warn!("SECURITY: Rejecting announcement with spoofed IP - source: {}, announced: {}",
                                source_ip, announcement.local_ip);
                            continue;
                        }

                        // SECURITY: Validate QUIC port is in expected range (only 9334 is valid for QUIC-only nodes)
                        if announcement.quic_port != 9334 {
                            warn!("SECURITY: Rejecting announcement with unexpected QUIC port {} (expected 9334)",
                                announcement.quic_port);
                            continue;
                        }

                        discovery_count += 1;
                        info!(" PEER DISCOVERED #{}: Node {} at {}",
                            discovery_count,
                            announcement.node_id,
                            announcement.local_ip
                        );
                        info!("   Mesh port: {}, QUIC port: {} (source validated)", announcement.mesh_port, announcement.quic_port);
                        info!("   Protocols: {:?}", announcement.protocols);

                        // === TLS Certificate Pinning (Issue #739) ===
                        // Verify signature and cache TLS pin if announcement is signed
                        if announcement.has_tls_pin() {
                            let peer_addr = format!("{}:{}", announcement.local_ip, announcement.quic_port);
                            match super::pin_cache::global_pin_cache()
                                .process_announcement(&announcement, vec![peer_addr.clone()])
                                .await
                            {
                                Ok(true) => {
                                    info!("   🔐 TLS pin cached for peer {} (expires: {})",
                                        announcement.node_id,
                                        announcement.expires_at.unwrap_or(0));
                                }
                                Ok(false) => {
                                    warn!("   ⚠️ Invalid signature on announcement from {}", announcement.node_id);
                                    // Continue anyway - UHP will verify identity
                                }
                                Err(e) => {
                                    warn!("   ⚠️ Failed to process TLS pin for {}: {}", announcement.node_id, e);
                                }
                            }
                        } else {
                            debug!("   No TLS pin in announcement (legacy peer)");
                        }

                        if !announcement.protocols.iter().any(|p| p == "quic") {
                            warn!("   Skipping peer without QUIC capability");
                            continue;
                        }
                        info!("   QUIC capability asserted - passing to coordinator");

                        // Notify coordinator if callback provided (Phase 3 integration)
                        if let Some(ref callback) = peer_discovered_callback {
                            // Pass QUIC port in address for QUIC-enabled peers
                            let peer_addr = format!("{}:{}", announcement.local_ip, announcement.quic_port);
                            callback(peer_addr, our_public_key.clone());
                            debug!("   ✓ Notified discovery coordinator (QUIC: {})", announcement.quic_port);
                        }
                        // Discovery is hint-only; coordinator must perform verified handshake.
                    },
                    Err(e) => {
                        debug!("Invalid announcement format from {}: {}", addr, e);
                    }
                }
            },
            Err(e) => {
                warn!("Error receiving multicast announcement: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Discover ZHTP nodes on local network immediately
pub async fn discover_local_peers() -> Result<Vec<NodeAnnouncement>> {
    info!("Scanning for ZHTP peers on local network...");
    
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    
    // Send discovery request
    let discovery_request = serde_json::json!({
        "type": "discovery_request",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    
    socket.send_to(discovery_request.to_string().as_bytes(), multicast_addr).await?;
    
    // Listen for responses (simplified - in implementation would be more sophisticated)
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // TODO: Collect actual responses
    Ok(vec![])
}

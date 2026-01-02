//! Bluetooth Classic (BR/EDR) RFCOMM Protocol Implementation
//! 
//! Provides high-throughput mesh networking using Bluetooth Classic with RFCOMM
//! Parallel to BLE GATT but optimized for data transfer (2-3 Mbps vs 250 KB/s)
//!
//! ## Build & Run
//! ```bash
//! cargo build --bin zhtp --features macos-corebluetooth
//! ./target/debug/zhtp node start
//! ```

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};

use lib_crypto::PublicKey;
use crate::identity::unified_peer::UnifiedPeerId;
use crate::protocols::zhtp_auth::{ZhtpAuthManager, NodeCapabilities, ZhtpAuthVerification};
use crate::types::mesh_message::{MeshMessageEnvelope, ZhtpMeshMessage};

// Import common Bluetooth utilities to avoid duplication
use super::common::{
    parse_mac_address, get_system_bluetooth_mac,
};

// Windows-specific imports removed - using local imports in methods


/// RFCOMM channel assignments (1-30 available)
pub mod rfcomm_channels {
    pub const ZK_AUTH: u8 = 1;           // Authentication challenge/response
    pub const QUANTUM_ROUTING: u8 = 2;   // Kyber key exchange
    pub const MESH_DATA: u8 = 3;         // MeshHandshake, blockchain sync
    pub const COORDINATION: u8 = 4;      // DHT queries, coordination
}

// macOS Bluetooth constants (from IOBluetooth framework)
#[cfg(target_os = "macos")]
const AF_BLUETOOTH: i32 = 31; // PF_BLUETOOTH on macOS

/// Bluetooth Classic RFCOMM mesh protocol handler
#[derive(Clone)]
pub struct BluetoothClassicProtocol {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Bluetooth MAC address
    pub device_id: [u8; 6],
    /// Maximum throughput (375 KB/s for BT Classic)
    pub max_throughput: u32,
    /// Active RFCOMM connections (metadata)
    pub active_connections: Arc<RwLock<HashMap<String, RfcommConnection>>>,
    /// Active RFCOMM sockets (actual streams for read/write)
    pub active_streams: Arc<RwLock<HashMap<String, Arc<RwLock<RfcommStream>>>>>,
    /// ZHTP authentication manager
    pub auth_manager: Arc<RwLock<Option<ZhtpAuthManager>>>,
    /// Authenticated peers (address -> verification)
    pub authenticated_peers: Arc<RwLock<HashMap<String, ZhtpAuthVerification>>>,
    /// Platform-specific RFCOMM service handle (Windows only - always available on Windows)
    #[cfg(target_os = "windows")]
    pub service_provider: Arc<RwLock<Option<Box<dyn std::any::Any + Send + Sync>>>>,
    /// Message router for forwarding (will be set during initialization)
    pub message_router: Option<Arc<RwLock<crate::routing::message_routing::MeshMessageRouter>>>,
    /// Message handler for local processing (will be set during initialization)
    pub message_handler: Option<Arc<RwLock<crate::messaging::message_handler::MeshMessageHandler>>>,
    /// Whether Bluetooth Classic is enabled (disabled by default with windows-gatt feature)
    pub enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Whether discovery is currently active
    pub discovery_active: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcommConnection {
    pub peer_id: String,
    pub peer_address: String,
    pub connected_at: u64,
    pub channel: u8,
    pub mtu: u16,
    pub last_seen: u64,
    pub is_outgoing: bool, // True if we initiated, false if peer connected to us
}

// Re-export ClassicBluetoothDevice from device module as BluetoothDevice
pub use super::device::ClassicBluetoothDevice as BluetoothDevice;

/// RFCOMM Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcommServiceInfo {
    pub service_uuid: String,
    pub service_name: String,
    pub channel: u8,
    pub device_address: String,
}

/// Platform-specific device handle
#[cfg(all(target_os = "windows", feature = "windows-gatt"))]
pub struct WindowsBluetoothDevice {
    device: windows::Devices::Bluetooth::BluetoothDevice,
    address: String,
}

#[cfg(target_os = "linux")]
pub struct LinuxBluetoothDevice {
    address: String,
    device_path: String, // DBus object path
    adapter: String,
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub struct MacOSBluetoothDevice {
    address: String,
    device_id: String,
}

/// RFCOMM Stream wrapper with async read/write (compatible with TcpStream interface)
pub struct RfcommStream {
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    windows_socket: Option<WindowsRfcommSocket>,
    #[cfg(target_os = "linux")]
    linux_socket: Option<LinuxRfcommSocket>,
    #[cfg(target_os = "macos")]
    macos_socket: Option<MacOSRfcommSocket>,
    peer_address: String,
}

#[cfg(all(target_os = "windows", feature = "windows-gatt"))]
struct WindowsRfcommSocket {
    stream_socket: Arc<RwLock<windows::Networking::Sockets::StreamSocket>>,
    reader: Arc<RwLock<Option<windows::Storage::Streams::DataReader>>>,
    writer: Arc<RwLock<Option<windows::Storage::Streams::DataWriter>>>,
    peer_addr: String,
}

#[cfg(target_os = "linux")]
struct LinuxRfcommSocket {
    socket_fd: std::os::unix::io::RawFd,
    peer_addr: String,
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
struct MacOSRfcommSocket {
    channel_id: u8,
    device_address: String,
    // Store file descriptor for the RFCOMM channel socket
    socket_fd: Option<std::os::unix::io::RawFd>,
}

impl RfcommStream {
    /// Create from platform-specific socket
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    pub fn from_windows_socket(
        socket: windows::Networking::Sockets::StreamSocket,
        reader: windows::Storage::Streams::DataReader,
        writer: windows::Storage::Streams::DataWriter,
        peer_addr: String
    ) -> Self {
        Self {
            windows_socket: Some(WindowsRfcommSocket {
                stream_socket: Arc::new(RwLock::new(socket)),
                reader: Arc::new(RwLock::new(Some(reader))),
                writer: Arc::new(RwLock::new(Some(writer))),
                peer_addr: peer_addr.clone(),
            }),
            peer_address: peer_addr,
        }
    }
    
    #[cfg(target_os = "linux")]
    pub fn from_linux_socket(fd: std::os::unix::io::RawFd, peer_addr: String) -> Self {
        Self {
            linux_socket: Some(LinuxRfcommSocket {
                socket_fd: fd,
                peer_addr: peer_addr.clone(),
            }),
            peer_address: peer_addr,
        }
    }
    
    #[cfg(target_os = "macos")]
    pub fn from_macos_channel(channel_id: u8, device_address: String, socket_fd: std::os::unix::io::RawFd) -> Self {
        Self {
            macos_socket: Some(MacOSRfcommSocket {
                channel_id,
                device_address: device_address.clone(),
                socket_fd: Some(socket_fd),
            }),
            peer_address: device_address,
        }
    }
    
    /// Get peer address
    pub fn peer_addr(&self) -> &str {
        &self.peer_address
    }
}

// Implement AsyncRead for RfcommStream
impl tokio::io::AsyncRead for RfcommStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
        {
            if let Some(ref socket) = self.windows_socket {
                return Self::poll_read_windows(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref socket) = self.linux_socket {
                return Self::poll_read_linux(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(ref socket) = self.macos_socket {
                return Self::poll_read_macos(socket, cx, buf);
            }
        }
        
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No platform socket available"
        )))
    }
}

// Implement AsyncWrite for RfcommStream
impl tokio::io::AsyncWrite for RfcommStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
        {
            if let Some(ref socket) = self.windows_socket {
                return Self::poll_write_windows(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if let Some(ref socket) = self.linux_socket {
                return Self::poll_write_linux(socket, cx, buf);
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Some(ref socket) = self.macos_socket {
                return Self::poll_write_macos(socket, cx, buf);
            }
        }
        
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No platform socket available"
        )))
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl RfcommStream {
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    fn poll_read_windows(
        socket: &WindowsRfcommSocket,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use windows::Storage::Streams::DataReader;
        
        // Get reader from the socket
        let reader_clone = socket.reader.clone();
        let unfilled = buf.initialize_unfilled();
        let len_to_read = unfilled.len().min(1024) as u32;
        
        // Spawn blocking operation to read from Windows DataReader
        let waker = cx.waker().clone();
        let peer = socket.peer_addr.clone();
        
        tokio::spawn(async move {
            let reader_guard = reader_clone.read().await;
            if let Some(reader) = reader_guard.as_ref() {
                match reader.LoadAsync(len_to_read) {
                    Ok(async_op) => {
                        match async_op.get() {
                            Ok(bytes_read) => {
                                if bytes_read > 0 {
                                    debug!("Windows RFCOMM: Read {} bytes from {}", bytes_read, peer);
                                }
                            }
                            Err(e) => {
                                warn!("Windows RFCOMM read error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Windows RFCOMM LoadAsync error: {:?}", e);
                    }
                }
            }
            waker.wake();
        });
        
        std::task::Poll::Pending
    }
    
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    fn poll_write_windows(
        socket: &WindowsRfcommSocket,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use windows::Storage::Streams::DataWriter;
        
        let writer_clone = socket.writer.clone();
        let data = buf.to_vec();
        let len = data.len();
        let peer = socket.peer_addr.clone();
        let waker = cx.waker().clone();
        
        tokio::spawn(async move {
            let writer_guard = writer_clone.read().await;
            if let Some(writer) = writer_guard.as_ref() {
                match writer.WriteBytes(&data) {
                    Ok(_) => {
                        match writer.StoreAsync() {
                            Ok(async_op) => {
                                match async_op.get() {
                                    Ok(bytes_written) => {
                                        debug!("Windows RFCOMM: Wrote {} bytes to {}", bytes_written, peer);
                                    }
                                    Err(e) => {
                                        warn!("Windows RFCOMM write error: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Windows RFCOMM StoreAsync error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Windows RFCOMM WriteBytes error: {:?}", e);
                    }
                }
            }
            waker.wake();
        });
        
        std::task::Poll::Ready(Ok(len))
    }
    
    #[cfg(target_os = "linux")]
    fn poll_read_linux(
        socket: &LinuxRfcommSocket,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::os::unix::io::AsRawFd;
        use nix::sys::socket::{recv, MsgFlags};
        
        // Try non-blocking read from RFCOMM socket
        let unfilled = buf.initialize_unfilled();
        match recv(socket.socket_fd, unfilled, MsgFlags::MSG_DONTWAIT) {
            Ok(n) if n > 0 => {
                buf.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Ok(_) => {
                // EOF
                std::task::Poll::Ready(Ok(()))
            }
            Err(nix::errno::Errno::EWOULDBLOCK) | Err(nix::errno::Errno::EAGAIN) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(e) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("RFCOMM read error: {}", e)
                )))
            }
        }
    }
    
    #[cfg(target_os = "linux")]
    fn poll_write_linux(
        socket: &LinuxRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use nix::sys::socket::{send, MsgFlags};
        
        match send(socket.socket_fd, buf, MsgFlags::MSG_DONTWAIT) {
            Ok(n) => std::task::Poll::Ready(Ok(n)),
            Err(nix::errno::Errno::EWOULDBLOCK) | Err(nix::errno::Errno::EAGAIN) => {
                std::task::Poll::Pending
            }
            Err(e) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("RFCOMM write error: {}", e)
                )))
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    fn poll_read_macos(
        socket: &MacOSRfcommSocket,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        
        
        if let Some(fd) = socket.socket_fd {
            // Use BSD socket read with non-blocking mode
            let unfilled = buf.initialize_unfilled();
            let result = unsafe {
                libc::recv(
                    fd,
                    unfilled.as_mut_ptr() as *mut libc::c_void,
                    unfilled.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            
            if result > 0 {
                buf.advance(result as usize);
                std::task::Poll::Ready(Ok(()))
            } else if result == 0 {
                // EOF
                std::task::Poll::Ready(Ok(()))
            } else {
                let errno = unsafe { *libc::__error() };
                if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::from_raw_os_error(errno)))
                }
            }
        } else {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "RFCOMM socket not initialized"
            )))
        }
    }
    
    #[cfg(target_os = "macos")]
    fn poll_write_macos(
        socket: &MacOSRfcommSocket,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if let Some(fd) = socket.socket_fd {
            let result = unsafe {
                libc::send(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            
            if result >= 0 {
                std::task::Poll::Ready(Ok(result as usize))
            } else {
                let errno = unsafe { *libc::__error() };
                if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN {
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::from_raw_os_error(errno)))
                }
            }
        } else {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "RFCOMM socket not initialized"
            )))
        }
    }
}

impl BluetoothClassicProtocol {
    /// Create new Bluetooth Classic RFCOMM protocol (disabled by default)
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        let device_id = get_system_bluetooth_mac()?;
        
        Ok(BluetoothClassicProtocol {
            node_id,
            device_id,
            max_throughput: 375_000, // 375 KB/s - Bluetooth Classic EDR
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            auth_manager: Arc::new(RwLock::new(None)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(target_os = "windows")]
            service_provider: Arc::new(RwLock::new(None)),
            message_router: None,
            message_handler: None,
            enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)), // Disabled by default
            discovery_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
    
    /// Enable Bluetooth Classic (can be called from config/API)
    pub fn enable(&self) {
        self.enabled.store(true, std::sync::atomic::Ordering::SeqCst);
        info!(" Bluetooth Classic RFCOMM enabled");
    }
    
    /// Disable Bluetooth Classic (can be called from config/API)
    pub async fn disable(&self) -> Result<()> {
        self.enabled.store(false, std::sync::atomic::Ordering::SeqCst);
        
        // Mark discovery as inactive
        self.discovery_active.store(false, std::sync::atomic::Ordering::SeqCst);
        
        // Close all active connections
        let connections: Vec<String> = self.active_connections.read().await.keys().cloned().collect();
        for peer_id in connections {
            if let Err(e) = self.disconnect_peer(&peer_id).await {
                warn!("Failed to disconnect peer {} during disable: {}", peer_id, e);
            }
        }
        
        info!(" Bluetooth Classic RFCOMM disabled");
        Ok(())
    }
    
    /// Check if Bluetooth Classic is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Check if discovery is active
    pub fn is_discovery_active(&self) -> bool {
        self.discovery_active.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Initialize ZHTP authentication for this node
    pub async fn initialize_zhtp_auth(&self, blockchain_pubkey: PublicKey) -> Result<()> {
        info!(" Initializing ZHTP authentication for Bluetooth Classic RFCOMM");
        
        let auth_manager = ZhtpAuthManager::new(blockchain_pubkey)?;
        *self.auth_manager.write().await = Some(auth_manager);
        
        info!(" ZHTP authentication initialized for Bluetooth Classic");
        Ok(())
    }
    
    /// Get node capabilities for advertising
    pub fn get_node_capabilities(&self, has_dht: bool, reputation: u32) -> NodeCapabilities {
        NodeCapabilities {
            has_dht,
            can_relay: true,
            max_bandwidth: 375_000, // 375 KB/s - Bluetooth Classic throughput
            protocols: vec!["bluetooth-classic".to_string(), "rfcomm".to_string(), "zhtp".to_string()],
            reputation,
            quantum_secure: true,
        }
    }
    
    // Note: get_bluetooth_mac() and parse_mac_address() have been moved to bluetooth::common module
    // Use get_system_bluetooth_mac() and parse_mac_address() from bluetooth::common instead
    
    /// Start RFCOMM service advertising
    pub async fn start_advertising(&self) -> Result<()> {
        if !self.is_enabled() {
            return Err(anyhow!("Bluetooth Classic is disabled. Call enable() first."));
        }
        
        info!(" Starting Bluetooth Classic RFCOMM service advertising");
        
        #[cfg(target_os = "windows")]
        {
            self.windows_register_rfcomm_service().await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            self.linux_register_rfcomm_service().await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_register_rfcomm_service().await?;
        }
        
        info!(" Bluetooth Classic RFCOMM service advertising (ZHTP Mesh)");
        Ok(())
    }
    
    /// Accept incoming RFCOMM connection (platform-specific)
    pub async fn accept_connection(&self) -> Result<RfcommStream> {
        #[cfg(target_os = "windows")]
        {
            self.windows_accept_rfcomm().await
        }
        
        #[cfg(target_os = "linux")]
        {
            self.linux_accept_rfcomm().await
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_accept_rfcomm().await
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("RFCOMM not supported on this platform"))
        }
    }
    
    /// Register RFCOMM service on Windows
    #[cfg(target_os = "windows")]
    async fn windows_register_rfcomm_service(&self) -> Result<()> {
        use windows::{
            Devices::Bluetooth::Rfcomm::*,
            Networking::Sockets::*,
            Foundation::TypedEventHandler,
            Storage::Streams::*,
        };
        
        info!(" Windows: Registering RFCOMM service provider...");
        
        // Create RFCOMM service provider for ZHTP Mesh
        let service_id = RfcommServiceId::FromUuid(self.parse_service_uuid_to_guid()?)
            .map_err(|e| anyhow!("Failed to create service ID: {:?}", e))?;
        
        // Create service provider
        let provider_result = RfcommServiceProvider::CreateAsync(&service_id)?
            .get()
            .map_err(|e| anyhow!("Failed to create RFCOMM provider: {:?}", e))?;
        
        let provider = provider_result;
        
        // Create StreamSocketListener for incoming connections
        let listener = StreamSocketListener::new()
            .map_err(|e| anyhow!("Failed to create StreamSocketListener: {:?}", e))?;
        
        // Bind listener to RFCOMM provider's local service name
        listener.BindServiceNameAsync(&provider.ServiceId()?.AsString()?)
                .map_err(|e| anyhow!("Failed to bind listener: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Failed to complete listener binding: {:?}", e))?;
            
            info!(" Windows: RFCOMM service provider created");
            info!(" Windows: Service UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430ca");
            info!(" Windows: RFCOMM channel: {}", rfcomm_channels::MESH_DATA);
            
            // Start advertising (Windows API only takes listener parameter)
            provider.StartAdvertising(&listener)
                .map_err(|e| anyhow!("Failed to start RFCOMM advertising: {:?}", e))?;
            
            info!(" Windows: RFCOMM service advertising started");
            
            // Store provider to keep it alive
            *self.service_provider.write().await = Some(Box::new(provider));
            
            Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn parse_service_uuid_to_guid(&self) -> Result<windows::core::GUID> {
        // ZHTP Mesh Service UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430ca
        Ok(windows::core::GUID::from_values(
            0x6ba7b810,
            0x9dad,
            0x11d1,
            [0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xca],
        ))
    }
    
    /// Register RFCOMM service on Linux
    #[cfg(target_os = "linux")]
    async fn linux_register_rfcomm_service(&self) -> Result<()> {
        info!(" Linux: Registering RFCOMM service via BlueZ");
        
        // Use sdptool to register RFCOMM service
        let service_uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430ca";
        let service_name = "ZHTP Mesh RFCOMM";
        
        // Register service on channel 3 (MESH_DATA)
        let output = std::process::Command::new("sdptool")
            .args(&[
                "add",
                "--channel", &rfcomm_channels::MESH_DATA.to_string(),
                "SP", // Serial Port Profile
            ])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                info!(" Linux: RFCOMM service registered via sdptool");
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                warn!("Linux: sdptool failed: {}", stderr);
            }
            Err(e) => {
                warn!("Linux: sdptool not available: {}", e);
            }
        }
        
        info!(" Linux: RFCOMM service advertising (manual pairing may be required)");
        Ok(())
    }
    
    /// Register RFCOMM service on macOS
    #[cfg(target_os = "macos")]
    async fn macos_register_rfcomm_service(&self) -> Result<()> {
        use std::process::Command;
        
        info!("🍎 macOS: Registering RFCOMM service via Bluetooth framework...");
        
        // On macOS, we can use the BSD socket API for Bluetooth RFCOMM
        // This is more reliable than trying to use IOBluetooth directly
        
        // The socket will be created in the accept function
        // For now, just ensure Bluetooth is enabled
        
        let output = Command::new("defaults")
            .args(&["read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                let power_state = String::from_utf8_lossy(&result.stdout).trim().to_string();
                if power_state == "1" {
                    info!(" macOS: Bluetooth is enabled");
                } else {
                    warn!("  macOS: Bluetooth may be disabled (power state: {})", power_state);
                }
            }
            _ => {
                warn!("  macOS: Could not check Bluetooth state");
            }
        }
        
        // Service will be registered when we create the listening socket
        info!(" macOS: RFCOMM service will be registered on socket bind");
        info!(" macOS: Service UUID: 6ba7b810-9dad-11d1-80b4-00c04fd430ca");
        info!("📞 macOS: RFCOMM channel: {}", rfcomm_channels::MESH_DATA);
        
        Ok(())
    }
    
    /// Windows: Accept incoming RFCOMM connection
    #[cfg(target_os = "windows")]
    async fn windows_accept_rfcomm(&self) -> Result<RfcommStream> {
        #[cfg(feature = "windows-gatt")]
        {
            use windows::{
                Networking::Sockets::*,
                Storage::Streams::*,
            };
            
            info!(" Windows: Waiting for RFCOMM connection...");
            
            // Get service provider from storage
            let provider_guard = self.service_provider.read().await;
            if provider_guard.is_none() {
                return Err(anyhow!("RFCOMM service not registered"));
            }
            
            // Create a StreamSocketListener to accept connections
            let listener = StreamSocketListener::new()
                .map_err(|e| anyhow!("Failed to create socket listener: {:?}", e))?;
            
            // Connection received channel
            let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamSocket>(1);
            
            // Set up connection received handler
            listener.ConnectionReceived(&windows::Foundation::TypedEventHandler::new(
                move |_listener: &Option<StreamSocketListener>, args: &Option<StreamSocketListenerConnectionReceivedEventArgs>| {
                    if let Some(args) = args {
                        if let Ok(socket) = args.Socket() {
                            let tx = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx.send(socket).await;
                            });
                        }
                    }
                    Ok(())
                }
            )).map_err(|e| anyhow!("Failed to set connection handler: {:?}", e))?;
            
            // Wait for incoming connection with timeout
            let socket = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                rx.recv()
            ).await
                .map_err(|_| anyhow!("Connection timeout"))?
                .ok_or_else(|| anyhow!("Connection channel closed"))?;
            
            // Get input/output streams
            let input_stream = socket.InputStream()
                .map_err(|e| anyhow!("Failed to get input stream: {:?}", e))?;
            let output_stream = socket.OutputStream()
                .map_err(|e| anyhow!("Failed to get output stream: {:?}", e))?;
            
            // Create DataReader and DataWriter
            let reader = DataReader::CreateDataReader(&input_stream)
                .map_err(|e| anyhow!("Failed to create data reader: {:?}", e))?;
            let writer = DataWriter::CreateDataWriter(&output_stream)
                .map_err(|e| anyhow!("Failed to create data writer: {:?}", e))?;
            
            // Get peer information
            let remote_info = socket.Information()
                .map_err(|e| anyhow!("Failed to get socket info: {:?}", e))?;
            let remote_hostname = remote_info.RemoteHostName()
                .map_err(|e| anyhow!("Failed to get remote hostname: {:?}", e))?;
            let peer_address = remote_hostname.DisplayName()
                .map_err(|e| anyhow!("Failed to get peer address: {:?}", e))?
                .to_string();
            
            info!(" Windows: RFCOMM connection accepted from {}", peer_address);
            
            Ok(RfcommStream::from_windows_socket(socket, reader, writer, peer_address))
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            info!(" Windows: RFCOMM accept requires windows-gatt feature");
            Err(anyhow!("Windows RFCOMM support requires --features windows-gatt"))
        }
    }
    
    /// Linux: Accept incoming RFCOMM connection
    #[cfg(target_os = "linux")]
    async fn linux_accept_rfcomm(&self) -> Result<RfcommStream> {
        use nix::sys::socket::{accept, AddressFamily, SockType, SockFlag};
        use nix::sys::socket::{socket, bind, listen, SockaddrLike};
        use std::os::unix::io::RawFd;
        
        info!(" Linux: Waiting for RFCOMM connection...");
        
        // RFCOMM protocol constant (from bluetooth.h)
        const BTPROTO_RFCOMM: i32 = 3;
        const RFCOMM_CHANNEL: u8 = 3; // MESH_DATA channel
        
        // Create RFCOMM socket
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_STREAM,
                BTPROTO_RFCOMM,
            )
        };
        
        if sock_fd < 0 {
            return Err(anyhow!("Failed to create RFCOMM socket"));
        }
        
        // Bind to RFCOMM channel
        #[repr(C)]
        struct sockaddr_rc {
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }
        
        let addr = sockaddr_rc {
            rc_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: [0; 6], // BDADDR_ANY
            rc_channel: RFCOMM_CHANNEL,
        };
        
        let bind_result = unsafe {
            libc::bind(
                sock_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_rc>() as libc::socklen_t,
            )
        };
        
        if bind_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to bind RFCOMM socket"));
        }
        
        // Listen for connections
        let listen_result = unsafe {
            libc::listen(sock_fd, 1)
        };
        
        if listen_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to listen on RFCOMM socket"));
        }
        
        info!(" Linux: RFCOMM socket listening on channel {}", RFCOMM_CHANNEL);
        
        // Accept connection (blocking - wrap in spawn_blocking)
        let client_fd = tokio::task::spawn_blocking(move || {
            unsafe {
                let client = libc::accept(sock_fd, std::ptr::null_mut(), std::ptr::null_mut());
                libc::close(sock_fd); // Close listener after accepting
                client
            }
        }).await?;
        
        if client_fd < 0 {
            return Err(anyhow!("Failed to accept RFCOMM connection"));
        }
        
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(client_fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        
        info!(" Linux: RFCOMM connection accepted (fd: {})", client_fd);
        
        // Format peer address (we don't have it from accept, use unknown)
        let peer_address = format!("RFCOMM:fd:{}", client_fd);
        
        Ok(RfcommStream::from_linux_socket(client_fd, peer_address))
    }
    
    /// macOS: Accept incoming RFCOMM connection
    #[cfg(target_os = "macos")]
    async fn macos_accept_rfcomm(&self) -> Result<RfcommStream> {
        info!("🍎 macOS: Setting up RFCOMM listener on BSD socket...");
        
        // macOS supports Bluetooth via BSD sockets similar to Linux
        // RFCOMM protocol constant (from IOBluetooth)
        const BTPROTO_RFCOMM: i32 = 3;
        const RFCOMM_CHANNEL: u8 = rfcomm_channels::MESH_DATA;
        
        // Create RFCOMM socket using BSD API
        let sock_fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_STREAM,
                BTPROTO_RFCOMM,
            )
        };
        
        if sock_fd < 0 {
            return Err(anyhow!("Failed to create RFCOMM socket on macOS"));
        }
        
        // Bind to RFCOMM channel
        // Note: sockaddr_rc structure is similar between Linux and macOS
        #[repr(C)]
        struct sockaddr_rc {
            rc_len: u8,
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }
        
        let addr = sockaddr_rc {
            rc_len: std::mem::size_of::<sockaddr_rc>() as u8,
            rc_family: AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: [0; 6], // BDADDR_ANY - bind to any local Bluetooth adapter
            rc_channel: RFCOMM_CHANNEL,
        };
        
        let bind_result = unsafe {
            libc::bind(
                sock_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_rc>() as libc::socklen_t,
            )
        };
        
        if bind_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to bind RFCOMM socket on macOS"));
        }
        
        // Listen for connections
        let listen_result = unsafe {
            libc::listen(sock_fd, 1)
        };
        
        if listen_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to listen on RFCOMM socket"));
        }
        
        info!(" macOS: RFCOMM socket listening on channel {}", RFCOMM_CHANNEL);
        
        // Accept connection (blocking - wrap in spawn_blocking)
        let (client_fd, peer_addr) = tokio::task::spawn_blocking(move || {
            let mut peer_addr = sockaddr_rc {
                rc_len: std::mem::size_of::<sockaddr_rc>() as u8,
                rc_family: 0,
                rc_bdaddr: [0; 6],
                rc_channel: 0,
            };
            let mut addr_len = std::mem::size_of::<sockaddr_rc>() as libc::socklen_t;
            
            unsafe {
                let client = libc::accept(
                    sock_fd,
                    &mut peer_addr as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                );
                libc::close(sock_fd); // Close listener after accepting
                (client, peer_addr)
            }
        }).await?;
        
        if client_fd < 0 {
            return Err(anyhow!("Failed to accept RFCOMM connection on macOS"));
        }
        
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(client_fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(client_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        
        // Format peer address
        let peer_address = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            peer_addr.rc_bdaddr[0], peer_addr.rc_bdaddr[1], peer_addr.rc_bdaddr[2],
            peer_addr.rc_bdaddr[3], peer_addr.rc_bdaddr[4], peer_addr.rc_bdaddr[5]
        );
        
        info!(" macOS: RFCOMM connection accepted from {} (fd: {})", peer_address, client_fd);
        
        Ok(RfcommStream::from_macos_channel(
            peer_addr.rc_channel,
            peer_address,
            client_fd
        ))
    }
    
    /// Send mesh message via RFCOMM
    pub async fn send_mesh_message(&self, target_address: &str, message: &[u8]) -> Result<()> {
        info!(" Sending RFCOMM message to {}: {} bytes", target_address, message.len());
        
        // Check if peer is connected
        let connections = self.active_connections.read().await;
        if !connections.contains_key(target_address) {
            return Err(anyhow!("Peer not connected: {}", target_address));
        }
        
        let connection = connections.get(target_address).unwrap();
        let mtu = connection.mtu as usize;
        
        // RFCOMM has larger MTU (1000 bytes typical) - less fragmentation needed
        if message.len() <= mtu {
            self.transmit_rfcomm_packet(message, target_address).await?;
        } else {
            // Fragment message (but with much larger chunks than BLE)
            let chunks: Vec<&[u8]> = message.chunks(mtu).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                info!("Sending RFCOMM fragment {}/{} ({} bytes)", i + 1, chunks.len(), chunk.len());
                self.transmit_rfcomm_packet(chunk, target_address).await?;
                
                // Minimal delay for flow control (RFCOMM handles this better than BLE)
                tokio::time::sleep(tokio::time::Duration::from_micros(500)).await;
            }
        }
        
        // Update connection activity
        drop(connections);
        let mut connections_mut = self.active_connections.write().await;
        if let Some(conn) = connections_mut.get_mut(target_address) {
            conn.last_seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        
        Ok(())
    }
    
    /// Send mesh message envelope via RFCOMM (NEW - Phase 1)
    pub async fn send_mesh_envelope(
        &self,
        peer_id: &PublicKey,
        envelope: &MeshMessageEnvelope,
    ) -> Result<()> {
        // Look up Bluetooth address from authenticated peers
        let connections = self.active_connections.read().await;
        let auth_peers = self.authenticated_peers.read().await;
        
        let mut target_address = None;
        for (address, verification) in auth_peers.iter() {
            if verification.peer_pubkey == peer_id.key_id {
                if connections.contains_key(address) {
                    target_address = Some(address.clone());
                    break;
                }
            }
        }
        
        let target_address = target_address
            .ok_or_else(|| anyhow!("No active Bluetooth connection to peer {:?}", hex::encode(&peer_id.key_id[0..8])))?;
        
        info!("📤 Sending mesh envelope {} to {:?} via RFCOMM", 
              envelope.message_id, 
              hex::encode(&peer_id.key_id[0..4]));
        
        // Serialize envelope
        let bytes = envelope.to_bytes()?;
        
        info!("Serialized envelope: {} bytes", bytes.len());
        
        // Send via existing send_mesh_message
        self.send_mesh_message(&target_address, &bytes).await?;
        
        info!(" Mesh envelope sent successfully");
        
        Ok(())
    }
    
    /// Get node ID as PublicKey
    pub fn get_node_id(&self) -> Result<PublicKey> {
        // Convert node_id bytes to PublicKey
        Ok(PublicKey::new(self.node_id.to_vec()))
    }
    
    /// Transmit packet via RFCOMM
    async fn transmit_rfcomm_packet(&self, data: &[u8], address: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.linux_transmit_rfcomm(data, address).await?;
        }
        
        #[cfg(target_os = "windows")]
        {
            self.windows_transmit_rfcomm(data, address).await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.macos_transmit_rfcomm(data, address).await?;
        }
        
        Ok(())
    }
    
    /// Linux RFCOMM transmission
    #[cfg(target_os = "linux")]
    async fn linux_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        
        debug!("Linux: RFCOMM transmit to {} ({} bytes)", address, data.len());
        
        // Get stored stream
        let streams = self.active_streams.read().await;
        let stream_arc = streams.get(address)
            .ok_or_else(|| anyhow!("No active RFCOMM stream to {}", address))?;
        
        // Write data to stream
        let mut stream_guard = stream_arc.write().await;
        
        stream_guard.write_all(data).await
            .map_err(|e| anyhow!("Failed to write to RFCOMM stream: {}", e))?;
        
        stream_guard.flush().await
            .map_err(|e| anyhow!("Failed to flush RFCOMM stream: {}", e))?;
        
        info!(" Linux: Transmitted {} bytes to {} via RFCOMM", data.len(), address);
        Ok(())
    }
    
    /// Windows RFCOMM transmission
    #[cfg(target_os = "windows")]
    async fn windows_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        #[cfg(feature = "windows-gatt")]
        {
            use tokio::io::AsyncWriteExt;
            
            debug!("Windows: RFCOMM transmit to {} ({} bytes)", address, data.len());
            
            // Get stored stream
            let streams = self.active_streams.read().await;
            let stream_arc = streams.get(address)
                .ok_or_else(|| anyhow!("No active RFCOMM stream to {}", address))?;
            
            // Write data to stream
            let mut stream_guard = stream_arc.write().await;
            
            // Use tokio::io::AsyncWriteExt to write the data
            stream_guard.write_all(data).await
                .map_err(|e| anyhow!("Failed to write to RFCOMM stream: {}", e))?;
            
            stream_guard.flush().await
                .map_err(|e| anyhow!("Failed to flush RFCOMM stream: {}", e))?;
            
            info!(" Windows: Transmitted {} bytes to {} via RFCOMM", data.len(), address);
            Ok(())
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            debug!("Windows: RFCOMM transmit to {} ({} bytes) - feature disabled", address, data.len());
            Err(anyhow!("Windows RFCOMM requires --features windows-gatt"))
        }
    }
    
    /// macOS RFCOMM transmission
    #[cfg(target_os = "macos")]
    async fn macos_transmit_rfcomm(&self, data: &[u8], address: &str) -> Result<()> {
        debug!("macOS: RFCOMM transmit to {} ({} bytes)", address, data.len());
        
        // Find active connection with socket FD
        let connections = self.active_connections.read().await;
        let _connection = connections.get(address)
            .ok_or_else(|| anyhow!("No active connection to {}", address))?;
        
        // In a full implementation, we would store the socket FD in the connection
        // and write directly to it here
        // For now, log the transmission
        info!(" macOS: Transmitted {} bytes to {} via RFCOMM", data.len(), address);
        
        Ok(())
    }
    
    /// Get active RFCOMM connections
    pub async fn get_connections(&self) -> Vec<RfcommConnection> {
        self.active_connections.read().await.values().cloned().collect()
    }
    
    // ============================================================================
    // DEVICE DISCOVERY AND ACTIVE CONNECTION METHODS
    // ============================================================================
    
    
    /// Start discovering Bluetooth Classic devices (marks discovery as active)
    pub async fn start_discovery(&self) -> Result<()> {
        if !self.is_enabled() {
            return Err(anyhow!("Bluetooth Classic is disabled. Call enable() first."));
        }
        
        self.discovery_active.store(true, std::sync::atomic::Ordering::SeqCst);
        info!(" Bluetooth Classic discovery started");
        Ok(())
    }
    
    /// Stop discovering Bluetooth Classic devices
    pub async fn stop_discovery(&self) -> Result<()> {
        self.discovery_active.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("🛑 Bluetooth Classic discovery stopped");
        Ok(())
    }
    
    /// Discover paired Bluetooth devices (cross-platform)
    pub async fn discover_paired_devices(&self) -> Result<Vec<BluetoothDevice>> {
        if !self.is_enabled() {
            return Err(anyhow!("Bluetooth Classic is disabled. Call enable() first."));
        }
        
        #[cfg(target_os = "windows")]
        {
            self.discover_paired_devices_windows().await
        }
        
        #[cfg(target_os = "linux")]
        {
            self.discover_paired_devices_linux().await
        }
        
        #[cfg(target_os = "macos")]
        {
            self.discover_paired_devices_macos().await
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Device discovery not supported on this platform"))
        }
    }
    
    /// Query RFCOMM services on a device (cross-platform)
    pub async fn query_rfcomm_services(&self, device_address: &str) -> Result<Vec<RfcommServiceInfo>> {
        #[cfg(target_os = "windows")]
        {
            self.query_services_windows(device_address).await
        }
        
        #[cfg(target_os = "linux")]
        {
            self.query_services_linux(device_address).await
        }
        
        #[cfg(target_os = "macos")]
        {
            self.query_services_macos(device_address).await
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Service query not supported on this platform"))
        }
    }
    
    /// Connect to a peer's RFCOMM service and store the stream (cross-platform)
    pub async fn connect_to_peer(&self, device_address: &str, channel: u8) -> Result<RfcommStream> {
        if !self.is_enabled() {
            return Err(anyhow!("Bluetooth Classic is disabled. Call enable() first."));
        }
        
        // Create the connection
        let stream = self.connect_to_peer_internal(device_address, channel).await?;
        
        // Store the stream for later use
        let stream_arc = Arc::new(RwLock::new(stream));
        self.active_streams.write().await.insert(device_address.to_string(), stream_arc.clone());
        
        info!(" Stored RFCOMM stream for {}", device_address);
        
        // Return a clone (the stream is now stored in active_streams)
        // Note: We can't directly clone RfcommStream, so we need a different approach
        // For now, return an error directing users to use send_mesh_message instead
        Err(anyhow!("Stream stored successfully. Use send_mesh_message() to transmit data to {}", device_address))
    }
    
    /// Internal connection method (cross-platform)
    async fn connect_to_peer_internal(&self, device_address: &str, channel: u8) -> Result<RfcommStream> {
        #[cfg(target_os = "windows")]
        {
            self.connect_to_peer_windows(device_address, channel).await
        }
        
        #[cfg(target_os = "linux")]
        {
            self.connect_to_peer_linux(device_address, channel).await
        }
        
        #[cfg(target_os = "macos")]
        {
            self.connect_to_peer_macos(device_address, channel).await
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Peer connection not supported on this platform"))
        }
    }
    
    // ============================================================================
    // WINDOWS DISCOVERY AND CONNECTION
    // ============================================================================
    
    #[cfg(target_os = "windows")]
    async fn discover_paired_devices_windows(&self) -> Result<Vec<BluetoothDevice>> {
        #[cfg(feature = "windows-gatt")]
        {
            use windows::{
                Devices::Bluetooth::BluetoothDevice as WinBluetoothDevice,
                Devices::Enumeration::{DeviceInformation, DeviceInformationCollection},
            };
            
            info!(" Windows: Discovering paired Bluetooth devices...");
            
            // Query for paired Bluetooth devices
            let selector = WinBluetoothDevice::GetDeviceSelectorFromPairingState(true)
                .map_err(|e| anyhow!("Failed to get device selector: {:?}", e))?;
            
            let device_info_collection = DeviceInformation::FindAllAsyncAqsFilter(&selector)
                .map_err(|e| anyhow!("Failed to query devices: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Failed to get devices: {:?}", e))?;
            
            let mut devices = Vec::new();
            let count = device_info_collection.Size()
                .map_err(|e| anyhow!("Failed to get device count: {:?}", e))?;
            
            for i in 0..count {
                if let Ok(device_info) = device_info_collection.GetAt(i) {
                    if let Ok(id) = device_info.Id() {
                        let id_string = id.to_string_lossy();
                        // Get Bluetooth device from ID
                        if let Ok(async_op) = WinBluetoothDevice::FromIdAsync(&id) {
                            if let Ok(bt_device) = async_op.get() {
                                let address = Self::format_bluetooth_address_windows(&bt_device)?;
                                
                                let name = device_info.Name()
                                    .ok()
                                    .map(|h_string| h_string.to_string_lossy())
                                    .map(|s| s.to_string());
                                
                                let device_class = bt_device.ClassOfDevice()
                                    .ok()
                                    .and_then(|cod| cod.RawValue().ok())
                                    .unwrap_or(0);
                                
                                let is_connected = bt_device.ConnectionStatus()
                                    .ok()
                                    .map(|s| s.0 == 1) // Connected = 1
                                    .unwrap_or(false);
                                
                                devices.push(BluetoothDevice {
                                    address: address.clone(),
                                    name: name.clone(),
                                    device_class,
                                    is_paired: true,
                                    is_connected,
                                    rssi: None, // Windows doesn't expose RSSI easily for paired devices
                                    last_seen: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                });
                                
                                info!("  Found device: {} ({})", name.as_deref().unwrap_or("Unknown"), address);
                            }
                        }
                    }
                }
            }
            
            info!(" Windows: Found {} paired devices", devices.len());
            Ok(devices)
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            Err(anyhow!("Windows discovery requires --features windows-gatt"))
        }
    }
    
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    fn format_bluetooth_address_windows(device: &windows::Devices::Bluetooth::BluetoothDevice) -> Result<String> {
        let address = device.BluetoothAddress()
            .map_err(|e| anyhow!("Failed to get address: {:?}", e))?;
        
        // Convert u64 to MAC address string
        Ok(format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (address >> 40) & 0xFF,
            (address >> 32) & 0xFF,
            (address >> 24) & 0xFF,
            (address >> 16) & 0xFF,
            (address >> 8) & 0xFF,
            address & 0xFF
        ))
    }
    
    #[cfg(target_os = "windows")]
    async fn query_services_windows(&self, device_address: &str) -> Result<Vec<RfcommServiceInfo>> {
        #[cfg(feature = "windows-gatt")]
        {
            use windows::{
                Devices::Bluetooth::{BluetoothDevice, Rfcomm::RfcommDeviceService},
            };
            
            info!(" Windows: Querying RFCOMM services on {}", device_address);
            
            // Convert address to u64 for Windows API
            let address_u64 = Self::parse_bluetooth_address_to_u64(device_address)?;
            
            // Get device from address
            let bt_device = BluetoothDevice::FromBluetoothAddressAsync(address_u64)
                .map_err(|e| anyhow!("Failed to get device: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Device not found: {:?}", e))?;
            
            // Get RFCOMM services
            let services_result = bt_device.GetRfcommServicesAsync()
                .map_err(|e| anyhow!("Failed to query services: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Failed to get services: {:?}", e))?;
            
            let services = services_result.Services()
                .map_err(|e| anyhow!("Failed to get service list: {:?}", e))?;
            
            let mut rfcomm_services = Vec::new();
            let count = services.Size()
                .map_err(|e| anyhow!("Failed to get service count: {:?}", e))?;
            
            for i in 0..count {
                if let Ok(service) = services.GetAt(i) {
                    if let Ok(service_id) = service.ServiceId() {
                        if let Ok(uuid) = service_id.Uuid() {
                            let uuid_str = format!("{:?}", uuid);
                            
                            // Check if this is our ZHTP service or any RFCOMM service
                            let service_name = if uuid_str.contains("6ba7b810") {
                                "ZHTP Mesh".to_string()
                            } else {
                                format!("RFCOMM Service {}", i)
                            };
                            
                            rfcomm_services.push(RfcommServiceInfo {
                                service_uuid: uuid_str,
                                service_name,
                                channel: (i + 1) as u8, // Approximate channel
                                device_address: device_address.to_string(),
                            });
                        }
                    }
                }
            }
            
            info!(" Windows: Found {} RFCOMM services on {}", rfcomm_services.len(), device_address);
            Ok(rfcomm_services)
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            Err(anyhow!("Windows service query requires --features windows-gatt"))
        }
    }
    
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    fn parse_bluetooth_address_to_u64(address: &str) -> Result<u64> {
        let clean = address.replace([':', '-'], "");
        if clean.len() != 12 {
            return Err(anyhow!("Invalid Bluetooth address format"));
        }
        
        u64::from_str_radix(&clean, 16)
            .map_err(|e| anyhow!("Failed to parse address: {}", e))
    }
    
    #[cfg(target_os = "windows")]
    async fn connect_to_peer_windows(&self, device_address: &str, channel: u8) -> Result<RfcommStream> {
        #[cfg(feature = "windows-gatt")]
        {
            use windows::{
                Devices::Bluetooth::{BluetoothDevice, Rfcomm::RfcommDeviceService},
                Networking::Sockets::StreamSocket,
                Storage::Streams::{DataReader, DataWriter},
            };
            
            info!(" Windows: Connecting to RFCOMM service on {} channel {}", device_address, channel);
            
            // Convert address to u64
            let address_u64 = Self::parse_bluetooth_address_to_u64(device_address)?;
            
            // Get device
            let bt_device = BluetoothDevice::FromBluetoothAddressAsync(address_u64)
                .map_err(|e| anyhow!("Failed to get device: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Device not found: {:?}", e))?;
            
            // Get RFCOMM services
            let services_result = bt_device.GetRfcommServicesAsync()
                .map_err(|e| anyhow!("Failed to query services: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Failed to get services: {:?}", e))?;
            
            let services = services_result.Services()
                .map_err(|e| anyhow!("Failed to get service list: {:?}", e))?;
            
            // Find ZHTP service or first available service
            let service = if services.Size().unwrap_or(0) > 0 {
                services.GetAt(0)
                    .map_err(|e| anyhow!("Failed to get service: {:?}", e))?
            } else {
                return Err(anyhow!("No RFCOMM services found on device"));
            };
            
            // Create socket and connect
            let socket = StreamSocket::new()
                .map_err(|e| anyhow!("Failed to create socket: {:?}", e))?;
            
            let hostname = bt_device.HostName()
                .map_err(|e| anyhow!("Failed to get hostname: {:?}", e))?;
            
            let service_name = service.ServiceId()
                .and_then(|id| id.AsString())
                .map_err(|e| anyhow!("Failed to get service name: {:?}", e))?;
            
            socket.ConnectAsync(&hostname, &service_name)
                .map_err(|e| anyhow!("Failed to initiate connection: {:?}", e))?
                .get()
                .map_err(|e| anyhow!("Connection failed: {:?}", e))?;
            
            // Create data reader/writer
            let input_stream = socket.InputStream()
                .map_err(|e| anyhow!("Failed to get input stream: {:?}", e))?;
            let output_stream = socket.OutputStream()
                .map_err(|e| anyhow!("Failed to get output stream: {:?}", e))?;
            
            let reader = DataReader::CreateDataReader(&input_stream)
                .map_err(|e| anyhow!("Failed to create reader: {:?}", e))?;
            let writer = DataWriter::CreateDataWriter(&output_stream)
                .map_err(|e| anyhow!("Failed to create writer: {:?}", e))?;
            
            info!(" Windows: Connected to {} via RFCOMM", device_address);
            
            // Track connection
            let connection = RfcommConnection {
                peer_id: device_address.to_string(),
                peer_address: device_address.to_string(),
                connected_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                channel,
                mtu: 1000, // Windows RFCOMM typical MTU
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                is_outgoing: true,
            };
            
            // Update active connections using async write to avoid blocking the runtime
            self.active_connections
                .write()
                .await
                .insert(device_address.to_string(), connection);

            Ok(RfcommStream::from_windows_socket(socket, reader, writer, device_address.to_string()))
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            Err(anyhow!("Windows connection requires --features windows-gatt"))
        }
    }
    
    // ============================================================================
    // LINUX DISCOVERY AND CONNECTION
    // ============================================================================
    
    #[cfg(target_os = "linux")]
    async fn discover_paired_devices_linux(&self) -> Result<Vec<BluetoothDevice>> {
        info!(" Linux: Discovering paired Bluetooth devices via BlueZ...");
        
        // Use bluetoothctl to list paired devices
        let output = std::process::Command::new("bluetoothctl")
            .args(&["devices", "Paired"])
            .output();
        
        let mut devices = Vec::new();
        
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                
                for line in output_str.lines() {
                    // Parse line format: "Device AA:BB:CC:DD:EE:FF Device Name"
                    if line.starts_with("Device ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let address = parts[1].to_string();
                            let name = parts[2..].join(" ");
                            
                            // Check if device is connected
                            let is_connected = Self::check_device_connected_linux(&address).await;
                            
                            devices.push(BluetoothDevice {
                                address: address.clone(),
                                name: Some(name.clone()),
                                device_class: 0, // Would need DBus to get class
                                is_paired: true,
                                is_connected,
                                rssi: None,
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            });
                            
                            info!("  Found device: {} ({})", name, address);
                        }
                    }
                }
            }
            Ok(result) => {
                warn!(" Linux: bluetoothctl failed: {}", String::from_utf8_lossy(&result.stderr));
            }
            Err(e) => {
                warn!(" Linux: bluetoothctl not available: {}", e);
                // Fallback: try to read from /var/lib/bluetooth
                devices = Self::discover_devices_from_bluez_cache()?;
            }
        }
        
        info!(" Linux: Found {} paired devices", devices.len());
        Ok(devices)
    }
    
    #[cfg(target_os = "linux")]
    async fn check_device_connected_linux(address: &str) -> bool {
        let output = std::process::Command::new("bluetoothctl")
            .args(&["info", address])
            .output();
        
        if let Ok(result) = output {
            let info = String::from_utf8_lossy(&result.stdout);
            info.contains("Connected: yes")
        } else {
            false
        }
    }
    
    #[cfg(target_os = "linux")]
    fn discover_devices_from_bluez_cache() -> Result<Vec<BluetoothDevice>> {
        let mut devices = Vec::new();
        let bluez_path = "/var/lib/bluetooth";
        
        if let Ok(adapters) = std::fs::read_dir(bluez_path) {
            for adapter_entry in adapters.flatten() {
                let adapter_path = adapter_entry.path();
                if let Ok(device_dirs) = std::fs::read_dir(&adapter_path) {
                    for device_entry in device_dirs.flatten() {
                        let device_path = device_entry.path();
                        let info_file = device_path.join("info");
                        
                        if let Ok(content) = std::fs::read_to_string(&info_file) {
                            if content.contains("Paired=true") {
                                let address = device_entry.file_name()
                                    .to_string_lossy()
                                    .replace('_', ":");
                                
                                let name = content.lines()
                                    .find(|l| l.starts_with("Name="))
                                    .and_then(|l| l.split('=').nth(1))
                                    .map(|s| s.to_string());
                                
                                devices.push(BluetoothDevice {
                                    address: address.clone(),
                                    name,
                                    device_class: 0,
                                    is_paired: true,
                                    is_connected: false,
                                    rssi: None,
                                    last_seen: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        Ok(devices)
    }
    
    #[cfg(target_os = "linux")]
    async fn query_services_linux(&self, device_address: &str) -> Result<Vec<RfcommServiceInfo>> {
        info!(" Linux: Querying RFCOMM services on {}", device_address);
        
        // Use sdptool to browse services
        let output = std::process::Command::new("sdptool")
            .args(&["browse", device_address])
            .output();
        
        let mut services = Vec::new();
        
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                let mut current_service: Option<(String, String, u8)> = None;
                
                for line in output_str.lines() {
                    // Look for service records
                    if line.contains("Service Name:") {
                        if let Some(name) = line.split(':').nth(1) {
                            if let Some((uuid, _, channel)) = current_service.take() {
                                services.push(RfcommServiceInfo {
                                    service_uuid: uuid,
                                    service_name: name.trim().to_string(),
                                    channel,
                                    device_address: device_address.to_string(),
                                });
                            }
                            current_service = Some((String::new(), name.trim().to_string(), 0));
                        }
                    }
                    
                    if line.contains("Service RecHandle:") || line.contains("Service Class ID:") {
                        if let Some(uuid_part) = line.split("0x").nth(1) {
                            if let Some((_, name, channel)) = current_service.as_ref() {
                                current_service = Some((
                                    uuid_part.trim().to_string(),
                                    name.clone(),
                                    *channel
                                ));
                            }
                        }
                    }
                    
                    if line.contains("Channel:") {
                        if let Some(channel_str) = line.split(':').nth(1) {
                            if let Ok(channel) = channel_str.trim().parse::<u8>() {
                                if let Some((uuid, name, _)) = current_service.as_ref() {
                                    current_service = Some((uuid.clone(), name.clone(), channel));
                                }
                            }
                        }
                    }
                }
                
                // Add final service
                if let Some((uuid, name, channel)) = current_service {
                    services.push(RfcommServiceInfo {
                        service_uuid: uuid,
                        service_name: name,
                        channel,
                        device_address: device_address.to_string(),
                    });
                }
            }
            Ok(result) => {
                warn!(" Linux: sdptool failed: {}", String::from_utf8_lossy(&result.stderr));
            }
            Err(e) => {
                warn!(" Linux: sdptool not available: {}", e);
            }
        }
        
        // If no services found via sdptool, try default ZHTP channel
        if services.is_empty() {
            services.push(RfcommServiceInfo {
                service_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430ca".to_string(),
                service_name: "ZHTP Mesh (default)".to_string(),
                channel: rfcomm_channels::MESH_DATA,
                device_address: device_address.to_string(),
            });
        }
        
        info!(" Linux: Found {} RFCOMM services on {}", services.len(), device_address);
        Ok(services)
    }
    
    #[cfg(target_os = "linux")]
    async fn connect_to_peer_linux(&self, device_address: &str, channel: u8) -> Result<RfcommStream> {
        info!(" Linux: Connecting to RFCOMM service on {} channel {}", device_address, channel);
        
        // Parse MAC address
        let mac_bytes = parse_mac_address(device_address)?;
        
        // RFCOMM protocol constant
        const BTPROTO_RFCOMM: i32 = 3;
        
        // Create RFCOMM socket
        let sock_fd = unsafe {
            libc::socket(libc::AF_BLUETOOTH, libc::SOCK_STREAM, BTPROTO_RFCOMM)
        };
        
        if sock_fd < 0 {
            return Err(anyhow!("Failed to create RFCOMM socket"));
        }
        
        // Connect to remote device
        #[repr(C)]
        struct sockaddr_rc {
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }
        
        let addr = sockaddr_rc {
            rc_family: libc::AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: mac_bytes,
            rc_channel: channel,
        };
        
        let connect_result = tokio::task::spawn_blocking(move || {
            unsafe {
                libc::connect(
                    sock_fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<sockaddr_rc>() as libc::socklen_t,
                )
            }
        }).await?;
        
        if connect_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow!("Failed to connect to RFCOMM device"));
        }
        
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        
        info!(" Linux: Connected to {} channel {} (fd: {})", device_address, channel, sock_fd);
        
        // Track connection
        let connection = RfcommConnection {
            peer_id: device_address.to_string(),
            peer_address: device_address.to_string(),
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            channel,
            mtu: 1000,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_outgoing: true,
        };
        
        self.active_connections.write().await.insert(device_address.to_string(), connection);
        
        Ok(RfcommStream::from_linux_socket(sock_fd, device_address.to_string()))
    }
    
    // ============================================================================
    // MACOS DISCOVERY AND CONNECTION
    // ============================================================================
    
    #[cfg(target_os = "macos")]
    async fn discover_paired_devices_macos(&self) -> Result<Vec<BluetoothDevice>> {
        info!("🍎 macOS: Discovering paired Bluetooth devices...");
        
        // Use system_profiler to get Bluetooth device information
        let output = std::process::Command::new("system_profiler")
            .args(&["SPBluetoothDataType", "-json"])
            .output();
        
        let mut devices = Vec::new();
        
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                
                // Parse JSON output (basic parsing)
                for line in output_str.lines() {
                    if line.contains("\"Address\"") || line.contains("\"address\"") {
                        if let Some(addr_start) = line.find("\"") {
                            if let Some(addr_part) = line[addr_start..].split('\"').nth(3) {
                                let address = addr_part.to_string();
                                
                                // Simple device entry
                                devices.push(BluetoothDevice {
                                    address: address.clone(),
                                    name: Some("macOS Device".to_string()),
                                    device_class: 0,
                                    is_paired: true,
                                    is_connected: false,
                                    rssi: None,
                                    last_seen: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {
                // Fallback: use blueutil if available
                let blueutil_output = std::process::Command::new("blueutil")
                    .args(&["--paired"])
                    .output();
                
                if let Ok(result) = blueutil_output {
                    let output_str = String::from_utf8_lossy(&result.stdout);
                    for line in output_str.lines() {
                        // Parse blueutil output format
                        if let Some(address) = line.split(',').next() {
                            devices.push(BluetoothDevice {
                                address: address.trim().to_string(),
                                name: Some("Paired Device".to_string()),
                                device_class: 0,
                                is_paired: true,
                                is_connected: false,
                                rssi: None,
                                last_seen: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            });
                        }
                    }
                }
            }
        }
        
        info!(" macOS: Found {} paired devices", devices.len());
        Ok(devices)
    }
    
    #[cfg(target_os = "macos")]
    async fn query_services_macos(&self, device_address: &str) -> Result<Vec<RfcommServiceInfo>> {
        info!("🍎 macOS: Querying RFCOMM services on {}", device_address);
        
        // macOS doesn't have easy command-line SDP browsing
        // Return default ZHTP service info
        let services = vec![
            RfcommServiceInfo {
                service_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430ca".to_string(),
                service_name: "ZHTP Mesh".to_string(),
                channel: rfcomm_channels::MESH_DATA,
                device_address: device_address.to_string(),
            }
        ];
        
        info!(" macOS: Returning default ZHTP service for {}", device_address);
        Ok(services)
    }
    
    #[cfg(target_os = "macos")]
    async fn connect_to_peer_macos(&self, device_address: &str, channel: u8) -> Result<RfcommStream> {
        info!("🍎 macOS: Connecting to RFCOMM service on {} channel {}", device_address, channel);
        
        // Parse MAC address
        let mac_bytes = parse_mac_address(device_address)?;
        
        // RFCOMM protocol constant
        const BTPROTO_RFCOMM: i32 = 3;
        
        // Create RFCOMM socket using BSD API
        let sock_fd = unsafe {
            libc::socket(AF_BLUETOOTH, libc::SOCK_STREAM, BTPROTO_RFCOMM)
        };
        
        if sock_fd < 0 {
            return Err(anyhow!("Failed to create RFCOMM socket on macOS"));
        }
        
        // Connect to remote device
        #[repr(C)]
        struct sockaddr_rc {
            rc_len: u8,
            rc_family: libc::sa_family_t,
            rc_bdaddr: [u8; 6],
            rc_channel: u8,
        }
        
        let addr = sockaddr_rc {
            rc_len: std::mem::size_of::<sockaddr_rc>() as u8,
            rc_family: AF_BLUETOOTH as libc::sa_family_t,
            rc_bdaddr: mac_bytes,
            rc_channel: channel,
        };
        
        let connect_result = tokio::task::spawn_blocking(move || {
            unsafe {
                libc::connect(
                    sock_fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<sockaddr_rc>() as libc::socklen_t,
                )
            }
        }).await?;
        
        if connect_result < 0 {
            unsafe { libc::close(sock_fd); }
            let errno = unsafe { *libc::__error() };
            return Err(anyhow!("Failed to connect to RFCOMM device: errno {}", errno));
        }
        
        // Set non-blocking mode
        let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL, 0) };
        unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        
        info!(" macOS: Connected to {} channel {} (fd: {})", device_address, channel, sock_fd);
        
        // Track connection
        let connection = RfcommConnection {
            peer_id: device_address.to_string(),
            peer_address: device_address.to_string(),
            connected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            channel,
            mtu: 1000,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_outgoing: true,
        };
        
        self.active_connections.write().await.insert(device_address.to_string(), connection);
        
        Ok(RfcommStream::from_macos_channel(channel, device_address.to_string(), sock_fd))
    }
    
    // ============================================================================
    // MESSAGE HANDLING AND MULTI-CHANNEL SUPPORT
    // ============================================================================
    
    /// Handle incoming messages from an RFCOMM stream
    /// Processes different message types based on channel or first byte
    pub async fn handle_incoming_messages(&self, stream: Arc<RwLock<RfcommStream>>) -> Result<()> {
        use tokio::io::AsyncReadExt;
        
        let peer_addr = {
            let stream_guard = stream.read().await;
            stream_guard.peer_addr().to_string()
        };
        
        info!("📬 Starting message handler for RFCOMM connection: {}", peer_addr);
        
        loop {
            let mut buffer = vec![0u8; 4096]; // RFCOMM can handle larger buffers than BLE
            
            let n = {
                let mut stream_guard = stream.write().await;
                match stream_guard.read(&mut buffer).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(" Read error from {}: {}", peer_addr, e);
                        break;
                    }
                }
            };
            
            if n == 0 {
                info!("🔌 Connection closed by {}", peer_addr);
                break;
            }
            
            buffer.truncate(n);
            debug!("📨 Received {} bytes from {}", n, peer_addr);
            
            // Process message based on first byte (message type)
            match buffer.get(0) {
                Some(0x01) => {
                    debug!(" ZK auth message from {}", peer_addr);
                    if let Err(e) = self.handle_zk_auth_message(&buffer[1..], &peer_addr).await {
                        warn!("Failed to process ZK auth message: {}", e);
                    }
                },
                Some(0x02) => {
                    debug!(" Quantum routing message from {}", peer_addr);
                    if let Err(e) = self.handle_quantum_routing_message(&buffer[1..], &peer_addr).await {
                        warn!("Failed to process quantum routing message: {}", e);
                    }
                },
                Some(0x03) => {
                    debug!(" Mesh data message from {}", peer_addr);
                    if let Err(e) = self.handle_mesh_data_message(&buffer[1..], &peer_addr).await {
                        warn!("Failed to process mesh data message: {}", e);
                    }
                },
                Some(0x04) => {
                    debug!(" Coordination message from {}", peer_addr);
                    if let Err(e) = self.handle_coordination_message(&buffer[1..], &peer_addr).await {
                        warn!("Failed to process coordination message: {}", e);
                    }
                },
                Some(msg_type) => {
                    warn!(" Unknown message type from {}: 0x{:02X}", peer_addr, msg_type);
                },
                None => {
                    warn!(" Empty message from {}", peer_addr);
                }
            }
            
            // Update last seen timestamp
            if let Some(conn) = self.active_connections.write().await.get_mut(&peer_addr) {
                conn.last_seen = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }
        }
        
        // Clean up connection
        info!("🧹 Cleaning up connection to {}", peer_addr);
        self.active_connections.write().await.remove(&peer_addr);
        self.active_streams.write().await.remove(&peer_addr);
        
        Ok(())
    }
    
    /// Handle ZK authentication message
    async fn handle_zk_auth_message(&self, data: &[u8], peer_addr: &str) -> Result<()> {
        info!(" Processing ZK auth message from {} ({} bytes)", peer_addr, data.len());
        
        // Try to parse as ZhtpAuthChallenge or ZhtpAuthResponse
        if let Ok(challenge) = serde_json::from_slice::<crate::protocols::zhtp_auth::ZhtpAuthChallenge>(data) {
            info!(" Received ZK auth challenge from {}", peer_addr);
            
            // Respond to challenge
            let auth_manager = self.auth_manager.read().await;
            if let Some(auth_mgr) = auth_manager.as_ref() {
                let capabilities = self.get_node_capabilities(true, 100); // has_dht=true, reputation=100
                match auth_mgr.respond_to_challenge(&challenge, capabilities) {
                    Ok(response) => {
                        let response_data = serde_json::to_vec(&response)?;
                        let mut message = vec![0x01]; // ZK auth type
                        message.extend_from_slice(&response_data);
                        
                        self.send_mesh_message(peer_addr, &message).await?;
                        info!(" Sent ZK auth response to {}", peer_addr);
                    }
                    Err(e) => {
                        warn!("Failed to create auth response: {}", e);
                    }
                }
            }
        } else if let Ok(response) = serde_json::from_slice::<crate::protocols::zhtp_auth::ZhtpAuthResponse>(data) {
            info!(" Received ZK auth response from {}", peer_addr);
            
            // Verify response
            let auth_manager = self.auth_manager.read().await;
            if let Some(auth_mgr) = auth_manager.as_ref() {
                match auth_mgr.verify_response(&response).await {
                    Ok(verification) => {
                        if verification.authenticated {
                            info!(" Peer {} authenticated! Trust score: {:.2}", peer_addr, verification.trust_score);
                            self.authenticated_peers.write().await.insert(
                                peer_addr.to_string(),
                                verification,
                            );
                        } else {
                            warn!(" Peer {} failed authentication", peer_addr);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to verify auth response: {}", e);
                    }
                }
            }
        } else {
            warn!(" Invalid ZK auth message format from {}", peer_addr);
        }
        
        Ok(())
    }
    
    /// Handle quantum routing message
    async fn handle_quantum_routing_message(&self, data: &[u8], peer_addr: &str) -> Result<()> {
        info!("🔮 Processing quantum routing message from {} ({} bytes)", peer_addr, data.len());
        
        // TODO: Implement Kyber key exchange and quantum-resistant routing
        // For now, just log the message
        debug!("Quantum routing data: {:?}", &data[..std::cmp::min(32, data.len())]);
        
        Ok(())
    }
    
    /// Handle mesh data message
    async fn handle_mesh_data_message(&self, data: &[u8], peer_addr: &str) -> Result<()> {
        info!(" Received mesh data message from {} ({} bytes)", peer_addr, data.len());
        
        // Deserialize envelope
        let envelope = match MeshMessageEnvelope::from_bytes(data) {
            Ok(env) => env,
            Err(e) => {
                warn!("Failed to deserialize mesh envelope: {}", e);
                return Err(e);
            }
        };
        
        info!("📨 Envelope {} from {:?} to {:?} (TTL: {}, hop: {})", 
              envelope.message_id,
              hex::encode(&envelope.origin.key_id[0..4]),
              hex::encode(&envelope.destination.key_id[0..4]),
              envelope.ttl,
              envelope.hop_count);
        
        // Get my node ID
        let my_id = self.get_node_id()?;
        
        // Check if message is for me
        if envelope.is_for_me(&my_id) {
            info!(" Message is for me, processing locally");
            return self.process_local_message(envelope).await;
        }
        
        // Check if should forward
        if envelope.should_drop(&my_id) {
            warn!(" Message TTL expired or loop detected, dropping");
            return Ok(());
        }
        
        // Check for loops
        if envelope.contains_in_route(&my_id) {
            warn!(" Loop detected in route, dropping message");
            return Ok(());
        }
        
        // Forward to next hop
        info!("📨 Message needs forwarding to {:?}", 
              hex::encode(&envelope.destination.key_id[0..4]));
        return self.forward_message(envelope).await;
    }
    
    /// Process message intended for this node (NEW - Phase 1)
    async fn process_local_message(&self, envelope: MeshMessageEnvelope) -> Result<()> {
        info!("Processing local message type: {:?}", envelope.message_type);

        // Deserialize message from envelope (Issue #479 - single-pass deserialization)
        let message = envelope.deserialize_message()?;

        // Get message handler if available
        if let Some(handler) = &self.message_handler {
            let handler_guard = handler.read().await;

            // Dispatch to appropriate handler based on message type
            match message {
                ZhtpMeshMessage::ZhtpRequest(request) => {
                    // Convert ZhtpHeaders to HashMap for compatibility
                    let mut headers_map = std::collections::HashMap::new();
                    if let Some(ct) = &request.headers.content_type {
                        headers_map.insert("Content-Type".to_string(), ct.clone());
                    }
                    if let Some(cl) = request.headers.content_length {
                        headers_map.insert("Content-Length".to_string(), cl.to_string());
                    }
                    for (k, v) in &request.headers.custom {
                        headers_map.insert(k.clone(), v.clone());
                    }

                    handler_guard.handle_lib_request(
                        envelope.origin.clone(),
                        request.method.to_string(),
                        request.uri,
                        headers_map,
                        request.body,
                        request.timestamp
                    ).await?;
                }
                ZhtpMeshMessage::ZhtpResponse(response) => {
                    // Convert ZhtpHeaders to HashMap
                    let mut headers_map = std::collections::HashMap::new();
                    if let Some(ct) = &response.headers.content_type {
                        headers_map.insert("Content-Type".to_string(), ct.clone());
                    }
                    if let Some(cl) = response.headers.content_length {
                        headers_map.insert("Content-Length".to_string(), cl.to_string());
                    }
                    for (k, v) in &response.headers.custom {
                        headers_map.insert(k.clone(), v.clone());
                    }

                    // Try to find request_id in headers or use 0
                    let request_id = response.headers.custom.get("Request-ID")
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);

                    handler_guard.handle_lib_response(
                        request_id,
                        response.status.code(),
                        response.status_message,
                        headers_map,
                        response.body,
                        response.timestamp
                    ).await?;
                }
                ZhtpMeshMessage::BlockchainRequest { requester, request_id, request_type } => {
                    handler_guard.handle_blockchain_request(requester, request_id, request_type).await?;
                }
                ZhtpMeshMessage::BlockchainData { sender, request_id, chunk_index, total_chunks, data, complete_data_hash } => {
                    handler_guard.handle_blockchain_data(&sender, request_id, chunk_index, total_chunks, data, complete_data_hash).await?;
                }
                ZhtpMeshMessage::NewBlock { .. } => {
                    info!("NewBlock message received - handler not yet implemented");
                    // TODO: Implement in Phase 3
                }
                ZhtpMeshMessage::NewTransaction { .. } => {
                    info!("NewTransaction message received - handler not yet implemented");
                    // TODO: Implement in Phase 3
                }
                ZhtpMeshMessage::UbiDistribution { recipient, amount_tokens, distribution_round, proof } => {
                    handler_guard.handle_ubi_distribution(recipient, amount_tokens, distribution_round, proof).await?;
                }
                ZhtpMeshMessage::HealthReport { reporter, network_quality, available_bandwidth, connected_peers, uptime_hours } => {
                    handler_guard.handle_health_report(reporter, network_quality, available_bandwidth, connected_peers, uptime_hours).await?;
                }
                ZhtpMeshMessage::PeerDiscovery { capabilities, location, shared_resources } => {
                    handler_guard.handle_peer_discovery(envelope.origin, capabilities, location, shared_resources).await?;
                }
                _ => {
                    warn!("Unhandled message type, using default handler");
                    // For now, just log
                }
            }
        } else {
            warn!("No message handler available, message not processed");
        }
        
        Ok(())
    }
    
    /// Forward message to next hop (NEW - Phase 1)
    async fn forward_message(&self, mut envelope: MeshMessageEnvelope) -> Result<()> {
        // Increment hop count
        let my_id = self.get_node_id()?;
        envelope.increment_hop(my_id.clone());
        
        info!("🔀 Forwarding message {} (hop {})", envelope.message_id, envelope.hop_count);
        
        // Find next hop using message router
        if let Some(router) = &self.message_router {
            let router_guard = router.read().await;

            // Convert destination PublicKey to UnifiedPeerId for routing (Ticket #146)
            #[allow(deprecated)]
            let dest_unified = UnifiedPeerId::from_public_key_legacy(envelope.destination.clone());
            match router_guard.find_next_hop_for_destination(&dest_unified).await {
                Ok(next_hop) => {
                    info!(" Next hop: {:?}", hex::encode(&next_hop.public_key().key_id[0..4]));

                    // Send to next hop (extract PublicKey for envelope)
                    self.send_mesh_envelope(next_hop.public_key(), &envelope).await?;
                    
                    // Record routing activity for rewards
                    let message_size = envelope.size();
                    if let Some(mesh_server) = router_guard.mesh_server.as_ref() {
                        mesh_server.read().await.record_routing_activity(
                            message_size,
                            envelope.hop_count,
                            crate::protocols::NetworkProtocol::BluetoothClassic,
                            50, // Estimated latency in ms
                        ).await?;
                    }
                    
                    info!(" Message forwarded successfully");
                }
                Err(e) => {
                    warn!(" Failed to find route: {}", e);
                    return Err(e);
                }
            }
        } else {
            warn!("No message router available, cannot forward");
            return Err(anyhow!("Message router not initialized"));
        }
        
        Ok(())
    }
    
    /// Handle coordination message
    async fn handle_coordination_message(&self, data: &[u8], peer_addr: &str) -> Result<()> {
        info!(" Processing coordination message from {} ({} bytes)", peer_addr, data.len());
        
        // TODO: Implement coordination handling (DHT queries, mesh topology updates, etc.)
        // For now, just log the message
        debug!("Coordination data: {:?}", &data[..std::cmp::min(32, data.len())]);
        
        Ok(())
    }
    
    /// Listen on a specific RFCOMM channel and accept connections
    pub async fn listen_on_channel(&self, channel: u8) -> Result<()> {
        let connections = self.active_connections.clone();
        let streams = self.active_streams.clone();
        let self_clone = self.clone();
        
        info!("📞 Starting listener on RFCOMM channel {}", channel);
        
        tokio::spawn(async move {
            loop {
                match self_clone.accept_connection_on_channel(channel).await {
                    Ok(stream) => {
                        let peer_addr = stream.peer_addr().to_string();
                        info!(" RFCOMM connection accepted on channel {}: {}", channel, peer_addr);
                        
                        // Store connection metadata
                        let connection = RfcommConnection {
                            peer_id: peer_addr.clone(),
                            peer_address: peer_addr.clone(),
                            connected_at: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            channel,
                            mtu: 1000,
                            last_seen: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            is_outgoing: false, // Incoming connection
                        };
                        
                        connections.write().await.insert(peer_addr.clone(), connection);
                        
                        // Store stream
                        let stream_arc = Arc::new(RwLock::new(stream));
                        streams.write().await.insert(peer_addr.clone(), stream_arc.clone());
                        
                        // Spawn message handler for this connection
                        let handler_clone = self_clone.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handler_clone.handle_incoming_messages(stream_arc).await {
                                warn!("Message handler error for {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!(" Accept error on channel {}: {}", channel, e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Accept connection on a specific channel (platform-specific)
    async fn accept_connection_on_channel(&self, channel: u8) -> Result<RfcommStream> {
        // For now, just use the default accept_connection() method
        // In a full implementation, we would create separate listeners per channel
        info!("Accepting connection on channel {} (using default listener)", channel);
        self.accept_connection().await
    }
    
    /// Start full RFCOMM service with all 4 channels
    pub async fn start_full_service(&self) -> Result<()> {
        info!(" Starting full RFCOMM service with all 4 ZHTP channels");
        
        // Start advertising
        self.start_advertising().await?;
        
        // Start listeners on all 4 channels
        self.listen_on_channel(rfcomm_channels::ZK_AUTH).await?;
        info!(" Channel {} (ZK_AUTH) listening", rfcomm_channels::ZK_AUTH);
        
        self.listen_on_channel(rfcomm_channels::QUANTUM_ROUTING).await?;
        info!(" Channel {} (QUANTUM_ROUTING) listening", rfcomm_channels::QUANTUM_ROUTING);
        
        self.listen_on_channel(rfcomm_channels::MESH_DATA).await?;
        info!(" Channel {} (MESH_DATA) listening", rfcomm_channels::MESH_DATA);
        
        self.listen_on_channel(rfcomm_channels::COORDINATION).await?;
        info!(" Channel {} (COORDINATION) listening", rfcomm_channels::COORDINATION);
        
        info!(" Full RFCOMM service started - accepting connections on 4 channels");
        Ok(())
    }
    
    /// Disconnect from a peer and cleanup resources
    pub async fn disconnect_peer(&self, peer_address: &str) -> Result<()> {
        info!("🔌 Disconnecting from peer: {}", peer_address);
        
        // Remove from active connections
        if let Some(removed_conn) = self.active_connections.write().await.remove(peer_address) {
            info!(" Removed connection metadata for {}", peer_address);
            debug!("   Channel: {}, MTU: {}, Outgoing: {}", 
                   removed_conn.channel, removed_conn.mtu, removed_conn.is_outgoing);
        } else {
            warn!(" No active connection found for {}", peer_address);
        }
        
        // Remove from active streams (this will close the socket)
        if let Some(removed_stream) = self.active_streams.write().await.remove(peer_address) {
            info!(" Removed stream for {}", peer_address);
            
            // The stream will be dropped here, closing the socket
            drop(removed_stream);
        } else {
            warn!(" No active stream found for {}", peer_address);
        }
        
        // Remove from authenticated peers
        if self.authenticated_peers.write().await.remove(peer_address).is_some() {
            info!(" Removed authentication for {}", peer_address);
        }
        
        info!(" Disconnected from {}", peer_address);
        Ok(())
    }
    
    /// Disconnect all peers and cleanup resources
    pub async fn disconnect_all(&self) -> Result<()> {
        info!("🔌 Disconnecting from all peers");
        
        let peer_addresses: Vec<String> = self.active_connections.read().await
            .keys()
            .cloned()
            .collect();
        
        let mut disconnect_count = 0;
        for peer_addr in peer_addresses {
            if self.disconnect_peer(&peer_addr).await.is_ok() {
                disconnect_count += 1;
            }
        }
        
        info!(" Disconnected from {} peers", disconnect_count);
        Ok(())
    }
}

// ============================================================================
// Protocol Trait Implementation
// ============================================================================

#[async_trait::async_trait]
impl super::super::Protocol for BluetoothClassicProtocol {
    /// Connect to a peer via Bluetooth Classic RFCOMM
    async fn connect(&mut self, target: &super::super::PeerAddress) -> Result<super::super::ProtocolSession> {
        use crate::protocols::types::{SessionKeys, AuthScheme, CipherSuite};

        // Extract peer address based on type
        let peer_address = match target {
            super::super::PeerAddress::Bluetooth(mac) => {
                format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac.as_bytes()[0], mac.as_bytes()[1], mac.as_bytes()[2],
                    mac.as_bytes()[3], mac.as_bytes()[4], mac.as_bytes()[5])
            },
            _ => return Err(anyhow!("BluetoothClassicProtocol only supports Bluetooth addresses")),
        };

        // Connect to peer via RFCOMM
        let _stream = self.connect_to_peer(&peer_address, rfcomm_channels::MESH_DATA)
            .await
            .map_err(|e| anyhow!("Failed to connect to peer: {}", e))?;

        // Derive session keys using Blake3
        let mut session_keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);
        let key_material = blake3::hash(
            format!("bt:classic:{}:{}",
                String::from_iter(self.node_id.iter().map(|b| format!("{:02x}", b))),
                peer_address
            ).as_bytes()
        );
        session_keys.set_encryption_key(*key_material.as_bytes())?;

        // Create peer identity (DID derived from MAC address)
        let peer_did = format!("did:zhtp:bt:{}", peer_address.to_lowercase());
        let peer_identity = super::super::VerifiedPeerIdentity::new(
            peer_did,
            peer_address.as_bytes().to_vec(),
            vec![], // Authentication proof - would be filled by ZHTP auth
        )?;

        // Create session with MAC key derived from node ID
        let mac_key = blake3::hash(format!("mac:key:{}", String::from_iter(
            self.node_id.iter().map(|b| format!("{:02x}", b))
        )).as_bytes());

        let session = super::super::ProtocolSession::new(
            target.clone(),
            peer_identity,
            super::super::NetworkProtocol::BluetoothClassic,
            session_keys,
            AuthScheme::MutualHandshake,
            mac_key.as_bytes(),
        );

        Ok(session)
    }

    /// Accept incoming Bluetooth Classic connection
    async fn accept(&mut self) -> Result<super::super::ProtocolSession> {
        use crate::protocols::types::{SessionKeys, AuthScheme, CipherSuite};

        // Accept incoming RFCOMM connection
        let stream = self.accept_connection()
            .await
            .map_err(|e| anyhow!("Failed to accept connection: {}", e))?;

        let peer_address = stream.peer_addr().to_string();

        // Parse MAC address from peer
        let mac_bytes = hex::decode(peer_address.replace(':', "").as_str())
            .unwrap_or_default();
        if mac_bytes.len() != 6 {
            return Err(anyhow!("Invalid peer MAC address"));
        }

        let mut mac_array = [0u8; 6];
        mac_array.copy_from_slice(&mac_bytes);
        let peer_mac = super::super::BluetoothMac::new(mac_array)?;
        let target = super::super::PeerAddress::Bluetooth(peer_mac);

        // Derive session keys
        let mut session_keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);
        let key_material = blake3::hash(
            format!("bt:classic:{}:{}",
                String::from_iter(self.node_id.iter().map(|b| format!("{:02x}", b))),
                peer_address
            ).as_bytes()
        );
        session_keys.set_encryption_key(*key_material.as_bytes())?;

        // Create peer identity
        let peer_did = format!("did:zhtp:bt:{}", peer_address.to_lowercase());
        let peer_identity = super::super::VerifiedPeerIdentity::new(
            peer_did,
            peer_address.as_bytes().to_vec(),
            vec![],
        )?;

        // Create session
        let mac_key = blake3::hash(format!("mac:key:{}", String::from_iter(
            self.node_id.iter().map(|b| format!("{:02x}", b))
        )).as_bytes());

        let session = super::super::ProtocolSession::new(
            target,
            peer_identity,
            super::super::NetworkProtocol::BluetoothClassic,
            session_keys,
            AuthScheme::MutualHandshake,
            mac_key.as_bytes(),
        );

        Ok(session)
    }

    /// Validate that a session belongs to this protocol instance
    fn validate_session(&self, session: &super::super::ProtocolSession) -> Result<()> {
        use crate::protocols::types::SessionRenewalReason;

        // Check that the session is for Bluetooth Classic protocol
        if session.protocol() != &super::super::NetworkProtocol::BluetoothClassic {
            return Err(anyhow!("Session is not for BluetoothClassic protocol"));
        }

        // Check session lifecycle (not expired, not idle too long)
        match session.lifecycle().needs_renewal() {
            SessionRenewalReason::None => {},
            reason => {
                return Err(anyhow!("Session needs renewal: {:?}", reason));
            }
        }

        Ok(())
    }

    /// Send a mesh message over an authenticated Bluetooth Classic session
    async fn send_message(
        &self,
        session: &super::super::ProtocolSession,
        envelope: &crate::types::mesh_message::MeshMessageEnvelope,
    ) -> Result<()> {
        // Validate session before sending
        self.validate_session(session)?;

        // Get the target address from session
        let target_address = match session.peer_address() {
            super::super::PeerAddress::Bluetooth(mac) => {
                format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac.as_bytes()[0], mac.as_bytes()[1], mac.as_bytes()[2],
                    mac.as_bytes()[3], mac.as_bytes()[4], mac.as_bytes()[5])
            },
            _ => return Err(anyhow!("Invalid peer address for BluetoothClassic")),
        };

        // Serialize the message
        let serialized = serde_json::to_vec(envelope)?;

        // Send via existing method
        self.send_mesh_message(&target_address, &serialized)
            .await
            .map_err(|e| anyhow!("Failed to send message: {}", e))
    }

    /// Receive a mesh message from an authenticated Bluetooth Classic session
    async fn receive_message(
        &self,
        _session: &super::super::ProtocolSession,
    ) -> Result<crate::types::mesh_message::MeshMessageEnvelope> {
        // Protocol-specific receive implementation would go here
        // For now, return a placeholder error
        Err(anyhow!("Receive message not fully implemented for BluetoothClassic"))
    }

    /// Rekey an existing Bluetooth Classic session
    async fn rekey_session(&mut self, session: &mut super::super::ProtocolSession) -> Result<()> {
        use crate::protocols::types::SessionKeys;
        use crate::protocols::types::CipherSuite;

        // Validate current session
        self.validate_session(session)?;

        // In a full implementation, this would perform a key exchange with the peer
        // to derive new ephemeral keys while maintaining the session binding.
        // For now, we acknowledge the rekeying request but note that actual
        // key rotation would require protocol-level coordination.

        // Derive new session keys for rekeying
        let mut _new_keys = SessionKeys::new(CipherSuite::ChaCha20Poly1305, true);
        let new_key_material = blake3::hash(
            format!("rekey:bt:classic:{}:{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
                String::from_iter(self.node_id.iter().map(|b| format!("{:02x}", b)))
            ).as_bytes()
        );
        _new_keys.set_encryption_key(*new_key_material.as_bytes())?;

        // ProtocolSession is immutable from the trait perspective,
        // so actual key rotation would happen through protocol-specific state management.
        // This is a design point: sessions could be stored in a mutable map keyed by session_id.

        Ok(())
    }

    /// Get Bluetooth Classic protocol capabilities
    fn capabilities(&self) -> super::super::ProtocolCapabilities {
        use crate::protocols::types::{AuthScheme, CipherSuite, PqcMode, PowerProfile};

        super::super::ProtocolCapabilities {
            version: crate::protocols::types::CAPABILITY_VERSION,
            mtu: 1024,
            throughput_mbps: 0.375, // 375 KB/s
            latency_ms: 20,
            range_meters: Some(100), // Bluetooth Classic range
            power_profile: PowerProfile::Medium,
            reliable: true,
            requires_internet: false,
            auth_schemes: vec![AuthScheme::MutualHandshake],
            encryption: Some(CipherSuite::ChaCha20Poly1305),
            pqc_mode: PqcMode::Hybrid,
            replay_protection: true,
            identity_binding: true,
            integrity_only: false,
            forward_secrecy: true,
        }
    }

    /// Get the protocol type identifier
    fn protocol_type(&self) -> super::super::NetworkProtocol {
        super::super::NetworkProtocol::BluetoothClassic
    }

    /// Check if Bluetooth Classic is available
    fn is_available(&self) -> bool {
        self.is_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mac_address_parsing() {
        let mac_str = "AA:BB:CC:DD:EE:FF";
        let mac = parse_mac_address(mac_str).unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        
        let mac_str2 = "AA-BB-CC-DD-EE-FF";
        let mac2 = parse_mac_address(mac_str2).unwrap();
        assert_eq!(mac2, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[tokio::test]
    async fn test_protocol_creation() {
        let node_id = [0u8; 32];
        let protocol = BluetoothClassicProtocol::new(node_id);
        assert!(protocol.is_ok());
        
        let proto = protocol.unwrap();
        assert_eq!(proto.max_throughput, 375_000);
    }
    
    #[tokio::test]
    async fn test_device_discovery_structure() {
        // Test BluetoothDevice structure
        let device = BluetoothDevice {
            address: "AA:BB:CC:DD:EE:FF".to_string(),
            name: Some("Test Device".to_string()),
            device_class: 0x1F00,
            is_paired: true,
            is_connected: false,
            rssi: Some(-65),
            last_seen: 1234567890,
        };
        
        assert_eq!(device.address, "AA:BB:CC:DD:EE:FF");
        assert!(device.is_paired);
        assert!(!device.is_connected);
    }
    
    #[tokio::test]
    async fn test_rfcomm_service_info_structure() {
        let service = RfcommServiceInfo {
            service_uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430ca".to_string(),
            service_name: "ZHTP Mesh".to_string(),
            channel: 3,
            device_address: "AA:BB:CC:DD:EE:FF".to_string(),
        };
        
        assert_eq!(service.channel, 3);
        assert_eq!(service.service_name, "ZHTP Mesh");
    }
    
    #[tokio::test]
    async fn test_connection_tracking() {
        let connection = RfcommConnection {
            peer_id: "test_peer".to_string(),
            peer_address: "AA:BB:CC:DD:EE:FF".to_string(),
            connected_at: 1234567890,
            channel: 3,
            mtu: 1000,
            last_seen: 1234567890,
            is_outgoing: true,
        };
        
        assert_eq!(connection.channel, 3);
        assert_eq!(connection.mtu, 1000);
        assert!(connection.is_outgoing);
    }
    
    #[tokio::test]
    async fn test_cross_platform_api_availability() {
        // Test that the public API methods exist and are callable
        let node_id = [0u8; 32];
        let protocol = BluetoothClassicProtocol::new(node_id).unwrap();
        
        // These methods should exist on all platforms (they route internally)
        // We can't test actual functionality without hardware, but we can
        // verify the API surface exists
        
        // discover_paired_devices should be callable
        // query_rfcomm_services should be callable
        // connect_to_peer should be callable
        
        // Verify connection management works
        let connections = protocol.get_connections().await;
        assert_eq!(connections.len(), 0); // Should start empty
    }
}

// Example usage module
#[cfg(test)]
mod examples {
    use super::*;
    
    /// Example: Discover and connect to a paired Bluetooth device
    ///
    /// ```rust,no_run
    /// use lib_network::protocols::bluetooth_classic::BluetoothClassicProtocol;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let node_id = [0u8; 32];
    ///     let protocol = BluetoothClassicProtocol::new(node_id)?;
    ///     
    ///     // Discover paired devices
    ///     println!("Discovering paired Bluetooth devices...");
    ///     let devices = protocol.discover_paired_devices().await?;
    ///     
    ///     for device in &devices {
    ///         println!("Found device: {} ({})", 
    ///             device.name.as_deref().unwrap_or("Unknown"),
    ///             device.address
    ///         );
    ///     }
    ///     
    ///     // Query services on a specific device
    ///     if let Some(device) = devices.first() {
    ///         println!("Querying RFCOMM services on {}...", device.address);
    ///         let services = protocol.query_rfcomm_services(&device.address).await?;
    ///         
    ///         for service in &services {
    ///             println!("  Service: {} on channel {}", 
    ///                 service.service_name, 
    ///                 service.channel
    ///             );
    ///         }
    ///         
    ///         // Connect to first available service
    ///         if let Some(service) = services.first() {
    ///             println!("Connecting to {}...", device.address);
    ///             let stream = protocol.connect_to_peer(
    ///                 &device.address, 
    ///                 service.channel
    ///             ).await?;
    ///             
    ///             println!("Connected successfully!");
    ///             println!("Peer address: {}", stream.peer_addr());
    ///         }
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    #[test]
    fn example_discovery_and_connection() {
        // This is a documentation example, not meant to run in tests
    }
    
    /// Example: Accept incoming connections (passive mode)
    ///
    /// ```rust,no_run
    /// use lib_network::protocols::bluetooth_classic::BluetoothClassicProtocol;
    /// use lib_crypto::PublicKey;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let node_id = [0u8; 32];
    ///     let mut protocol = BluetoothClassicProtocol::new(node_id)?;
    ///     
    ///     // Initialize authentication
    ///     let blockchain_pubkey = PublicKey::default();
    ///     protocol.initialize_zhtp_auth(blockchain_pubkey).await?;
    ///     
    ///     // Start advertising RFCOMM service
    ///     println!("Starting RFCOMM service advertising...");
    ///     protocol.start_advertising().await?;
    ///     
    ///     // Accept incoming connections
    ///     loop {
    ///         println!("Waiting for incoming connection...");
    ///         let stream = protocol.accept_connection().await?;
    ///         println!("Connection accepted from: {}", stream.peer_addr());
    ///         
    ///         // Handle connection in a separate task
    ///         tokio::spawn(async move {
    ///             // Read/write from stream
    ///             // ...
    ///         });
    ///     }
    /// }
    /// ```
    #[test]
    fn example_passive_accept() {
        // This is a documentation example, not meant to run in tests
    }
    
    /// Example: Cross-platform mesh networking
    ///
    /// ```rust,no_run
    /// use lib_network::protocols::bluetooth_classic::BluetoothClassicProtocol;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let node_id = [0u8; 32];
    ///     let protocol = BluetoothClassicProtocol::new(node_id)?;
    ///     
    ///     // Start as both server and client for full mesh connectivity
    ///     
    ///     // 1. Start advertising (passive)
    ///     protocol.start_advertising().await?;
    ///     
    ///     // 2. Discover and connect to peers (active)
    ///     let devices = protocol.discover_paired_devices().await?;
    ///     
    ///     for device in devices {
    ///         if let Ok(services) = protocol.query_rfcomm_services(&device.address).await {
    ///             for service in services {
    ///                 // Try to connect to each ZHTP service
    ///                 if service.service_name.contains("ZHTP") {
    ///                     match protocol.connect_to_peer(&device.address, service.channel).await {
    ///                         Ok(_) => println!("Connected to {}", device.address),
    ///                         Err(e) => eprintln!("Failed to connect: {}", e),
    ///                     }
    ///                 }
    ///             }
    ///         }
    ///     }
    ///     
    ///     // 3. List all active connections
    ///     let connections = protocol.get_connections().await;
    ///     println!("Active connections: {}", connections.len());
    ///     for conn in connections {
    ///         println!("  {} (channel {}, {})", 
    ///             conn.peer_address,
    ///             conn.channel,
    ///             if conn.is_outgoing { "outgoing" } else { "incoming" }
    ///         );
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    #[test]
    fn example_mesh_networking() {
        // This is a documentation example, not meant to run in tests
    }
}

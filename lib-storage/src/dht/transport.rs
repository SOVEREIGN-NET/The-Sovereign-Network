use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::io;

/// Supported transport protocols for the DHT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Udp,
    Ble,
    Quic,
    WifiDirect,
}

/// Minimal transport abstraction for sending/receiving raw DHT frames.
pub trait DhtTransport: Send + Sync {
    fn protocol(&self) -> TransportProtocol;
    fn send(&self, target: SocketAddr, bytes: &[u8]) -> Result<()>;
    fn recv(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// UDP transport implementation (default).
pub struct UdpDhtTransport {
    socket: UdpSocket,
}

impl UdpDhtTransport {
    pub fn bind(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }
}

impl DhtTransport for UdpDhtTransport {
    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::Udp
    }

    fn send(&self, target: SocketAddr, bytes: &[u8]) -> Result<()> {
        self.socket.send_to(bytes, target)?;
        Ok(())
    }

    fn recv(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }
}

/// Placeholder BLE transport (to be wired to platform BLE sockets).
pub struct BleDhtTransport;

impl DhtTransport for BleDhtTransport {
    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::Ble
    }

    fn send(&self, _target: SocketAddr, _bytes: &[u8]) -> Result<()> {
        Err(anyhow!("BLE DHT transport not implemented"))
    }

    fn recv(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BLE DHT transport not implemented",
        ))
    }
}

/// Placeholder QUIC transport (to be wired to quinn).
pub struct QuicDhtTransport;

impl DhtTransport for QuicDhtTransport {
    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::Quic
    }

    fn send(&self, _target: SocketAddr, _bytes: &[u8]) -> Result<()> {
        Err(anyhow!("QUIC DHT transport not implemented"))
    }

    fn recv(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QUIC DHT transport not implemented",
        ))
    }
}

/// Placeholder WiFi Direct transport.
pub struct WifiDirectDhtTransport;

impl DhtTransport for WifiDirectDhtTransport {
    fn protocol(&self) -> TransportProtocol {
        TransportProtocol::WifiDirect
    }

    fn send(&self, _target: SocketAddr, _bytes: &[u8]) -> Result<()> {
        Err(anyhow!("WiFi Direct DHT transport not implemented"))
    }

    fn recv(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WiFi Direct DHT transport not implemented",
        ))
    }
}

/// Multi-transport selector with a primary route.
pub struct MultiDhtTransport {
    primary: TransportProtocol,
    transports: HashMap<TransportProtocol, Box<dyn DhtTransport>>,
}

impl MultiDhtTransport {
    pub fn with_primary(transport: Box<dyn DhtTransport>) -> Self {
        let primary = transport.protocol();
        let mut transports = HashMap::new();
        transports.insert(primary, transport);
        Self { primary, transports }
    }

    pub fn set_primary(&mut self, protocol: TransportProtocol) {
        self.primary = protocol;
    }

    pub fn add_transport(&mut self, transport: Box<dyn DhtTransport>) {
        self.transports.insert(transport.protocol(), transport);
    }

    pub fn send(&self, target: SocketAddr, bytes: &[u8]) -> Result<()> {
        if let Some(primary) = self.transports.get(&self.primary) {
            return primary.send(target, bytes);
        }
        Err(anyhow::anyhow!("No primary DHT transport configured"))
    }

    pub fn recv(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        if let Some(primary) = self.transports.get(&self.primary) {
            return primary.recv(buffer);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No primary DHT transport configured",
        ))
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.transports
            .get(&self.primary)
            .and_then(|t| t.local_addr())
    }
}

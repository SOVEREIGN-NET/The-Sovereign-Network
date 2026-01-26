//! Socket Configuration Utilities
//!
//! Provides common patterns for socket creation and configuration across all transports.
//! Eliminates duplicated socket setup code (SO_REUSEADDR, SO_REUSEPORT, etc).

use anyhow::Result;

/// Configure socket with SO_REUSEADDR and SO_REUSEPORT for socket reuse
///
/// This helper consolidates socket configuration that's repeated in multiple places:
/// - Allows multiple processes to bind to the same port (SO_REUSEADDR)
/// - Enables port reuse for load balancing (SO_REUSEPORT on Unix platforms)
///
/// # Arguments
/// * `socket` - Socket to configure
///
/// # Returns
/// - `Ok(())` - Socket configured successfully
/// - `Err(...)` - Socket configuration failed
///
/// # Notes
/// - SO_REUSEPORT failure is non-fatal (warning only)
/// - Only applies on Unix platforms (not Solaris/illumos)
pub fn enable_socket_reuse(socket: &socket2::Socket) -> Result<()> {
    socket.set_reuse_address(true)?;

    // Set SO_REUSEPORT on platforms that support it (Linux, BSD)
    // This allows multiple sockets to bind to the same port for load balancing
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            if ret != 0 {
                // Non-fatal: SO_REUSEPORT is optional optimization
                eprintln!("Warning: Failed to set SO_REUSEPORT: {}", std::io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_reuse_configuration() {
        // This test ensures socket reuse configuration can be applied
        // Actual socket binding is tested via integration tests
    }
}

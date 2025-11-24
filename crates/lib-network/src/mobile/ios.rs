//! iOS C FFI bindings for ZHTP
//!
//! This module provides C-compatible FFI for iOS apps using Swift.
//! It enables MultipeerConnectivity and CoreBluetooth integration.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use super::{NodeConfig, FFIResult, create_node, start_node, stop_node, get_node_status, discover_peers, connect_to_peer, send_message, get_connected_peers, c_str_to_string};

/// Initialize ZHTP node with configuration
///
/// Returns: JSON string with node_id on success, error message on failure
/// Swift usage: let result = zhtp_init_node("router", true, true, true, 9333)
#[no_mangle]
pub extern "C" fn zhtp_init_node(
    device_type: *const c_char,
    enable_multipeer: bool,
    enable_bluetooth: bool,
    enable_mdns: bool,
    port: u16,
) -> *mut c_char {
    let device_type_str = match unsafe { c_str_to_string(device_type) } {
        Ok(s) => s,
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            return CString::new(error).unwrap().into_raw();
        }
    };
    
    let config = NodeConfig {
        enable_wifi_direct: enable_multipeer, // MultipeerConnectivity on iOS
        enable_bluetooth: enable_bluetooth,
        enable_udp_multicast: true, // Always enabled for iOS
        enable_mdns: enable_mdns,
        port,
        device_type: device_type_str,
    };
    
    match create_node(config) {
        Ok(node_id) => {
            let response = format!("{{\"success\":true,\"node_id\":\"{}\"}}", node_id);
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Start the ZHTP node
///
/// Returns: JSON string with success status
/// Swift usage: let result = zhtp_start_node()
#[no_mangle]
pub extern "C" fn zhtp_start_node() -> *mut c_char {
    match start_node() {
        Ok(msg) => {
            let response = format!("{{\"success\":true,\"message\":\"{}\"}}", msg);
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Stop the ZHTP node
///
/// Returns: JSON string with success status
/// Swift usage: let result = zhtp_stop_node()
#[no_mangle]
pub extern "C" fn zhtp_stop_node() -> *mut c_char {
    match stop_node() {
        Ok(msg) => {
            let response = format!("{{\"success\":true,\"message\":\"{}\"}}", msg);
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Get node status as JSON
///
/// Returns: JSON string with node status
/// Swift usage: let status = zhtp_get_status()
#[no_mangle]
pub extern "C" fn zhtp_get_status() -> *mut c_char {
    match get_node_status() {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Discover peers on the network
///
/// Returns: JSON array of discovered peers
/// Swift usage: let peers = zhtp_discover_peers(5)
#[no_mangle]
pub extern "C" fn zhtp_discover_peers(timeout_secs: u64) -> *mut c_char {
    match discover_peers(timeout_secs) {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Connect to a specific peer
///
/// Returns: JSON string with success status
/// Swift usage: let result = zhtp_connect_to_peer("192.168.1.100:9333", "peer-uuid")
#[no_mangle]
pub extern "C" fn zhtp_connect_to_peer(
    peer_address: *const c_char,
    peer_id: *const c_char,
) -> *mut c_char {
    let peer_address_str = match unsafe { c_str_to_string(peer_address) } {
        Ok(s) => s,
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            return CString::new(error).unwrap().into_raw();
        }
    };
    
    let peer_id_str = match unsafe { c_str_to_string(peer_id) } {
        Ok(s) => s,
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            return CString::new(error).unwrap().into_raw();
        }
    };
    
    match connect_to_peer(&peer_address_str, &peer_id_str) {
        Ok(msg) => {
            let response = format!("{{\"success\":true,\"message\":\"{}\"}}", msg);
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Send a message to a peer
///
/// Returns: JSON string with success status
/// Swift usage: let result = zhtp_send_message("peer-uuid", "Hello, world!")
#[no_mangle]
pub extern "C" fn zhtp_send_message(
    peer_id: *const c_char,
    message: *const c_char,
) -> *mut c_char {
    let peer_id_str = match unsafe { c_str_to_string(peer_id) } {
        Ok(s) => s,
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            return CString::new(error).unwrap().into_raw();
        }
    };
    
    let message_str = match unsafe { c_str_to_string(message) } {
        Ok(s) => s,
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            return CString::new(error).unwrap().into_raw();
        }
    };
    
    match send_message(&peer_id_str, &message_str) {
        Ok(msg) => {
            let response = format!("{{\"success\":true,\"message\":\"{}\"}}", msg);
            CString::new(response).unwrap().into_raw()
        }
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Get list of connected peers as JSON
///
/// Returns: JSON array of connected peers
/// Swift usage: let peers = zhtp_get_connected_peers()
#[no_mangle]
pub extern "C" fn zhtp_get_connected_peers() -> *mut c_char {
    match get_connected_peers() {
        Ok(json) => CString::new(json).unwrap().into_raw(),
        Err(e) => {
            let error = format!("{{\"success\":false,\"error\":\"{}\"}}", e);
            CString::new(error).unwrap().into_raw()
        }
    }
}

/// Callback from iOS when MultipeerConnectivity peer is discovered
///
/// Swift usage: zhtp_on_multipeer_peer_discovered(peerIdCStr, displayNameCStr)
#[no_mangle]
pub extern "C" fn zhtp_on_multipeer_peer_discovered(
    peer_id: *const c_char,
    display_name: *const c_char,
) {
    let peer_id_str = match unsafe { c_str_to_string(peer_id) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let display_name_str = match unsafe { c_str_to_string(display_name) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    // TODO: Add discovered MultipeerConnectivity peer to internal peer list
    log::info!("MultipeerConnectivity peer discovered: {} ({})", display_name_str, peer_id_str);
}

/// Callback from iOS when CoreBluetooth peripheral is discovered
///
/// Swift usage: zhtp_on_bluetooth_peripheral_discovered(uuidCStr, nameCStr, -65)
#[no_mangle]
pub extern "C" fn zhtp_on_bluetooth_peripheral_discovered(
    peripheral_uuid: *const c_char,
    peripheral_name: *const c_char,
    rssi: i32,
) {
    let uuid_str = match unsafe { c_str_to_string(peripheral_uuid) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let name_str = match unsafe { c_str_to_string(peripheral_name) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    // TODO: Add discovered Bluetooth peripheral to internal peer list
    log::info!("Bluetooth peripheral discovered: {} ({}) RSSI: {}", name_str, uuid_str, rssi);
}

/// Callback from iOS when MultipeerConnectivity session state changes
///
/// Swift usage: zhtp_on_multipeer_state_changed(true, peerIdCStr)
#[no_mangle]
pub extern "C" fn zhtp_on_multipeer_state_changed(
    is_connected: bool,
    peer_id: *const c_char,
) {
    let peer_id_str = match unsafe { c_str_to_string(peer_id) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    if is_connected {
        log::info!("MultipeerConnectivity connected to peer: {}", peer_id_str);
        // TODO: Initiate ZHTP handshake with peer
    } else {
        log::info!("MultipeerConnectivity disconnected from peer: {}", peer_id_str);
        // TODO: Remove peer from peer list
    }
}

/// Callback from iOS when CoreBluetooth connection state changes
///
/// Swift usage: zhtp_on_bluetooth_state_changed(true, peripheralUuidCStr)
#[no_mangle]
pub extern "C" fn zhtp_on_bluetooth_state_changed(
    is_connected: bool,
    peripheral_uuid: *const c_char,
) {
    let uuid_str = match unsafe { c_str_to_string(peripheral_uuid) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    if is_connected {
        log::info!("Bluetooth connected to peripheral: {}", uuid_str);
        // TODO: Initiate ZHTP handshake over Bluetooth
    } else {
        log::info!("Bluetooth disconnected from peripheral: {}", uuid_str);
        // TODO: Remove Bluetooth peripheral from peer list
    }
}

/// Callback from iOS when MultipeerConnectivity receives data
///
/// Swift usage: zhtp_on_multipeer_data_received(dataCStr, dataLen, peerIdCStr)
#[no_mangle]
pub extern "C" fn zhtp_on_multipeer_data_received(
    data: *const u8,
    data_len: usize,
    peer_id: *const c_char,
) {
    if data.is_null() {
        return;
    }
    
    let peer_id_str = match unsafe { c_str_to_string(peer_id) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    
    // TODO: Process received ZHTP message
    log::info!("Received {} bytes from MultipeerConnectivity peer: {}", data_len, peer_id_str);
}

/// Callback from iOS when CoreBluetooth receives data
///
/// Swift usage: zhtp_on_bluetooth_data_received(dataCStr, dataLen, peripheralUuidCStr)
#[no_mangle]
pub extern "C" fn zhtp_on_bluetooth_data_received(
    data: *const u8,
    data_len: usize,
    peripheral_uuid: *const c_char,
) {
    if data.is_null() {
        return;
    }
    
    let uuid_str = match unsafe { c_str_to_string(peripheral_uuid) } {
        Ok(s) => s,
        Err(_) => return,
    };
    
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    
    // TODO: Process received ZHTP message over Bluetooth
    log::info!("Received {} bytes from Bluetooth peripheral: {}", data_len, uuid_str);
}

//! Android JNI bindings for ZHTP
//!
//! This module provides JNI (Java Native Interface) bindings for Android apps.
//! It enables WiFi Direct and Bluetooth integration with Android's native APIs.

use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject};
use jni::sys::{jstring, jboolean, jlong, jint};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use super::{NodeConfig, create_node, start_node, stop_node, get_node_status, discover_peers, connect_to_peer, send_message, get_connected_peers};

/// Initialize ZHTP node with configuration
/// 
/// Java signature: public static native long initNode(String deviceType, boolean enableWifiDirect, boolean enableBluetooth, boolean enableMdns, int port);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_initNode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    device_type: JString<'local>,
    enable_wifi_direct: jboolean,
    enable_bluetooth: jboolean,
    enable_mdns: jboolean,
    port: jint,
) -> jstring {
    let device_type_str: String = match env.get_string(&device_type) {
        Ok(s) => s.into(),
        Err(e) => {
            let error = format!("Failed to get device type: {}", e);
            return env.new_string(error).unwrap().into_raw();
        }
    };
    
    let config = NodeConfig {
        enable_wifi_direct: enable_wifi_direct != 0,
        enable_bluetooth: enable_bluetooth != 0,
        enable_udp_multicast: true, // Always enabled for Android
        enable_mdns: enable_mdns != 0,
        port: port as u16,
        device_type: device_type_str,
    };
    
    match create_node(config) {
        Ok(node_id) => {
            env.new_string(format!("{{\"success\":true,\"node_id\":\"{}\"}}", node_id))
                .unwrap()
                .into_raw()
        }
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Start the ZHTP node
///
/// Java signature: public static native String startNode();
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_startNode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match start_node() {
        Ok(msg) => {
            env.new_string(format!("{{\"success\":true,\"message\":\"{}\"}}", msg))
                .unwrap()
                .into_raw()
        }
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Stop the ZHTP node
///
/// Java signature: public static native String stopNode();
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_stopNode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match stop_node() {
        Ok(msg) => {
            env.new_string(format!("{{\"success\":true,\"message\":\"{}\"}}", msg))
                .unwrap()
                .into_raw()
        }
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Get node status as JSON
///
/// Java signature: public static native String getNodeStatus();
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_getNodeStatus<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match get_node_status() {
        Ok(json) => env.new_string(json).unwrap().into_raw(),
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Discover peers on the network
///
/// Java signature: public static native String discoverPeers(int timeoutSecs);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_discoverPeers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    timeout_secs: jint,
) -> jstring {
    match discover_peers(timeout_secs as u64) {
        Ok(json) => env.new_string(json).unwrap().into_raw(),
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Connect to a specific peer
///
/// Java signature: public static native String connectToPeer(String peerAddress, String peerId);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_connectToPeer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    peer_address: JString<'local>,
    peer_id: JString<'local>,
) -> jstring {
    let peer_address_str: String = match env.get_string(&peer_address) {
        Ok(s) => s.into(),
        Err(e) => {
            let error = format!("Failed to get peer address: {}", e);
            return env.new_string(error).unwrap().into_raw();
        }
    };
    
    let peer_id_str: String = match env.get_string(&peer_id) {
        Ok(s) => s.into(),
        Err(e) => {
            let error = format!("Failed to get peer ID: {}", e);
            return env.new_string(error).unwrap().into_raw();
        }
    };
    
    match connect_to_peer(&peer_address_str, &peer_id_str) {
        Ok(msg) => {
            env.new_string(format!("{{\"success\":true,\"message\":\"{}\"}}", msg))
                .unwrap()
                .into_raw()
        }
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Send a message to a peer
///
/// Java signature: public static native String sendMessage(String peerId, String message);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_sendMessage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    peer_id: JString<'local>,
    message: JString<'local>,
) -> jstring {
    let peer_id_str: String = match env.get_string(&peer_id) {
        Ok(s) => s.into(),
        Err(e) => {
            let error = format!("Failed to get peer ID: {}", e);
            return env.new_string(error).unwrap().into_raw();
        }
    };
    
    let message_str: String = match env.get_string(&message) {
        Ok(s) => s.into(),
        Err(e) => {
            let error = format!("Failed to get message: {}", e);
            return env.new_string(error).unwrap().into_raw();
        }
    };
    
    match send_message(&peer_id_str, &message_str) {
        Ok(msg) => {
            env.new_string(format!("{{\"success\":true,\"message\":\"{}\"}}", msg))
                .unwrap()
                .into_raw()
        }
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Get list of connected peers as JSON
///
/// Java signature: public static native String getConnectedPeers();
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_getConnectedPeers<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match get_connected_peers() {
        Ok(json) => env.new_string(json).unwrap().into_raw(),
        Err(e) => {
            env.new_string(format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                .unwrap()
                .into_raw()
        }
    }
}

/// Callback from Android when WiFi Direct peer is discovered
///
/// Java signature: public static native void onWifiDirectPeerDiscovered(String deviceAddress, String deviceName);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_onWifiDirectPeerDiscovered<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    device_address: JString<'local>,
    device_name: JString<'local>,
) {
    let device_address_str: String = match env.get_string(&device_address) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    let device_name_str: String = match env.get_string(&device_name) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    // TODO: Add discovered WiFi Direct peer to internal peer list
    log::info!("WiFi Direct peer discovered: {} ({})", device_name_str, device_address_str);
}

/// Callback from Android when Bluetooth device is discovered
///
/// Java signature: public static native void onBluetoothDeviceDiscovered(String deviceAddress, String deviceName, int rssi);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_onBluetoothDeviceDiscovered<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    device_address: JString<'local>,
    device_name: JString<'local>,
    rssi: jint,
) {
    let device_address_str: String = match env.get_string(&device_address) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    let device_name_str: String = match env.get_string(&device_name) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    // TODO: Add discovered Bluetooth device to internal peer list
    log::info!("Bluetooth device discovered: {} ({}) RSSI: {}", device_name_str, device_address_str, rssi);
}

/// Callback from Android when WiFi Direct connection state changes
///
/// Java signature: public static native void onWifiDirectConnectionChanged(boolean isConnected, String groupOwnerAddress);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_onWifiDirectConnectionChanged<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    is_connected: jboolean,
    group_owner_address: JString<'local>,
) {
    let connected = is_connected != 0;
    
    let go_address_str: String = match env.get_string(&group_owner_address) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    if connected {
        log::info!("WiFi Direct connected to group owner: {}", go_address_str);
        // TODO: Initiate ZHTP handshake with group owner
    } else {
        log::info!("WiFi Direct disconnected");
        // TODO: Remove WiFi Direct peers from peer list
    }
}

/// Callback from Android when Bluetooth connection state changes
///
/// Java signature: public static native void onBluetoothConnectionChanged(boolean isConnected, String deviceAddress);
#[no_mangle]
pub extern "system" fn Java_net_sovereign_zhtp_ZhtpNative_onBluetoothConnectionChanged<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    is_connected: jboolean,
    device_address: JString<'local>,
) {
    let connected = is_connected != 0;
    
    let device_address_str: String = match env.get_string(&device_address) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    
    if connected {
        log::info!("Bluetooth connected to device: {}", device_address_str);
        // TODO: Initiate ZHTP handshake over Bluetooth
    } else {
        log::info!("Bluetooth disconnected from device: {}", device_address_str);
        // TODO: Remove Bluetooth peer from peer list
    }
}

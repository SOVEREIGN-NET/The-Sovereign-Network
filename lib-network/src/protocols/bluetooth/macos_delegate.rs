// Objective-C delegate implementation for Core Bluetooth on macOS
// Creates custom NSObject subclasses that conform to Core Bluetooth protocols

#[cfg(target_os = "macos")]
use objc2::declare::ClassBuilder;
#[cfg(target_os = "macos")]
use objc2::runtime::{AnyClass, AnyObject, Sel, AnyProtocol};
#[cfg(target_os = "macos")]
use objc2::{msg_send, sel};
#[cfg(target_os = "macos")]
use std::sync::Once;
#[cfg(target_os = "macos")]
use tracing::{info, warn, error, debug};

#[cfg(target_os = "macos")]
use super::macos_core::{CoreBluetoothEvent, BluetoothState};

#[cfg(target_os = "macos")]
use super::macos_error::parse_nserror;

/// One-time registration of custom delegate classes
#[cfg(target_os = "macos")]
static REGISTER_DELEGATES: Once = Once::new();

/// Register all custom Core Bluetooth delegate classes
#[cfg(target_os = "macos")]
pub unsafe fn register_delegate_classes() {
    REGISTER_DELEGATES.call_once(|| {
        register_central_manager_delegate();
        register_peripheral_manager_delegate();
        register_peripheral_delegate();
        info!(" Core Bluetooth delegate classes registered");
    });
}

/// Register ZhtpCBCentralManagerDelegate class
#[cfg(target_os = "macos")]
unsafe fn register_central_manager_delegate() {
    let superclass = AnyClass::get(c"NSObject").expect("NSObject class not found");
    let mut decl = ClassBuilder::new(c"ZhtpCBCentralManagerDelegate", superclass)
        .expect("Failed to declare ZhtpCBCentralManagerDelegate class");
    
    // Add ivar to store the event sender pointer (as raw pointer)
    decl.add_ivar::<usize>(c"event_sender_ptr");
    
    // Add protocol conformance to CBCentralManagerDelegate
    // Note: Protocol may not be available at runtime without importing CoreBluetooth framework
    if let Some(protocol) = AnyProtocol::get(c"CBCentralManagerDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBCentralManagerDelegate protocol");
    } else {
        warn!("CBCentralManagerDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)centralManagerDidUpdateState:(CBCentralManager *)central
    unsafe extern "C" fn central_manager_did_update_state(this: *mut AnyObject, _cmd: Sel, central: *mut AnyObject) {
        let this = &*this;
        // Get state from CBCentralManager
        let state: i64 = msg_send![central, state];
        
        // Map to BluetoothState enum
        let bt_state = match state {
            0 => BluetoothState::Unknown,
            1 => BluetoothState::Resetting,
            2 => BluetoothState::Unsupported,
            3 => BluetoothState::Unauthorized,
            4 => BluetoothState::PoweredOff,
            5 => BluetoothState::PoweredOn,
            _ => BluetoothState::Unknown,
        };
        
        debug!(" Delegate: centralManagerDidUpdateState: {:?}", bt_state);
        
        // Get event sender from ivar and send event
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::StateChanged(bt_state));
        }
    }
    
    decl.add_method(
        sel!(centralManagerDidUpdateState:),
        central_manager_did_update_state as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject)
    );
    
    // Implement: - (void)centralManager:didDiscoverPeripheral:advertisementData:RSSI:
    unsafe extern "C" fn central_manager_did_discover_peripheral(
        this: *mut AnyObject,
        _cmd: Sel,
        central: *mut AnyObject,
        peripheral: *mut AnyObject,
        advertisement_data: *mut AnyObject,
        rssi: *mut AnyObject,
    ) {
        let this = &*this;
        // Get peripheral identifier (UUID)
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        // Get peripheral name (may be nil)
        let name_obj: *mut AnyObject = msg_send![peripheral, name];
        let name = if !name_obj.is_null() {
            let name_cstr: *const i8 = msg_send![name_obj, UTF8String];
            Some(std::ffi::CStr::from_ptr(name_cstr).to_string_lossy().to_string())
        } else {
            None
        };
        
        // Get RSSI value
        let rssi_value: i32 = msg_send![rssi, intValue];
        
        // Parse advertisement data (NSDictionary)
        let mut ad_data = std::collections::HashMap::new();
        if !advertisement_data.is_null() {
            let keys: *mut AnyObject = msg_send![advertisement_data, allKeys];
            let count: usize = msg_send![keys, count];
            
            for i in 0..count {
                let key: *mut AnyObject = msg_send![keys, objectAtIndex: i];
                let value: *mut AnyObject = msg_send![advertisement_data, objectForKey: key];
                
                if !key.is_null() {
                    let key_cstr: *const i8 = msg_send![key, UTF8String];
                    let key_str = std::ffi::CStr::from_ptr(key_cstr).to_string_lossy().to_string();
                    
                    // Convert value to string (simplified)
                    if !value.is_null() {
                        let value_desc: *mut AnyObject = msg_send![value, description];
                        let value_cstr: *const i8 = msg_send![value_desc, UTF8String];
                        let value_str = std::ffi::CStr::from_ptr(value_cstr).to_string_lossy().to_string();
                        ad_data.insert(key_str, value_str);
                    }
                }
            }
        }
        
        info!(" Delegate: Discovered {} ({}), RSSI: {}", 
               name.as_deref().unwrap_or("Unknown"), identifier, rssi_value);
        
        // Send event
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::PeripheralDiscovered {
                identifier,
                name,
                rssi: rssi_value,
                advertisement_data: ad_data,
                peripheral_ptr: peripheral as usize,
            });
        }
    }
    
    decl.add_method(
        sel!(centralManager:didDiscoverPeripheral:advertisementData:RSSI:),
        central_manager_did_discover_peripheral as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)centralManager:didConnectPeripheral:
    unsafe extern "C" fn central_manager_did_connect_peripheral(
        this: *mut AnyObject,
        _cmd: Sel,
        central: *mut AnyObject,
        peripheral: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        debug!(" Delegate: Connected to {}", identifier);
        
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::PeripheralConnected(identifier));
        }
    }
    
    decl.add_method(
        sel!(centralManager:didConnectPeripheral:),
        central_manager_did_connect_peripheral as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)centralManager:didDisconnectPeripheral:error:
    unsafe extern "C" fn central_manager_did_disconnect_peripheral(
        this: *mut AnyObject,
        _cmd: Sel,
        central: *mut AnyObject,
        peripheral: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            // Log with appropriate level based on error type
            if error_info.cb_error.is_some() {
                warn!(" Delegate: Disconnected from {} - {}", identifier, error_info.to_error_message());
            } else {
                warn!(" Delegate: Disconnected from {} - {}", identifier, error_info.localized_description);
            }
        } else {
            debug!(" Delegate: Clean disconnect from {}", identifier);
        }
        
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::PeripheralDisconnected(identifier));
        }
    }
    
    decl.add_method(
        sel!(centralManager:didDisconnectPeripheral:error:),
        central_manager_did_disconnect_peripheral as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)centralManager:didFailToConnectPeripheral:error:
    unsafe extern "C" fn central_manager_did_fail_to_connect(
        this: *mut AnyObject,
        _cmd: Sel,
        central: *mut AnyObject,
        peripheral: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Failed to connect to {} - {}", identifier, error_info.to_error_message());
            
            // Send ConnectionFailed event with detailed error information
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::ConnectionFailed {
                    peripheral_id: identifier,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                    error_domain: error_info.domain,
                });
            }
        } else {
            error!(" Delegate: Failed to connect to {} - Unknown error", identifier);
            
            // Send generic failure event
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::ConnectionFailed {
                    peripheral_id: identifier,
                    error_message: "Unknown connection error".to_string(),
                    error_code: -1,
                    error_domain: "Unknown".to_string(),
                });
            }
        }
    }
    
    decl.add_method(
        sel!(centralManager:didFailToConnectPeripheral:error:),
        central_manager_did_fail_to_connect as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    decl.register();
    debug!("Registered ZhtpCBCentralManagerDelegate class");
}

/// Register ZhtpCBPeripheralManagerDelegate class
#[cfg(target_os = "macos")]
unsafe fn register_peripheral_manager_delegate() {
    let superclass = AnyClass::get(c"NSObject").expect("NSObject class not found");
    let mut decl = ClassBuilder::new(c"ZhtpCBPeripheralManagerDelegate", superclass)
        .expect("Failed to declare ZhtpCBPeripheralManagerDelegate class");
    
    // Add ivar to store the event sender pointer
    decl.add_ivar::<usize>(c"event_sender_ptr");
    
    // Add protocol conformance to CBPeripheralManagerDelegate
    if let Some(protocol) = AnyProtocol::get(c"CBPeripheralManagerDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBPeripheralManagerDelegate protocol");
    } else {
        warn!("CBPeripheralManagerDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral
    unsafe extern "C" fn peripheral_manager_did_update_state(this: *mut AnyObject, _cmd: Sel, peripheral: *mut AnyObject) {
        let this = &*this;
        let state: i64 = msg_send![peripheral, state];
        
        let bt_state = match state {
            0 => BluetoothState::Unknown,
            1 => BluetoothState::Resetting,
            2 => BluetoothState::Unsupported,
            3 => BluetoothState::Unauthorized,
            4 => BluetoothState::PoweredOff,
            5 => BluetoothState::PoweredOn,
            _ => BluetoothState::Unknown,
        };
        
        debug!(" Delegate: peripheralManagerDidUpdateState: {:?}", bt_state);
        
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::StateChanged(bt_state));
        }
    }
    
    decl.add_method(
        sel!(peripheralManagerDidUpdateState:),
        peripheral_manager_did_update_state as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject)
    );
    
    // Implement: - (void)peripheralManager:didAddService:error:
    unsafe extern "C" fn peripheral_manager_did_add_service(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        service: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Failed to add service - {}", error_info.to_error_message());
        } else {
            let service_uuid_obj: *mut AnyObject = msg_send![service, UUID];
            let uuid_string: *mut AnyObject = msg_send![service_uuid_obj, UUIDString];
            let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
            let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
            
            debug!(" Delegate: Added service: {}", uuid);
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::ServiceAdded(uuid));
            }
        }
    }
    
    decl.add_method(
        sel!(peripheralManager:didAddService:error:),
        peripheral_manager_did_add_service as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheralManagerDidStartAdvertising:error:
    unsafe extern "C" fn peripheral_manager_did_start_advertising(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Failed to start advertising - {}", error_info.to_error_message());
        } else {
            debug!(" Delegate: Started advertising");
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::AdvertisingStarted);
            }
        }
    }
    
    decl.add_method(
        sel!(peripheralManagerDidStartAdvertising:error:),
        peripheral_manager_did_start_advertising as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheralManager:didReceiveWriteRequests:
    unsafe extern "C" fn peripheral_manager_did_receive_write_requests(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        requests: *mut AnyObject, // NSArray of CBATTRequest objects
    ) {
        info!("🚨 WRITE REQUEST HANDLER CALLED!");
        let this = &*this;
        
        // Get count of requests
        let count: usize = msg_send![requests, count];
        info!(" Delegate: Received {} write request(s)", count);
        
        // Process each write request
        for i in 0..count {
            let request: *mut AnyObject = msg_send![requests, objectAtIndex: i as usize];
            
            // Get characteristic UUID
            let characteristic: *mut AnyObject = msg_send![request, characteristic];
            let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
            let uuid_string: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
            let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
            let char_uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
            
            // Get write value (NSData)
            let value: *mut AnyObject = msg_send![request, value];
            let length: usize = if !value.is_null() {
                msg_send![value, length]
            } else {
                0
            };
            
            // Get central (peer) identifier
            let central: *mut AnyObject = msg_send![request, central];
            let central_uuid: *mut AnyObject = msg_send![central, identifier];
            let central_uuid_string: *mut AnyObject = msg_send![central_uuid, UUIDString];
            let central_uuid_cstr: *const i8 = msg_send![central_uuid_string, UTF8String];
            let peer_id = std::ffi::CStr::from_ptr(central_uuid_cstr).to_string_lossy().to_string();
            
            info!(" Write request: char={}, peer={}, bytes={}", char_uuid, peer_id, length);
            
            // Extract data bytes - wrapped in catch_unwind to prevent Objective-C callback crashes
            let mut data = Vec::new();
            if !value.is_null() && length > 0 {
                // NSData.bytes returns *const c_void, we must cast it properly
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let bytes_ptr: *const std::ffi::c_void = msg_send![value, bytes];
                    let bytes_ptr = bytes_ptr as *const u8;
                    if !bytes_ptr.is_null() && length > 0 {
                        std::slice::from_raw_parts(bytes_ptr, length).to_vec()
                    } else {
                        Vec::new()
                    }
                })) {
                    Ok(extracted_data) => {
                        data = extracted_data;
                        if !data.is_empty() {
                            info!(" Data: {} bytes: {:?}", length, &data[..std::cmp::min(20, length)]);
                        } else {
                            warn!(" Received null bytes pointer for {} byte write request", length);
                        }
                    }
                    Err(e) => {
                        error!(" CRITICAL: Failed to extract NSData bytes: {:?}", e);
                        warn!(" Attempting safe fallback for {} byte write request", length);
                        // Leave data empty - will still send response to avoid Windows hanging
                    }
                }
            }
            
            // Send event to application
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::WriteRequest {
                    central_id: peer_id,
                    characteristic_uuid: char_uuid,
                    value: data,
                });
            }
        }
        
        // Respond to all requests with success
        // CBATTError.success = 0
        // Get first request from NSArray to respond to
        if count > 0 {
            let first_request: *mut AnyObject = msg_send![requests, objectAtIndex:0usize];
            let result_code: i64 = 0; // CBATTErrorSuccess
            let _: () = msg_send![peripheral, respondToRequest:first_request withResult:result_code];
            info!(" Responded to {} write request(s) with success", count);
        } else {
            info!(" No write requests to respond to");
        }
    }
    
    decl.add_method(
        sel!(peripheralManager:didReceiveWriteRequests:),
        peripheral_manager_did_receive_write_requests as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheralManager:central:didSubscribeToCharacteristic:
    unsafe extern "C" fn peripheral_manager_did_subscribe_to_characteristic(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        central: *mut AnyObject,
        characteristic: *mut AnyObject,
    ) {
        let this = &*this;
        
        // Get central identifier
        let central_id_obj: *mut AnyObject = msg_send![central, identifier];
        let central_id_str: *mut AnyObject = msg_send![central_id_obj, UUIDString];
        let central_id_cstr: *const i8 = msg_send![central_id_str, UTF8String];
        let central_id = std::ffi::CStr::from_ptr(central_id_cstr).to_string_lossy().to_string();
        
        // Get characteristic UUID
        let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
        let char_uuid_str: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
        let char_uuid_cstr: *const i8 = msg_send![char_uuid_str, UTF8String];
        let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
        
        info!(" Delegate: Central {} subscribed to characteristic {}", central_id, char_uuid);
        
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::CentralSubscribed { central_id, characteristic_uuid: char_uuid });
        }
    }
    
    decl.add_method(
        sel!(peripheralManager:central:didSubscribeToCharacteristic:),
        peripheral_manager_did_subscribe_to_characteristic as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheralManager:central:didUnsubscribeFromCharacteristic:
    unsafe extern "C" fn peripheral_manager_did_unsubscribe_from_characteristic(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        central: *mut AnyObject,
        characteristic: *mut AnyObject,
    ) {
        let this = &*this;
        
        // Get central identifier
        let central_id_obj: *mut AnyObject = msg_send![central, identifier];
        let central_id_str: *mut AnyObject = msg_send![central_id_obj, UUIDString];
        let central_id_cstr: *const i8 = msg_send![central_id_str, UTF8String];
        let central_id = std::ffi::CStr::from_ptr(central_id_cstr).to_string_lossy().to_string();
        
        // Get characteristic UUID
        let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
        let char_uuid_str: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
        let char_uuid_cstr: *const i8 = msg_send![char_uuid_str, UTF8String];
        let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
        
        info!("🔕 Delegate: Central {} unsubscribed from characteristic {}", central_id, char_uuid);
        
        let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
        if sender_ptr != 0 {
            let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
            let _ = sender.send(CoreBluetoothEvent::CentralUnsubscribed { central_id, characteristic_uuid: char_uuid });
        }
    }
    
    decl.add_method(
        sel!(peripheralManager:central:didUnsubscribeFromCharacteristic:),
        peripheral_manager_did_unsubscribe_from_characteristic as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    decl.register();
    info!(" Registered ZhtpCBPeripheralManagerDelegate with 6 methods:");
    info!("   1. peripheralManagerDidUpdateState:");
    info!("   2. peripheralManager:didAddService:error:");
    info!("   3. peripheralManagerDidStartAdvertising:error:");
    info!("   4. peripheralManager:didReceiveWriteRequests: 🔥");
    info!("   5. peripheralManager:central:didSubscribeToCharacteristic: ");
    info!("   6. peripheralManager:central:didUnsubscribeFromCharacteristic: 🔕");
}

/// Register ZhtpCBPeripheralDelegate class for GATT operations
#[cfg(target_os = "macos")]
unsafe fn register_peripheral_delegate() {
    let superclass = AnyClass::get(c"NSObject").expect("NSObject class not found");
    let mut decl = ClassBuilder::new(c"ZhtpCBPeripheralDelegate", superclass)
        .expect("Failed to declare ZhtpCBPeripheralDelegate class");
    
    // Add ivar to store the event sender pointer
    decl.add_ivar::<usize>(c"event_sender_ptr");
    
    // Add protocol conformance to CBPeripheralDelegate
    if let Some(protocol) = AnyProtocol::get(c"CBPeripheralDelegate") {
        decl.add_protocol(protocol);
        debug!("Added CBPeripheralDelegate protocol");
    } else {
        warn!("CBPeripheralDelegate protocol not found - continuing without it");
    }
    
    // Implement: - (void)peripheral:didDiscoverServices:
    unsafe extern "C" fn peripheral_did_discover_services(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Service discovery failed for {} - {}", identifier, error_info.to_error_message());
            
            // Send error event
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::ServiceDiscoveryFailed {
                    peripheral_id: identifier,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                });
            }
        } else {
            // Success - extract discovered services
            let services_array: *mut AnyObject = msg_send![peripheral, services];
            if !services_array.is_null() {
                let count: usize = msg_send![services_array, count];
                let mut service_uuids = Vec::new();
                
                for i in 0..count {
                    let service: *mut AnyObject = msg_send![services_array, objectAtIndex: i];
                    let uuid_obj: *mut AnyObject = msg_send![service, UUID];
                    let uuid_string: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
                    service_uuids.push(uuid);
                }
                
                debug!(" Delegate: Discovered {} services for {}", service_uuids.len(), identifier);
                
                let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::ServicesDiscovered {
                        peripheral_id: identifier,
                        service_uuids,
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didDiscoverServices:),
        peripheral_did_discover_services as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheral:didDiscoverCharacteristicsForService:error:
    unsafe extern "C" fn peripheral_did_discover_characteristics(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        service: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        let service_uuid_obj: *mut AnyObject = msg_send![service, UUID];
        let service_uuid_string: *mut AnyObject = msg_send![service_uuid_obj, UUIDString];
        let service_uuid_cstr: *const i8 = msg_send![service_uuid_string, UTF8String];
        let service_uuid = std::ffi::CStr::from_ptr(service_uuid_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Characteristic discovery failed for service {} - {}", 
                   service_uuid, error_info.to_error_message());
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::CharacteristicDiscoveryFailed {
                    peripheral_id: identifier,
                    service_uuid,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                });
            }
        } else {
            // Success - extract characteristics
            let characteristics_array: *mut AnyObject = msg_send![service, characteristics];
            if !characteristics_array.is_null() {
                let count: usize = msg_send![characteristics_array, count];
                let mut char_uuids = Vec::new();
                
                for i in 0..count {
                    let characteristic: *mut AnyObject = msg_send![characteristics_array, objectAtIndex: i];
                    let uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
                    let uuid_string: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_string, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy().to_string();
                    char_uuids.push(uuid);
                }
                
                debug!(" Delegate: Discovered {} characteristics for service {}", 
                       char_uuids.len(), service_uuid);
                
                let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
                if sender_ptr != 0 {
                    let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                    let _ = sender.send(CoreBluetoothEvent::CharacteristicsDiscovered {
                        peripheral_id: identifier,
                        service_uuid,
                        characteristic_uuids: char_uuids,
                    });
                }
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didDiscoverCharacteristicsForService:error:),
        peripheral_did_discover_characteristics as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheral:didUpdateValueForCharacteristic:error:
    unsafe extern "C" fn peripheral_did_update_value(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        characteristic: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
        let char_uuid_string: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
        let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
        let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Read failed for characteristic {} - {}", 
                   char_uuid, error_info.to_error_message());
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::CharacteristicReadFailed {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                });
            }
        } else {
            // Success - extract value
            let value: *mut AnyObject = msg_send![characteristic, value];
            let data = if !value.is_null() {
                let length: usize = msg_send![value, length];
                let bytes: *const u8 = msg_send![value, bytes];
                std::slice::from_raw_parts(bytes, length).to_vec()
            } else {
                Vec::new()
            };
            
            debug!("📖 Delegate: Read {} bytes from characteristic {}", data.len(), char_uuid);
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::CharacteristicValueUpdated {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                    value: data,
                });
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didUpdateValueForCharacteristic:error:),
        peripheral_did_update_value as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheral:didWriteValueForCharacteristic:error:
    unsafe extern "C" fn peripheral_did_write_value(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        characteristic: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
        let char_uuid_string: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
        let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
        let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Write failed for characteristic {} - {}", 
                   char_uuid, error_info.to_error_message());
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::CharacteristicWriteFailed {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                });
            }
        } else {
            debug!(" Delegate: Write completed for characteristic {}", char_uuid);
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::WriteCompleted {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                });
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didWriteValueForCharacteristic:error:),
        peripheral_did_write_value as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    // Implement: - (void)peripheral:didUpdateNotificationStateForCharacteristic:error:
    unsafe extern "C" fn peripheral_did_update_notification_state(
        this: *mut AnyObject,
        _cmd: Sel,
        peripheral: *mut AnyObject,
        characteristic: *mut AnyObject,
        error: *mut AnyObject,
    ) {
        let this = &*this;
        let peripheral_id_obj: *mut AnyObject = msg_send![peripheral, identifier];
        let id_string: *mut AnyObject = msg_send![peripheral_id_obj, UUIDString];
        let id_cstr: *const i8 = msg_send![id_string, UTF8String];
        let identifier = std::ffi::CStr::from_ptr(id_cstr).to_string_lossy().to_string();
        
        let char_uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
        let char_uuid_string: *mut AnyObject = msg_send![char_uuid_obj, UUIDString];
        let char_uuid_cstr: *const i8 = msg_send![char_uuid_string, UTF8String];
        let char_uuid = std::ffi::CStr::from_ptr(char_uuid_cstr).to_string_lossy().to_string();
        
        // Use comprehensive error parsing
        if let Some(error_info) = parse_nserror(error) {
            error!(" Delegate: Notification state update failed for {} - {}", 
                   char_uuid, error_info.to_error_message());
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::NotificationStateFailed {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                    error_message: error_info.to_error_message(),
                    error_code: error_info.code,
                });
            }
        } else {
            // Check if notifications are now enabled or disabled
            let is_notifying: bool = msg_send![characteristic, isNotifying];
            
            debug!(" Delegate: Notification {} for characteristic {}", 
                   if is_notifying { "enabled" } else { "disabled" }, char_uuid);
            
            let sender_ptr: usize = *this.get_ivar::<usize>("event_sender_ptr");
            if sender_ptr != 0 {
                let sender = &*(sender_ptr as *const tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>);
                let _ = sender.send(CoreBluetoothEvent::NotificationStateChanged {
                    peripheral_id: identifier,
                    characteristic_uuid: char_uuid,
                    enabled: is_notifying,
                });
            }
        }
    }
    
    decl.add_method(
        sel!(peripheral:didUpdateNotificationStateForCharacteristic:error:),
        peripheral_did_update_notification_state as unsafe extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject, *mut AnyObject)
    );
    
    decl.register();
    debug!("Registered ZhtpCBPeripheralDelegate class");
}

/// Create an instance of ZhtpCBCentralManagerDelegate with event sender
#[cfg(target_os = "macos")]
#[allow(invalid_reference_casting)]
pub unsafe fn create_central_manager_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut AnyObject {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = AnyClass::get(c"ZhtpCBCentralManagerDelegate").expect("Delegate class not registered");
    
    // Create instance: [[ZhtpCBCentralManagerDelegate alloc] init]
    let delegate: *mut AnyObject = msg_send![class, alloc];
    let delegate: *mut AnyObject = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    // Box the sender to ensure it lives long enough
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    if let Some(delegate_ref) = delegate.as_mut() {
        // Use ptr::write to set the ivar value safely
        let ivar_ptr = delegate_ref.get_ivar::<usize>("event_sender_ptr") as *const usize;
        std::ptr::write(ivar_ptr as *mut usize, sender_ptr);
    }
    
    info!(" Created CBCentralManagerDelegate instance");
    delegate
}

/// Create an instance of ZhtpCBPeripheralManagerDelegate with event sender
#[cfg(target_os = "macos")]
#[allow(invalid_reference_casting)]
pub unsafe fn create_peripheral_manager_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut AnyObject {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = AnyClass::get(c"ZhtpCBPeripheralManagerDelegate").expect("Delegate class not registered");
    
    // Create instance
    let delegate: *mut AnyObject = msg_send![class, alloc];
    let delegate: *mut AnyObject = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    if let Some(delegate_ref) = delegate.as_mut() {
        // Use ptr::write to set the ivar value safely
        let ivar_ptr = delegate_ref.get_ivar::<usize>("event_sender_ptr") as *const usize;
        std::ptr::write(ivar_ptr as *mut usize, sender_ptr);
    }
    
    info!(" Created CBPeripheralManagerDelegate instance");
    delegate
}

/// Create an instance of ZhtpCBPeripheralDelegate with event sender
#[cfg(target_os = "macos")]
#[allow(invalid_reference_casting)]
pub unsafe fn create_peripheral_delegate_instance(
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>
) -> *mut AnyObject {
    // Ensure delegate class is registered
    register_delegate_classes();
    
    // Get the custom class
    let class = AnyClass::get(c"ZhtpCBPeripheralDelegate").expect("Peripheral delegate class not registered");
    
    // Create instance
    let delegate: *mut AnyObject = msg_send![class, alloc];
    let delegate: *mut AnyObject = msg_send![delegate, init];
    
    // Store event sender pointer in ivar
    let sender_box = Box::new(event_sender);
    let sender_ptr = Box::into_raw(sender_box) as usize;
    if let Some(delegate_ref) = delegate.as_mut() {
        // Use ptr::write to set the ivar value safely
        let ivar_ptr = delegate_ref.get_ivar::<usize>("event_sender_ptr") as *const usize;
        std::ptr::write(ivar_ptr as *mut usize, sender_ptr);
    }
    
    info!(" Created CBPeripheralDelegate instance");
    delegate
}

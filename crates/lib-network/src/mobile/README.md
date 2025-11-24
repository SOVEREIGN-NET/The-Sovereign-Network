# Mobile FFI Bindings

This directory contains Foreign Function Interface (FFI) bindings for Android and iOS mobile platforms.

## Overview

The mobile FFI layer enables native mobile apps to use the ZHTP mesh networking protocol by providing:
- **Android**: JNI (Java Native Interface) bindings for Kotlin/Java
- **iOS**: C FFI bindings for Swift

## Architecture

```
Mobile App (Kotlin/Swift)
    ↓
FFI Bridge (JNI/C FFI)
    ↓
Rust ZHTP Core (lib-network)
    ↓
Native Protocols (WiFi Direct, Bluetooth, mDNS)
```

## Files

- **mod.rs**: Common types and helper functions shared by both platforms
- **android.rs**: Android JNI bindings (conditional compilation: `target_os = "android"`)
- **ios.rs**: iOS C FFI bindings (conditional compilation: `target_os = "ios"`)

## Features

### Core Functions
- `init_node()` - Initialize ZHTP node with configuration
- `start_node()` - Start the mesh networking node
- `stop_node()` - Stop the node and clean up resources
- `get_status()` - Get current node status as JSON
- `discover_peers()` - Discover peers on local network
- `connect_to_peer()` - Connect to a specific peer
- `send_message()` - Send message to connected peer
- `get_connected_peers()` - Get list of connected peers

### Platform-Specific Callbacks

#### Android (WiFi Direct + Bluetooth)
- `onWifiDirectPeerDiscovered()` - Called when WiFi Direct peer found
- `onBluetoothDeviceDiscovered()` - Called when Bluetooth device found
- `onWifiDirectConnectionChanged()` - WiFi Direct connection state
- `onBluetoothConnectionChanged()` - Bluetooth connection state

#### iOS (MultipeerConnectivity + CoreBluetooth)
- `zhtp_on_multipeer_peer_discovered()` - MultipeerConnectivity peer found
- `zhtp_on_bluetooth_peripheral_discovered()` - Bluetooth peripheral found
- `zhtp_on_multipeer_state_changed()` - MultipeerConnectivity session state
- `zhtp_on_bluetooth_state_changed()` - Bluetooth connection state
- `zhtp_on_multipeer_data_received()` - Data received via MultipeerConnectivity
- `zhtp_on_bluetooth_data_received()` - Data received via Bluetooth

## Building

### Android
```bash
# Install Android NDK and Rust targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android

# Build
cargo build --target aarch64-linux-android --release

# Output: target/aarch64-linux-android/release/liblib_network.so
```

### iOS
```bash
# Install iOS targets
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios

# Build
cargo build --target aarch64-apple-ios --release

# Create XCFramework
# See examples/ios/build_xcframework.sh
```

## Integration Examples

See the `examples/` directory for complete integration examples:
- `examples/android/` - Android Studio project with Kotlin
- `examples/ios/` - Xcode project with SwiftUI

## JSON Response Format

All FFI functions return JSON strings with consistent format:

```json
{
  "success": true,
  "node_id": "uuid-string",
  "message": "Operation completed"
}
```

Error format:
```json
{
  "success": false,
  "error": "Error message"
}
```

## Thread Safety

The FFI layer handles thread safety internally using:
- `Mutex` for shared state
- `Arc` for reference counting
- Tokio runtime for async operations

Mobile apps can call FFI functions from any thread safely.

## Memory Management

### Android (JNI)
- String memory is managed by JVM
- No manual cleanup needed

### iOS (C FFI)
- Strings returned from Rust must be freed using `zhtp_free_string()`
- Always free returned strings to prevent memory leaks

```swift
let status = zhtp_get_status()
defer { zhtp_free_string(status) }
let statusStr = String(cString: status!)
```

## Error Handling

All FFI functions return JSON with success/error status. Always check the `success` field:

```kotlin
// Android
val result = ZhtpNative.initNode("router", true, true, true, 9333)
val json = JSONObject(result)
if (json.getBoolean("success")) {
    val nodeId = json.getString("node_id")
    // Success
} else {
    val error = json.getString("error")
    // Handle error
}
```

```swift
// iOS
guard let resultPtr = zhtp_init_node("router", true, true, true, 9333) else {
    return
}
defer { zhtp_free_string(resultPtr) }
let resultStr = String(cString: resultPtr)
let json = try? JSONSerialization.jsonObject(with: resultStr.data(using: .utf8)!)
// Check json["success"]
```

## Logging

The FFI layer uses the `log` crate for debugging:
- Android: Logs go to logcat with tag "RustZHTP"
- iOS: Logs go to Console.app

Enable logging in your app:
```kotlin
// Android - already integrated with android.util.Log
```

```swift
// iOS - logs appear in Xcode console automatically
```

## Security Considerations

1. **Permissions**: Apps must request WiFi, Bluetooth, and Location permissions
2. **Background execution**: Use foreground services (Android) or background modes (iOS)
3. **Network security**: All ZHTP connections use post-quantum cryptography
4. **Data privacy**: No personal data is transmitted without encryption

## Troubleshooting

### Android
- **Library not found**: Ensure `liblib_network.so` is in `jniLibs/arm64-v8a/`
- **JNI method not found**: Check package name matches `net.sovereign.zhtp`
- **Crash on startup**: Enable verbose JNI logs with `adb logcat | grep JNI`

### iOS
- **Symbol not found**: Ensure framework is linked in Build Phases
- **Segmentation fault**: Always check for null pointers before dereferencing
- **Memory leak**: Always call `zhtp_free_string()` on returned strings

## Next Steps

1. Review the integration examples in `examples/`
2. Build the Rust library for your target platform
3. Create native app wrapper with WiFi Direct/Bluetooth integration
4. Test peer discovery and connection on real devices
5. Integrate with Firebase for app distribution

## License

MIT OR Apache-2.0 (same as parent project)

# React Native iOS Integration Guide

This guide explains how to integrate `NativeIdentityProvisioning` into your React Native iOS app.

## Prerequisites

- macOS with Xcode installed
- Rust toolchain with iOS targets
- React Native project (0.70+)

## Step 1: Build the iOS XCFramework

On a macOS machine, run these commands from the `lib-client` directory:

```bash
# Add iOS targets to Rust
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build for iOS device (arm64)
cargo build -p lib-client --release --features uniffi --target aarch64-apple-ios

# Build for iOS simulator (arm64 - Apple Silicon)
cargo build -p lib-client --release --features uniffi --target aarch64-apple-ios-sim

# Build for iOS simulator (x86_64 - Intel Macs)
cargo build -p lib-client --release --features uniffi --target x86_64-apple-ios

# Install uniffi-bindgen if not already installed
cargo install uniffi_bindgen

# Generate Swift bindings
uniffi-bindgen generate uniffi/zhtp_client.udl --language swift --out-dir ./generated/swift

# Create fat library for simulator (combines arm64 + x86_64)
lipo -create \
    target/aarch64-apple-ios-sim/release/libzhtp_client.a \
    target/x86_64-apple-ios/release/libzhtp_client.a \
    -output target/ios-sim-universal/libzhtp_client.a

# Create XCFramework
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libzhtp_client.a \
    -headers generated/swift \
    -library target/ios-sim-universal/libzhtp_client.a \
    -headers generated/swift \
    -output ZhtpClient.xcframework
```

## Step 2: Add Files to Your iOS Project

### 2.1 Add XCFramework

1. Open your React Native iOS project in Xcode (`ios/YourApp.xcworkspace`)
2. Drag `ZhtpClient.xcframework` into the project navigator
3. Ensure "Copy items if needed" is checked
4. Add to target: your main app target
5. In **Build Settings** > **Framework Search Paths**, add the path to the framework

### 2.2 Add Generated Swift Module

1. Copy `generated/swift/zhtp_client.swift` to your iOS project
2. Copy `generated/swift/zhtp_clientFFI.h` to your iOS project
3. Add both files to your Xcode project

### 2.3 Add the React Native Bridge Files

Copy these files from `react-native/ios/` to your iOS project:

```
ios/
├── NativeIdentityProvisioning.swift
└── NativeIdentityProvisioning.m
```

Add them to your Xcode project.

### 2.4 Create/Update Bridging Header

If you don't have a bridging header, Xcode will prompt you to create one when adding Swift files.

Add these imports to your bridging header (`YourApp-Bridging-Header.h`):

```objc
#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>
#import "zhtp_clientFFI.h"
```

### 2.5 Update Build Settings

In Xcode, go to your target's **Build Settings**:

1. **Swift Language Version**: 5.0 or later
2. **Enable Bitcode**: No (Rust doesn't support bitcode)
3. **Other Linker Flags**: Add `-lzhtp_client`

### 2.6 Add to Podfile (if using CocoaPods)

Add to your `ios/Podfile`:

```ruby
target 'YourApp' do
  # ... existing pods ...

  # Required for Swift/ObjC interop in React Native
  use_frameworks! :linkage => :static
end
```

Then run:

```bash
cd ios && pod install
```

## Step 3: Add TypeScript Files

Copy `react-native/js/NativeIdentityProvisioning.ts` to your React Native project:

```bash
cp react-native/js/NativeIdentityProvisioning.ts your-rn-app/src/native/
```

## Step 4: Usage in React Native

```typescript
import { identityProvisioning, IdentityInfo } from './native/NativeIdentityProvisioning';

// Generate new identity
async function createIdentity(): Promise<IdentityInfo> {
  const deviceId = 'unique-device-id'; // Use a UUID or device identifier
  const identity = await identityProvisioning.generateIdentity(deviceId);

  console.log('Created identity:', identity.did);
  console.log('Public key (base64):', identity.publicKey);

  return identity;
}

// Register with server
async function registerWithServer(serverUrl: string): Promise<void> {
  // Get public identity (safe to send)
  const publicIdentity = await identityProvisioning.getPublicIdentity();

  // Sign registration proof
  const timestamp = Date.now();
  const signature = await identityProvisioning.signRegistrationProof(timestamp);

  // Send to server
  const response = await fetch(`${serverUrl}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      publicIdentity,
      timestamp,
      signature,
    }),
  });

  if (!response.ok) {
    throw new Error('Registration failed');
  }
}

// Perform UHP v2 handshake
async function performHandshake(serverUrl: string): Promise<void> {
  // Compute channel binding (hash of connection info)
  const channelBinding = btoa('local:port|remote:port'); // Simplified

  // Initialize handshake
  await identityProvisioning.initHandshake(channelBinding);

  // Step 1: Create and send ClientHello
  const clientHello = await identityProvisioning.createClientHello();
  const response1 = await fetch(`${serverUrl}/handshake/hello`, {
    method: 'POST',
    body: clientHello, // base64
  });
  const serverHello = await response1.text();

  // Step 2: Process ServerHello, send ClientFinish
  const clientFinish = await identityProvisioning.processServerHello(serverHello);
  await fetch(`${serverUrl}/handshake/finish`, {
    method: 'POST',
    body: clientFinish,
  });

  // Step 3: Finalize
  const result = await identityProvisioning.finalizeHandshake();
  console.log('Connected to:', result.peerDid);
  console.log('Session ID:', result.sessionId);
}

// Encrypt/Decrypt after handshake
async function sendSecureMessage(message: string): Promise<string> {
  const plaintextBase64 = btoa(message);
  const encrypted = await identityProvisioning.encrypt(plaintextBase64);
  return encrypted;
}

async function receiveSecureMessage(encrypted: string): Promise<string> {
  const decrypted = await identityProvisioning.decrypt(encrypted);
  return atob(decrypted);
}
```

## Troubleshooting

### "NativeIdentityProvisioning not available on this platform"

This error means the native module isn't linked. Check:

1. XCFramework is properly added to the Xcode project
2. Swift files are added to the correct target
3. Bridging header is configured
4. You ran `pod install` after changes
5. You're not running in Expo Go (use a dev build)

### "Failed to generate identity"

1. Check that the Rust library compiled without errors
2. Verify the XCFramework contains the correct architectures:
   ```bash
   lipo -info ZhtpClient.xcframework/ios-arm64/libzhtp_client.a
   ```

### Build errors about missing symbols

Add `-lzhtp_client` to **Other Linker Flags** in Xcode.

### Swift version errors

Ensure **Swift Language Version** is set to 5.0+ in Build Settings.

## Architecture Overview

```
React Native JS/TS
        │
        │ NativeModules.NativeIdentityProvisioning
        ▼
┌─────────────────────────────┐
│  NativeIdentityProvisioning │ ◄── Swift (Bridge)
│  .swift / .m                │
└─────────────────────────────┘
        │
        │ import ZhtpClient
        ▼
┌─────────────────────────────┐
│  zhtp_client.swift          │ ◄── UniFFI Generated
│  (Swift bindings)           │
└─────────────────────────────┘
        │
        │ FFI calls
        ▼
┌─────────────────────────────┐
│  libzhtp_client.a           │ ◄── Rust (lib-client)
│  (Static library)           │
└─────────────────────────────┘
```

## Security Notes

- **Private keys never leave native code**: The JS layer only receives public keys and DIDs
- **Session keys stay in Swift**: Encryption/decryption happens natively
- **Master seed for backup only**: Only expose when user explicitly requests backup

## File Inventory

After integration, your iOS project should have:

```
ios/
├── YourApp/
│   ├── NativeIdentityProvisioning.swift  # RN Bridge
│   ├── NativeIdentityProvisioning.m      # ObjC macros
│   ├── zhtp_client.swift                 # UniFFI bindings
│   └── zhtp_clientFFI.h                  # FFI header
├── YourApp-Bridging-Header.h
└── ZhtpClient.xcframework/               # Rust library
    ├── ios-arm64/
    │   └── libzhtp_client.a
    └── ios-arm64_x86_64-simulator/
        └── libzhtp_client.a
```

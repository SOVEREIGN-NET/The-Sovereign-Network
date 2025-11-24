# ZHTP Mobile Build Configuration

Complete build configuration for Android and iOS mobile platforms.

## Overview

This directory contains build configurations and scripts for compiling ZHTP as a mobile library:
- **Android**: Produces `.so` files for JNI integration
- **iOS**: Produces `.xcframework` for Swift/Objective-C integration

## Project Structure

```
zhtp/
├── .cargo/
│   └── config.toml          # Mobile target configurations
├── Cargo.toml               # Mobile features and profiles
├── src/
│   └── mobile_lib.rs        # Mobile library entry point
└── scripts/
    ├── build_android.sh     # Android build script
    └── build_ios.sh         # iOS build script
```

## Build Configurations

### Cargo.toml Changes

#### Library Target
```toml
[lib]
name = "zhtp_mobile"
path = "src/mobile_lib.rs"
crate-type = ["cdylib", "staticlib"]  # cdylib for Android, staticlib for iOS
```

#### Mobile Features
```toml
[features]
mobile = ["minimal-blockchain"]  # Base mobile configuration
android = ["mobile"]             # Android-specific features
ios = ["mobile"]                 # iOS-specific features
```

#### Mobile Build Profiles
```toml
[profile.mobile]
opt-level = "z"         # Optimize for size
lto = "fat"             # Full link-time optimization
codegen-units = 1       # Single codegen unit
strip = true            # Strip symbols
panic = "abort"         # No unwinding
```

### Target Configurations (.cargo/config.toml)

#### Android Targets
- `aarch64-linux-android` - ARM64 (modern devices)
- `armv7-linux-androideabi` - ARMv7 (older devices)
- `x86_64-linux-android` - x86_64 emulator
- `i686-linux-android` - x86 emulator

#### iOS Targets
- `aarch64-apple-ios` - iOS device (ARM64)
- `aarch64-apple-ios-sim` - iOS simulator (Apple Silicon)
- `x86_64-apple-ios` - iOS simulator (Intel)

## Prerequisites

### Android
1. **Android NDK** (r21 or later)
   ```bash
   # Download from: https://developer.android.com/ndk/downloads
   # Set environment variable:
   export ANDROID_NDK_HOME=/path/to/android-ndk
   ```

2. **Rust Android targets**
   ```bash
   rustup target add aarch64-linux-android
   rustup target add armv7-linux-androideabi
   rustup target add x86_64-linux-android
   rustup target add i686-linux-android
   ```

3. **cargo-ndk** (automated NDK integration)
   ```bash
   cargo install cargo-ndk
   ```

### iOS
1. **macOS with Xcode** (13.0 or later)
   ```bash
   xcode-select --install
   ```

2. **Rust iOS targets**
   ```bash
   rustup target add aarch64-apple-ios
   rustup target add aarch64-apple-ios-sim
   rustup target add x86_64-apple-ios
   ```

## Building

### Android

#### Quick Build (All Architectures)
```bash
cd zhtp/scripts
chmod +x build_android.sh
./build_android.sh release
```

#### Manual Build (Single Architecture)
```bash
cd zhtp

# ARM64 (primary target)
cargo ndk --target aarch64-linux-android --platform 26 \
    build --release --features android --lib

# Output: target/aarch64-linux-android/mobile/libzhtp_mobile.so
```

#### Output Structure
```
target/android/jniLibs/
├── arm64-v8a/
│   └── libzhtp_mobile.so
├── armeabi-v7a/
│   └── libzhtp_mobile.so
├── x86_64/
│   └── libzhtp_mobile.so
└── x86/
    └── libzhtp_mobile.so
```

### iOS

#### Quick Build (XCFramework)
```bash
cd zhtp/scripts
chmod +x build_ios.sh
./build_ios.sh release
```

#### Manual Build (Single Architecture)
```bash
cd zhtp

# iOS Device
cargo build --target aarch64-apple-ios --release --features ios --lib

# iOS Simulator (Apple Silicon)
cargo build --target aarch64-apple-ios-sim --release --features ios --lib

# iOS Simulator (Intel)
cargo build --target x86_64-apple-ios --release --features ios --lib
```

#### Output
```
target/ios/ZhtpFramework.xcframework/
├── ios-arm64/
│   └── ZhtpFramework.framework/
└── ios-arm64_x86_64-simulator/
    └── ZhtpFramework.framework/
```

## Build Options

### Build Types

| Command | Profile | Optimization | Size | Use Case |
|---------|---------|--------------|------|----------|
| `./build_android.sh debug` | `dev` | None | Large | Development |
| `./build_android.sh release` | `mobile` | Max size | Small | Production |

### Custom Builds

#### Debug Build (Faster compilation)
```bash
cargo build --target aarch64-linux-android --features android --lib
```

#### Release Build (Optimized for size)
```bash
cargo build --target aarch64-linux-android --release --features android --lib
```

#### Profile-Specific Build
```bash
cargo build --target aarch64-linux-android --profile mobile --features android --lib
```

## Integration

### Android Studio

1. **Copy libraries to project:**
   ```bash
   cp -r target/android/jniLibs app/src/main/
   ```

2. **Or configure in build.gradle:**
   ```gradle
   android {
       sourceSets {
           main {
               jniLibs.srcDirs = ['../../zhtp/target/android/jniLibs']
           }
       }
   }
   ```

3. **Load library in code:**
   ```kotlin
   companion object {
       init {
           System.loadLibrary("zhtp_mobile")
       }
   }
   ```

### Xcode

1. **Add framework to project:**
   - Drag `ZhtpFramework.xcframework` to project navigator
   - Select target → General → Frameworks, Libraries, and Embedded Content
   - Set to "Embed & Sign"

2. **Import in Swift:**
   ```swift
   import ZhtpFramework
   
   // Use FFI functions
   let result = zhtp_init_node("client", true, true, true, 9333)
   ```

## Build Performance

### Compilation Time

| Platform | Debug | Release | Incremental |
|----------|-------|---------|-------------|
| Android ARM64 | ~3 min | ~8 min | ~30 sec |
| iOS Device | ~2 min | ~6 min | ~20 sec |
| iOS Universal | ~5 min | ~15 min | ~1 min |

### Binary Size

| Platform | Debug | Release (mobile profile) |
|----------|-------|--------------------------|
| Android ARM64 | ~25 MB | ~4 MB |
| Android ARMv7 | ~20 MB | ~3.5 MB |
| iOS Device | ~30 MB | ~5 MB |
| iOS Simulator | ~35 MB | ~6 MB |

### Optimization Tips

1. **Use release profile for production:**
   ```bash
   ./build_android.sh release
   ```

2. **Enable LTO for smaller binaries** (already in mobile profile):
   ```toml
   [profile.mobile]
   lto = "fat"
   ```

3. **Strip symbols** (already enabled):
   ```toml
   [profile.mobile]
   strip = true
   ```

4. **Parallel builds:**
   ```bash
   cargo build -j 8  # Use 8 cores
   ```

## Troubleshooting

### Android

**NDK not found:**
```
Solution: Set ANDROID_NDK_HOME environment variable
export ANDROID_NDK_HOME=/path/to/android-ndk
```

**Linker errors:**
```
Solution: Ensure NDK version matches target API level (26+)
Solution: Check .cargo/config.toml has correct linker paths
```

**Library not loading:**
```
Solution: Verify ABI matches device (arm64-v8a for modern devices)
Solution: Check library is in correct jniLibs/[abi]/ directory
```

### iOS

**Framework not found:**
```
Solution: Ensure XCFramework is set to "Embed & Sign" in Xcode
Solution: Clean build folder (Cmd+Shift+K) and rebuild
```

**Symbol not found:**
```
Solution: Check all architectures are built
Solution: Verify lipo created universal simulator library correctly
```

**Build fails on Intel Mac:**
```
Solution: Install x86_64-apple-ios target
rustup target add x86_64-apple-ios
```

## CI/CD Integration

### GitHub Actions (Android)
```yaml
- name: Install Android NDK
  run: |
    export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653

- name: Build Android
  run: |
    cd zhtp/scripts
    ./build_android.sh release
```

### GitHub Actions (iOS)
```yaml
- name: Build iOS XCFramework
  run: |
    cd zhtp/scripts
    ./build_ios.sh release
```

## Advanced Configuration

### Custom NDK Path
```bash
export ANDROID_NDK_HOME=/custom/path/to/ndk
./build_android.sh release
```

### Custom SDK Version
Edit `build_android.sh`:
```bash
MIN_SDK_VERSION=28  # Android 9.0
```

### Cross-Compilation Cache
```bash
export CARGO_TARGET_DIR=/path/to/shared/target
cargo build --target aarch64-linux-android --release --features android --lib
```

## Next Steps

1.  Build mobile libraries
2.  Integrate into mobile apps
3.  Create native UI (Jetpack Compose / SwiftUI)
4.  Implement native networking (WiFi Direct / MultipeerConnectivity)
5.  Test on physical devices
6.  Deploy via Firebase App Distribution

## Resources

- [Android NDK Guide](https://developer.android.com/ndk/guides)
- [iOS XCFramework Guide](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle)
- [Rust Mobile Book](https://rust-mobile.github.io/book/)
- [cargo-ndk Documentation](https://github.com/bbqsrc/cargo-ndk)

## License

MIT OR Apache-2.0 (same as parent project)

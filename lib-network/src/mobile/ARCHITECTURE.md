# ZHTP Mobile Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MOBILE APPLICATION LAYER                          │
├─────────────────────────────────┬───────────────────────────────────────────┤
│         ANDROID APP             │              iOS APP                      │
│                                 │                                           │
│  ┌──────────────────────────┐  │  ┌──────────────────────────┐            │
│  │   MainActivity.kt        │  │  │   ContentView.swift      │            │
│  │   (Jetpack Compose UI)   │  │  │   (SwiftUI)              │            │
│  └─────────────┬────────────┘  │  └─────────────┬────────────┘            │
│                │                 │                │                          │
│  ┌─────────────▼────────────┐  │  ┌─────────────▼────────────┐            │
│  │   ZhtpService.kt         │  │  │   NetworkManager.swift   │            │
│  │   (Foreground Service)   │  │  │   (ObservableObject)     │            │
│  └─────────────┬────────────┘  │  └─────────────┬────────────┘            │
│                │                 │                │                          │
│  ┌─────────────▼────────────┐  │  ┌─────────────▼────────────┐            │
│  │   ZhtpNative.kt          │  │  │   ZhtpClient.swift       │            │
│  │   (Kotlin Wrapper)       │  │  │   (Swift Wrapper)        │            │
│  └─────────────┬────────────┘  │  └─────────────┬────────────┘            │
│                │                 │                │                          │
├────────────────┼─────────────────┼────────────────┼──────────────────────────┤
│                │  FFI BOUNDARY   │                │                          │
├────────────────┼─────────────────┼────────────────┼──────────────────────────┤
│                │                 │                │                          │
│  ┌─────────────▼────────────┐  │  ┌─────────────▼────────────┐            │
│  │   android.rs             │  │  │   ios.rs                 │            │
│  │   (JNI Bindings)         │  │  │   (C FFI)                │            │
│  │                          │  │  │                          │            │
│  │ • initNode()             │  │  │ • zhtp_init_node()       │            │
│  │ • startNode()            │  │  │ • zhtp_start_node()      │            │
│  │ • discoverPeers()        │  │  │ • zhtp_discover_peers()  │            │
│  │ • connectToPeer()        │  │  │ • zhtp_connect_to_peer() │            │
│  │ • sendMessage()          │  │  │ • zhtp_send_message()    │            │
│  └─────────────┬────────────┘  │  └─────────────┬────────────┘            │
│                │                 │                │                          │
│                └─────────────────┴────────────────┘                          │
│                                  │                                           │
│                  ┌───────────────▼────────────────┐                         │
│                  │          mod.rs                │                         │
│                  │    (Common FFI Layer)          │                         │
│                  │                                │                         │
│                  │  • ZhtpNode                    │                         │
│                  │  • NodeConfig                  │                         │
│                  │  • PeerInfo                    │                         │
│                  │  • create_node()               │                         │
│                  │  • start_node()                │                         │
│                  │  • discover_peers()            │                         │
│                  │  • connect_to_peer()           │                         │
│                  │  • send_message()              │                         │
│                  │  • Tokio Runtime               │                         │
│                  │  • Arc<Mutex<ZhtpNode>>        │                         │
│                  └───────────────┬────────────────┘                         │
│                                  │                                           │
├──────────────────────────────────┼───────────────────────────────────────────┤
│                    ZHTP CORE RUST LIBRARY                                   │
├──────────────────────────────────┴───────────────────────────────────────────┤
│                                                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │    DHT     │  │  Protocols │  │ Blockchain │  │   Crypto   │           │
│  │ Bootstrap  │  │   (mesh)   │  │    Sync    │  │(Dilithium2)│           │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘           │
│         │               │                │                │                  │
│         └───────────────┴────────────────┴────────────────┘                  │
│                                  │                                           │
│  ┌───────────────────────────────▼────────────────────────────────┐         │
│  │                    ServiceDaemon (mDNS)                         │         │
│  │              • browse_zhtp_services()                           │         │
│  │              • discover_routers_only()                          │         │
│  └───────────────────────────────┬────────────────────────────────┘         │
│                                  │                                           │
├──────────────────────────────────┼───────────────────────────────────────────┤
│                    NATIVE PLATFORM APIS                                     │
├──────────────────────────────────┴───────────────────────────────────────────┤
│                                                                               │
│  ANDROID                                    iOS                              │
│  ┌─────────────────────────┐              ┌─────────────────────────┐       │
│  │   WifiP2pManager        │              │ MultipeerConnectivity   │       │
│  │   • discoverPeers()     │              │ • MCNearbyServiceBrowser│       │
│  │   • connect()           │              │ • MCSession             │       │
│  └────────────┬────────────┘              └────────────┬────────────┘       │
│               │                                        │                     │
│  ┌────────────▼────────────┐              ┌───────────▼─────────────┐       │
│  │   BluetoothAdapter      │              │   CoreBluetooth         │       │
│  │   • startLeScan()       │              │   • CBCentralManager    │       │
│  │   • BluetoothGatt       │              │   • CBPeripheral        │       │
│  └─────────────────────────┘              └─────────────────────────┘       │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PEER DISCOVERY FLOW                           │
└──────────────────────────────────────────────────────────────────────┘

Android Side                 Rust ZHTP Core              iOS Side
─────────────               ─────────────────            ─────────

1. App Start
   │
   ├─► ZhtpNative.initNode()  ────►  create_node()  ◄──── ZhtpClient.initNode()
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ ZhtpNode       │
   │                              │ • node_id      │
   │                              │ • config       │
   │                              │ • peers: {}    │
   │                              └───────┬────────┘
   │                                      │
   ├─► ZhtpNative.startNode()  ────►  start_node() ◄──── ZhtpClient.startNode()
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ ServiceDaemon  │
   │                              │ • mDNS browser │
   │                              └───────┬────────┘
   │                                      │
2. Native Discovery                      │
   │                                      │
WifiP2pManager                            │                MultipeerConnectivity
   │                                      │                         │
   ├─ onPeersAvailable ─────────►        │         ◄───── foundPeer
   │                                      │                         │
   └─► onWifiDirectPeerDiscovered()      │         ZhtpClient.notifyMultipeerPeerDiscovered()
                │                         │                         │
                │                    ┌────▼─────┐                  │
                └───────────────────►│   Add to │◄─────────────────┘
                                     │ peer list│
                                     └────┬─────┘
                                          │
3. Auto-Connect                           │
   │                                      │
   ├─► ZhtpNative.connectToPeer() ──►  connect_to_peer() ◄─── ZhtpClient.connectToPeer()
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ TCP Handshake  │
   │                              │ Authentication │
   │                              │ Key Exchange   │
   │                              │ DHT Register   │
   │                              └───────┬────────┘
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ Connected!     │
   │                              │ peers[peer_id] │
   │                              └────────────────┘

4. Message Sending
   │
   ├─► ZhtpNative.sendMessage() ────►  send_message()  ◄──── ZhtpClient.sendMessage()
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ MeshEnvelope   │
   │                              │ (encrypted)    │
   │                              └───────┬────────┘
   │                                      │
   │                              ┌───────▼────────┐
   │                              │ Protocol Send  │
   │                              │ (TCP/BT/WiFi)  │
   │                              └────────────────┘
```

## Memory Management

```
Android (JNI)                          iOS (C FFI)
─────────────                          ───────────

Java/Kotlin Heap                       Swift ARC
      │                                     │
      │ JNI Boundary                       │ C FFI Boundary
      ├─────────────┐                      ├─────────────┐
      │             │                      │             │
      ▼             ▼                      ▼             ▼
┌─────────┐   ┌─────────┐          ┌─────────┐   ┌─────────┐
│ JString │   │ JObject │          │  *char  │   │  Data   │
└────┬────┘   └────┬────┘          └────┬────┘   └────┬────┘
     │             │                     │             │
     │ Convert     │ Copy                │ Copy        │ Copy
     │             │                     │             │
     ▼             ▼                     ▼             ▼
┌────────────────────┐            ┌────────────────────┐
│   Rust Heap        │            │   Rust Heap        │
│                    │            │                    │
│ • String           │            │ • CString          │
│ • Vec<u8>          │            │ • Vec<u8>          │
│ • Arc<Mutex<T>>    │            │ • Arc<Mutex<T>>    │
│                    │            │                    │
│ (Managed by Rust)  │            │ (Managed by Rust)  │
└────────────────────┘            └────────────────────┘
                                           │
                                           │ Return
                                           │
                                           ▼
                                   ┌──────────────┐
                                   │ CString::raw │
                                   └───────┬──────┘
                                           │
                                           │ MUST free!
                                           │
                                           ▼
                                   zhtp_free_string()

  Automatic cleanup           Manual cleanup required!
```

## Thread Safety Model

```
┌────────────────────────────────────────────────────────────┐
│                     Application Threads                     │
│  (UI Thread, Background Workers, Service Threads)           │
└─────────┬──────────────────┬──────────────────┬────────────┘
          │                  │                  │
          │ FFI Call         │ FFI Call         │ FFI Call
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                         FFI Layer                           │
│              (android.rs / ios.rs / mod.rs)                 │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              │ Lock
                              ▼
                    ┌──────────────────┐
                    │ RUNTIME: Mutex   │ ← Global Tokio Runtime
                    │ Arc<Runtime>     │   (Thread-safe singleton)
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ NODE: Mutex      │ ← Global ZhtpNode Instance
                    │ Arc<Mutex<       │   (Thread-safe singleton)
                    │   ZhtpNode       │
                    │ >>               │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ ZhtpNode         │
                    │ • node_id        │
                    │ • peers: HashMap │
                    │ • status         │
                    │ • service_daemon │
                    └──────────────────┘

 Multiple threads can safely call FFI functions
 Mutex ensures exclusive access to shared state
 Arc enables shared ownership across threads
 Tokio runtime handles async operations
```

## Build Output Structure

```
Android Build Output:                     iOS Build Output:
────────────────────                     ─────────────────

target/android-libs/                      target/ios-framework/
└── jniLibs/                              └── ZhtpFramework.xcframework/
    ├── arm64-v8a/                            ├── ios-arm64/
    │   └── liblib_network.so (6MB)           │   └── ZhtpFramework.framework/
    ├── armeabi-v7a/                          │       ├── ZhtpFramework (5MB)
    │   └── liblib_network.so (5MB)           │       ├── Headers/
    ├── x86_64/                               │       │   └── zhtp.h
    │   └── liblib_network.so (7MB)           │       ├── Modules/
    └── x86/                                  │       │   └── module.modulemap
        └── liblib_network.so (6MB)           │       └── Info.plist
                                              └── ios-arm64_x86_64-simulator/
                                                  └── ZhtpFramework.framework/
                                                      ├── ZhtpFramework (12MB)
                                                      └── ...

Copy to Android Project:                  Add to Xcode Project:
app/src/main/jniLibs/                     Drag & drop .xcframework
                                          Set "Embed & Sign"
```

---

**This diagram shows the complete end-to-end architecture from mobile UI to native protocols! **

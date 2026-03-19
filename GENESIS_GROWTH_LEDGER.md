# ⏱️ GENESIS GROWTH LEDGER: IMMUTABLE SYSTEM CLOCK

This ledger records the structural growth of the Sovereign Network from day one initialization to the MrCakes931 A+ Hardening phase.

| Date | Hash | Milestone / System Evolution |
| :--- | :--- | :--- |
| 2025-11-24 | `a0d071c8` | Initial commit: Complete Sovereign Network mono-repo with all crates and build scripts |
| 2025-11-24 | `7e6f6cf1` | docs: Add comprehensive network deployment and multi-user onboarding documentation |
| 2025-11-24 | `d2f18c2f` | chore: Add node output logs and push instructions |
| 2025-11-24 | `fedba462` | chore: Update lib-proofs submodule reference |
| 2025-11-24 | `2bea1dd3` | chore: Remove problems file |
| 2025-11-24 | `d370b240` | chore: Update .gitignore to exclude problems and runtime data |
| 2025-11-24 | `08c366e1` | chore: Allow Node_print.txt to be tracked |
| 2025-11-24 | `31ffc1b6` | docs: Add FIXED status to resolved issues in problems file |
| 2025-11-24 | `14254adc` | docs: Replace absolute paths with relative paths |
| 2025-11-24 | `ae66a9f1` | feat: Convert crates to monorepo structure |
| 2025-11-24 | `aeeadf9c` | chore: Move internal docs to .gitignore |
| 2025-11-25 | `46a2bd26` | refactor(dht): Add DHTClient type alias and clarify architecture |
| 2025-11-26 | `cc7a6bda` | DHT consolidation complete - all 19 issues fixed |
| 2025-11-26 | `486dd44c` | Remove security audit files from tracking |
| 2025-11-26 | `dd12f9bb` | Add security audit files to gitignore |
| 2025-11-26 | `660a6847` | Update AUTHORS section in README |
| 2025-11-26 | `0832c68c` | fix: resolve runtime nesting panic in DHT initialization |
| 2025-11-26 | `b46b87c9` | feat: add network ping command and connection guide |
| 2025-11-28 | `ef7c130d` | refactor: move crates to root level |
| 2025-11-30 | `7f7a4270` | feat: Port P1-7 seed-anchored identity and proof governance to monorepo |
| 2025-11-30 | `fc48e2c2` | docs: Update README with monorepo structure and git strategy |
| 2025-11-30 | `120bd659` | docs: Add identity and proof architecture to README |
| 2025-11-30 | `c2c554f7` | docs: Update default branch to development in README |
| 2025-11-30 | `1fb7bfc1` | Excludes documentation and project files |
| 2025-11-30 | `5649f5cd` | Simplifies gitignore and adds proof versioning support (#20) |
| 2025-11-30 | `d25f52e9` | fix: Move Bluetooth initialization to background to prevent server startup blocking |
| 2025-11-30 | `fd80efbe` | fix: Move Bluetooth initialization to background to prevent server startup blocking (#21) |
| 2025-11-30 | `f7d58f8c` | fix: Use PublicKey.dilithium_pk field for hex encoding in multi_wallet (#22) |
| 2025-11-30 | `bdd1dc49` | fix: Update storage_integration for P1-7 ZhtpIdentity changes (#23) |
| 2025-11-30 | `d46a8b28` | fix: Update lib-protocols and lib-network for P1-7 ZhtpIdentity changes (#24) |
| 2025-11-30 | `e09e2f4e` | fix(zhtp): Complete P1-7 identity architecture migration - all errors fixed (#25) |
| 2025-12-01 | `fc42e74e` | fix: Device identity age requirement and macOS Bluetooth permissions (#26) |
| 2025-12-01 | `7d4fc61c` | [ALPHA-STEP1] Replace NodeId type alias with lib_identity::NodeId (#83) |
| 2025-12-02 | `33687ad3` | Fix #55: Update DHT routing table to use lib_identity::NodeId (#91) |
| 2025-12-02 | `34d26570` | [ALPHA-STEP1] Fix add_peer to accept identity-derived NodeId parameter (#92) |
| 2025-12-02 | `6fca56e7` | Add NodeId field to bootstrap PeerInfo structure (Issue #57) (#93) |
| 2025-12-02 | `9506d705` | Add NodeId stability integration tests (Issue #58) (#94) |
| 2025-12-02 | `b5e23482` | P1-8: Add multi-device support (#95) |
| 2025-12-02 | `2c8fa7d4` | feat: Add comprehensive unified identity demo example (P1-15) (#96) |
| 2025-12-02 | `ce38bfc9` | [ALPHA-FE-1] Implement signin/login API endpoints for authentication (#103) |
| 2025-12-02 | `a18c78ce` | Implement backup/recovery API endpoints (Issue #100) (#104) |
| 2025-12-02 | `480362ba` | [ALPHA-FE-3] Implement guardian social recovery system (#106) |
| 2025-12-02 | `82cbcb6b` | Implement Zero-Knowledge Proof API Endpoints (Issue #102) (#107) |
| 2025-12-02 | `0f46cef2` | Fix API client path alignment (Issues #7-10) (#109) |
| 2025-12-02 | `dbb50d49` | Add CI workflow (advisory tests) (#114) |
| 2025-12-03 | `af5b4fff` | [Advisory] Restore workspace compilation after API changes (#120) |
| 2025-12-03 | `9a3b82cb` | feat: Add comprehensive exports for DAO, content ownership, etc.. (#97) |
| 2025-12-03 | `c78dc391` | fix(security): Remove fake balance estimation from transaction fees (#123) |
| 2025-12-03 | `ab80b5a4` | Complete guardian social recovery API implementation (Issue #116) (#128) |
| 2025-12-03 | `65804f43` | Complete DAO/Wallet/Network Endpoints with Security Fixes (Issue #118) (#129) |
| 2025-12-03 | `343e7455` | Complete identity backup/recovery endpoints for Issue #115 (#130) |
| 2025-12-04 | `4a163478` | fix: Resolve compilation errors in guardian and DAO handlers (#132) |
| 2025-12-05 | `7fcac76b` | feat: Implement QUIC-first unified protocol handler (#133) |
| 2025-12-05 | `0f7aa9ba` | feat: Implement Unified Handshake Protocol (UHP) - Phase 1-P0 (#209) |
| 2025-12-06 | `62722688` | feat: implement unified peer identity system (Phase 1-P0) (#210) |
| 2025-12-07 | `480d8f30` | Fix lib-storage test suite (#127): Safe IdentityBlob serialization (#212) |
| 2025-12-07 | `732f8709` | Issue #125: Fix 11 lib-blockchain test failures (#213) |
| 2025-12-07 | `4b4d6b5e` | feat(handshake): Implement core UHP handshake I/O layer (#221) |
| 2025-12-07 | `378ff1d0` |  Bootstrap: peer_discovery.rs line 18 - discover_bootstrap_peers() ac… (#122) |
| 2025-12-07 | `22429c77` | Replace recovery phrase XOR with AES-256-GCM (issue #105) (#207) |
| 2025-12-07 | `6e4440c4` | Use deterministic NodeId across lib-storage consistency (issue #28) (#208) |
| 2025-12-07 | `48fdb6dd` | feat: implement blockchain-aware handshake extension (ticket #138) (#214) |
| 2025-12-07 | `a26edf02` | feat: implement TCP bootstrap adapter for UHP (ticket #139) (#215) |
| 2025-12-08 | `8c896171` | feat: implement WiFi Direct UHP handshake adapter (ticket #142) (#216) |
| 2025-12-08 | `582accec` | feat(dht): Migrate DHT from NodeId-only to full peer identity (Ticket… (#217) |
| 2025-12-08 | `20aef5f0` | feat(mesh): Migrate mesh layer from PublicKey-only to full peer ident… (#218) |
| 2025-12-08 | `cd3dcf5e` | feat: Implement unified peer registry (Ticket #147) (#219) |
| 2025-12-08 | `93ca0332` | ci: Add deployment to dev server (#342) |
| 2025-12-08 | `e0509dff` | ci: Add systemd service for auto-start and restart (#343) |
| 2025-12-08 | `dcb30782` | fix(ci): Add retry logic to ssh-keyscan for deploy reliability (#345) |
| 2025-12-08 | `2e0b3953` | fix: disable network isolation by default (#346) |
| 2025-12-09 | `4b9208ce` | fix: add node start command and auto-wallet to systemd service (#347) |
| 2025-12-09 | `7ef12860` | feat(api): Wire up 7 missing identity API endpoints (#348) (#349) |
| 2025-12-09 | `a2c61474` | feat: Add ALPN support to QUIC server for mobile client compatibility (#353) |
| 2025-12-09 | `a06b3ee6` | fix: Add wildcard and additional SANs to QUIC server certificate for handshake compatibility (#354) |
| 2025-12-09 | `b254f94b` | feat(network): Add persistent TLS certificates for Android Cronet compatibility (#355) |
| 2025-12-10 | `d89ebe97` | feat(persistence): Add blockchain file persistence for alpha (#357) |
| 2025-12-10 | `df2d9e33` | fix(rate-limiter): Only count failed attempts, increase limit to 100 (#358) |
| 2025-12-10 | `4e65be18` | fix(lib-dns): Suppress compiler warnings from upstream code (#363) |
| 2025-12-10 | `54600e9f` | [ARCH-D-1.6] Implement QUIC Adapter with PQC - Secure UHP+Kyber Handshake (#364) |
| 2025-12-11 | `37ce5eb2` | feat(network): Migrate mesh to unified peer registry (Ticket #149) (#368) |
| 2025-12-11 | `99f95b83` | feat(peer-registry): Add synchronization with observer pattern (Ticke… (#386) |
| 2025-12-11 | `b5caa4d2` | feat(dht): Migrate to internal peer registry (Ticket #148) (#385) |
| 2025-12-12 | `55c9c723` | feat(network,storage): Implement DHT transport abstraction (Ticket #152) (#370) |
| 2025-12-12 | `9635621a` | feat(network): Migrate bootstrap to unified peer registry (Ticket #150) (#369) |
| 2025-12-12 | `634ba974` | feat(routing): Unify DHT, Mesh, and Graph routing - Ticket #153 (#371) |
| 2025-12-12 | `b7efb18e` | feat(dht): Route DHT traffic through mesh network (Ticket #154) (#387) |
| 2025-12-12 | `ea977389` | Created Unified Discovery (#384) |
| 2025-12-13 | `23ddc6cb` | feat(web4): Implement Web4 HTTP Gateway Phase 1 (#394) |
| 2025-12-13 | `6c07e3b4` | feat(zdns): Implement ZDNS resolver with LRU caching (Phase 2) (#395) |
| 2025-12-13 | `d0290a76` | feat(zdns): UDP/TCP DNS Transport Layer (Phase 3) (#396) |
| 2025-12-13 | `227325ce` | feat(gateway): HTTPS Gateway with TLS support (Phase 4) (#398) |
| 2025-12-13 | `6f6e1302` | feat(web4): Phase 5 - Chunked uploads with limits and TOFU trust verification (#402) |
| 2025-12-13 | `c3772c56` | feat(web4): Domain versioning with atomic updates, history, and rollback (#403) |
| 2025-12-13 | `a639323a` | fix(quic): rustls CryptoProvider + CLI QUIC migration + Device identity (#404) |
| 2025-12-13 | `086781ec` | fix(cli): Add ALPN protocols and separate keystore for QUIC clients (#405) |
| 2025-12-13 | `3a70e65c` | feat(quic): ALPN-based protocol routing for UHP control plane (#406) |
| 2025-12-14 | `dea095de` | fix(handshake): Remove duplicate verify_signature call causing nonce replay |
| 2025-12-14 | `273e4039` | fix(handshake): Remove duplicate verify_signature call causing nonce replay (#407) |
| 2025-12-14 | `937ff221` | fix(quic): Use CBOR wire protocol for authenticated control plane streams |
| 2025-12-14 | `d58cf580` | Merge pull request #408 from SOVEREIGN-NET/fix/wire-protocol-cbor |
| 2025-12-14 | `04a35dd5` | fix(handshake): Use consistent node ID for master key derivation |
| 2025-12-14 | `71d1f876` | Merge pull request #409 from SOVEREIGN-NET/fix/session-id-mismatch |
| 2025-12-14 | `40cf62bc` | debug: Add logging for master key derivation inputs |
| 2025-12-14 | `e95cc8ba` | Merge pull request #410 from SOVEREIGN-NET/debug/session-id-mismatch |
| 2025-12-14 | `95854526` | fix(crypto): Fix Kyber KDF info mismatch causing session ID divergence (#411) |
| 2025-12-14 | `1b811e17` | feat(identity): Auto-register peer identities on authenticated QUIC handshake (#412) |
| 2025-12-14 | `33757dc5` | feat(web4): Allow .sov TLD in domain registration |
| 2025-12-14 | `aa13ad2b` | Merge pull request #413 from SOVEREIGN-NET/feature/sov-tld-domain-validation |
| 2025-12-14 | `f5ba35e2` | fix: Install rustls crypto provider at startup (#414) |
| 2025-12-14 | `b03813df` | feat(quic): Add zhtp-public/1 ALPN for unauthenticated public content access (#415) |
| 2025-12-14 | `40f734f3` | fix(quic): Allow all public endpoints on zhtp-public/1 (#416) |
| 2025-12-14 | `727280a6` | fix(web4): Share domain registry between unified server and Web4Handler (#417) |
| 2025-12-14 | `160a5bbe` | debug: Add logging to public ALPN resolve path (#418) |
| 2025-12-14 | `2ce56871` | fix(web4): Implement content-addressed storage for Web4 manifests and blobs (#419) |
| 2025-12-16 | `647aa2cd` | feat: Persistent Storage with Security Hardening (#425) |
| 2025-12-16 | `70d52ea9` | feat(node): Add persistent identity keystore for node startup (#427) |
| 2025-12-16 | `bcd52061` | fix(identity): Add custom serde for HashMap<CredentialType, ZkCredential> (#428) |
| 2025-12-16 | `9a676ee3` | chore(deploy): Update service to use testnet and persistent identity (#429) |
| 2025-12-16 | `5a1f7eab` | fix(identity): Add serde string key serialization for WalletManager HashMap (#430) |
| 2025-12-16 | `5b1cc20d` | feat(blockchain): Add mining profiles for environment-aware difficulty (#432) |
| 2025-12-16 | `01082096` | fix(mining): Use mining profile difficulty for block creation (#434) |
| 2025-12-16 | `34a5bee3` | fix(identity): Critical identity persistence and QUIC fixes (#435) |
| 2025-12-16 | `d595be62` | fix(identity): Properly load node identity with private key (#439) |
| 2025-12-17 | `95fc8dbf` | fix(handshake): Remove per-open epoch increment causing handshake failures (#440) |
| 2025-12-17 | `81eff7d0` | fix(identity): Correct DID/ID validation for seed-anchored identities (#442) |
| 2025-12-17 | `4c6e9530` | fix(blockchain): Use mining profile for difficulty validation (#443) |
| 2025-12-17 | `2cc41d39` | feat(identity): Persist identity records to DHT for fast lookups (#444) |
| 2025-12-17 | `ced0a283` | fix: Blockchain and DHT persistence paths (#445) |
| 2025-12-17 | `b2bbf027` | fix: Persist blockchain after every block (not every 5) (#446) |
| 2025-12-17 | `854ac92b` | Update issue templates (#448) |
| 2025-12-17 | `833eae44` | ci: Add release workflow for binary distribution (#449) |
| 2025-12-17 | `c94ba5c0` | ci: Split deployments for main (production) and development (dev) (#450) |
| 2025-12-17 | `3e71a40b` | Fix typo in ZHTP description (#383) |
| 2025-12-17 | `2045cfee` | feat: Merge blockchain sync managers with strategy pattern (#164) (#420) |
| 2025-12-19 | `14577599` | feat: resolve lib-network ⟷ lib-storage circular dependency (#461) |
| 2025-12-19 | `d9aa1423` | feat: add SonarCloud integration (#465) |
| 2025-12-20 | `7315ec26` | feat: add manual workflow trigger with deploy option (#467) |
| 2025-12-20 | `9ff633cb` | fix: allow manual trigger to deploy to dev server (#468) |
| 2025-12-20 | `bab6d74c` | ci: Add dev-specific service file with bootstrap mode (#451) |
| 2025-12-20 | `0836e1b7` | feat(lib-network): add PQC support with Kyber1024 and Dilithium5 (#352) |
| 2025-12-20 | `2cdb7368` | feat(network): Consolidate get_local_ip implementations (Ticket #157) (#390) |
| 2025-12-20 | `17b98c25` | feat(network): Define unified Protocol trait for all mesh transports (#393) |
| 2025-12-21 | `c9c54fd6` | 148 arch d 114 migrate dht to use unified peer registry (#460) |
| 2025-12-21 | `57c1671e` | feat(network): Add BLE GATT adapter with UHP framing (#476) |
| 2025-12-21 | `70a89631` | fix: consolidate address resolution into unified AddressResolver (#463) |
| 2025-12-22 | `34f70745` | perf(network): Implement single-pass mesh message serialization (#480) |
| 2025-12-22 | `460e3e0c` | docs: add BUILDING.md with platform-specific build instructions (#483) |
| 2025-12-22 | `9c4a31eb` | 156 arch d 22 fix hardware capabilities name collision (#388) |
| 2025-12-22 | `63325726` | feat(blockchain-sync): Replace SHA256 with Blake3 and add stricter security (#485) |
| 2025-12-22 | `dc20f0d2` | fix: address 7 critical and high-priority security vulnerabilities from audit (#486) |
| 2025-12-23 | `39a1f357` | fix: Remove redundant multicast listener from discovery_coordinator.rs (Issue #498) (#499) |
| 2025-12-23 | `e53b18e2` | docs: Complete QUIC encryption defense-in-depth documentation (Issue #492) (#501) |
| 2025-12-23 | `f27c7208` | docs: update network configuration - correct ports and add comprehensive guide (#496) |
| 2025-12-23 | `74b53848` | fix: Reduce log noise for expected UDP socket timeouts during idle (Issue #494) (#502) |
| 2025-12-22 | `7b106e3a` | feat(lib-blockchain): add DAO types module with DAOType enum and token classes (#350) |
| 2025-12-23 | `91dc7454` | Fully replaced the zhtp-orchestrator name for the binarry with zhtp (#497) |
| 2025-12-23 | `036019e4` | fix(discovery): Replace TCP with QUIC and upgrade handshake protocol to UHP v2 (Issue #504) (#507) |
| 2025-12-23 | `124aa37f` | refactor: Split monolithic BluetoothMeshProtocol into 25+ functional modules (#509) (#510) |
| 2025-12-23 | `af446931` | fix: Remove windows-bluetooth from default features to fix Ubuntu compilation (Issue #506) (#511) |
| 2025-12-25 | `615e5c7b` | Issue #490: Unified Protocol Encryption Architecture (#514) |
| 2025-12-26 | `90fefb1e` | feat(zhtp): Implement ZHTP Post-Quantum Encryption and Mesh Encryption Adapter (#516) |
| 2025-12-26 | `8cf3c47c` | fix: Add execute permissions to shell scripts for Ubuntu compatibility (Issue #512) (#517) |
| 2025-12-26 | `a24f8bc5` | refactor(lib-network): Achieve 100% architecture compliance by eliminating std::env and std::process usage (Issue #482) (#518) |
| 2025-12-27 | `3f2c75a5` | fix: Complete CLI extraction tests and centralize keystore file naming (Issue #422) (#531) |
| 2025-12-27 | `a243005a` | Fix: Remove unused mut qualifiers in deploy and domain commands (Issue #532) (#533) |
| 2025-12-27 | `c88361b6` | fix(deploy): Validate manifest CID consistency during upload (#534) |
| 2025-12-29 | `3e028949` | fix(web4): Complete canonical manifest architecture with test verification (#536) |
| 2025-12-29 | `557a0469` | feat(github): Add standardized issue templates with clear prefixes (#541) |
| 2025-12-29 | `8c29135f` | docs(community): Add v0.2.0 community testing guide and announcements (#542) |
| 2025-12-29 | `84bb933f` | perf(lib-network): Implement ZHTP single-pass serialization with secu… (#493) |
| 2025-12-29 | `08184cf1` | Feat/v0.2.0 community announcement (#543) |
| 2025-12-30 | `c7454a34` | PR#508 Code Review Fixes: Message Routing Centralization + QUIC-Only Architecture (#547) |
| 2025-12-30 | `5829c655` | Optimize identity violation tracking in blockchain broadcast (#548) |
| 2025-12-30 | `6b00436e` | [WIP] Update message routing and QUIC-only architecture (#549) |
| 2025-12-30 | `36e5f25d` | fix: Clean up unused imports in lib-network and reduce warning noise (#550) |
| 2025-12-30 | `f73c0474` | Add Copilot instructions for repository context and conventions (#559) |
| 2025-12-30 | `7ae851ad` | feat(lib-consensus): Implement ConsensusMessageCodec for deterministic serialization (#561) |
| 2025-12-30 | `8c5c6627` | fix: Add 'quic' to all node configuration protocol lists (#563) |
| 2025-12-30 | `994d4acf` | Refactor ZhtpUnifiedServer: Extract NodeRuntime + Security Fixes (#557) |
| 2025-12-30 | `b03c86d5` | ci: Skip macOS build on pull requests, run only on pushes (#565) |
| 2025-12-30 | `6bd03afc` | feat(lib-network): Implement ConsensusMessageEncryption using ChaCha20Poly1305 (Gap 1.3) (#564) |
| 2025-12-31 | `98e1c516` | feat(consensus): Integrate MessageBroadcaster into ConsensusEngine (CONSENSUS-NET-21) (#567) |
| 2025-12-31 | `62697a42` | Complete Gap 3: Endpoint selection and routing for validator discovery (#568) |
| 2025-12-31 | `7af982cc` | feat(lib-network): Implement ConsensusReceiver (Gap 4) (#569) |
| 2025-12-31 | `961099ba` | fix(consensus): Implement safety/liveness invariants (CE-S1, CE-L1, CE-L2) (#570) |
| 2026-01-02 | `08c8ae7e` | Add restart determinism integration tests (issue #68) (#572) |
| 2026-01-02 | `eafff27f` | Fix Windows Bluetooth build errors (#579) |
| 2026-01-02 | `0df9d729` | [ALPHA-STEP2] Add mesh integration tests for deterministic NodeIds (#580) |
| 2026-01-02 | `449a4c06` | refactor: Remove HTTP/1.1 compatibility layer and fix 18 compiler warnings (#581) |
| 2026-01-02 | `543c600d` | [ALPHA-STEP2] Mesh NodeId integration tests (#575) |
| 2026-01-02 | `977f616f` | fix(bluetooth): Remove duplicate BLE_MESH_SERVICE_UUID import (#585) |
| 2026-01-02 | `52c6064f` | [ALPHA-STEP3] Use unified identity init for node startup (#576) |
| 2026-01-02 | `ea72c139` | [CONSENSUS-NET-4.3] Harden remote vote validation and fix critical safety bugs (#587) |
| 2026-01-02 | `1977fca7` | fix: rename _request to request in check_https function (#588) |
| 2026-01-02 | `08b17e1c` | CONSENSUS-NET-5: Implement Validator Heartbeat and Liveness Tracking (#589) |
| 2026-01-03 | `d3b0ef0c` | [CONSENSUS-NET-43] Implement Validator Liveness Monitor and Consensus Stall Detection (#590) |
| 2026-01-03 | `f3b1e296` | feat(Gap 6): Byzantine Fault Detector Evidence Production (#591) |
| 2026-01-04 | `1e907763` | CONSENSUS-NET-61: Byzantine Fault Detector Evidence Production with Error Handling (#602) |
| 2026-01-03 | `35c263a8` | [ALPHA-STEP2] Add mesh NodeId integration tests (#574) |
| 2026-01-04 | `28fe415f` | Fix #65: Derive NodeId at startup from DID + device name (#583) |
| 2026-01-04 | `88cea13c` | Fix Windows RFCOMM connection tracking (#603) |
| 2026-01-05 | `22324873` | feat(SOV-L0-1.1): Correct SOV Economic Constants and Refactor DAO Treasury (#625) |
| 2026-01-05 | `17a9ab34` | feat: Extend Byzantine Fault Detector with Network Anomaly Detection and Consensus Engine Improvements (#624) |
| 2026-01-05 | `308e6335` | fix: On-chain cryptographic signature verification in Emergency Reserve (SOV-L0-1.2) (#633) |
| 2026-01-06 | `41069fa8` | tests(e2e): add Web4 CLI E2E suite for issue #537 |
| 2026-01-06 | `d21b006d` | tests(lib-network): add deterministic mesh integration tests, scripts, and workspace test runner |
| 2026-01-06 | `9863049c` | feat: implement SovSwap AMM contract for SOVDAO token swaps (#635) |
| 2026-01-06 | `96c78d77` | Merge pull request #638 from SOVEREIGN-NET/feat/tests/lib-network-mesh |
| 2026-01-06 | `0ddf5eae` | feat(dao_registry): Implement DAO Registry contract with identity and registration features (#636) |
| 2026-01-08 | `30c12934` | feat: Implement Development Grants Fund contract (SOV-L0-2.3) - Phase 2 Complete (#649) |
| 2026-01-09 | `4f76ac00` | Fix restart-safety alert manager and node identity tests (#651) |
| 2026-01-09 | `5a95f6ae` | fix: Bootstrap QUIC port mismatch & implement authoritative protocol filtering (#654) |
| 2026-01-09 | `66f6119a` | fix: Resolve compilation errors in mesh test utilities (#659) |
| 2026-01-09 | `0c7c57dd` | fix: Resolve mesh integration test issues and disable network tests by default (#662) |
| 2026-01-09 | `2cbae638` | Refactor: Move difficulty adjustment ownership to lib-consensus (#641) |
| 2026-01-09 | `225310fe` | Fix: Use configured mesh_port for node-to-node QUIC communication (#673) |
| 2026-01-09 | `d941f14e` | fix: remove duplicate DifficultyConfig import from lib_consensus (#675) |
| 2026-01-09 | `6f1d183b` | feat(lib-blockchain): Add DifficultyConfig struct for adaptive diffic… (#652) |
| 2026-01-10 | `c699059f` | fix(handshake): Implement network epoch and persistent replay protection (PR #542) (#653) |
| 2026-01-10 | `fa8fbac6` | fix: Add missing NetworkEpoch argument to NonceCache::open_default in test (#692) |
| 2026-01-10 | `0eb46a15` | fix: Add missing error macro import to wifi.rs (#693) |
| 2026-01-10 | `92612917` | fix: Extract bootstrap peers from NodeConfig into DiscoveryConfig (#694) |
| 2026-01-11 | `20851a5e` | feat(lib-storage): Implement DHT message signing and verification (#676) (#696) |
| 2026-01-11 | `2e568718` | feat(lib-storage): Add ZK proof verification timeouts [DB-002] (#697) |
| 2026-01-11 | `c829ff80` | feat(dht): add per-peer sequence tracking (#695) |
| 2026-01-11 | `a731b3da` | [DB-004] Replace RocksDB dependency with sled (#702) |
| 2026-01-11 | `b021e424` | feat(lib-network): Migrate nonce cache from RocksDB to sled [DB-005] (#703) |
| 2026-01-11 | `31cf479d` | feat(lib-network): Add batch operations to nonce cache [DB-006] (#707) |
| 2026-01-12 | `8dfd8a4c` | [DB-007] Create StorageBackend trait abstraction (#708) |
| 2026-01-12 | `96efdc6a` | feat(lib-storage): Implement SQLite StorageBackend for structured data [DB-009] (#709) |
| 2026-01-12 | `79bf4db3` | feat(lib-storage): Implement sled StorageBackend [DB-008] (#710) |
| 2026-01-12 | `b7214fd5` | fix: Remove hardcoded bootstrap peers and fix configuration (#716) |
| 2026-01-12 | `ea841f3f` | feat(lib-storage): Complete DB-010 - Migrate DHT Storage to Backend Trait (#714) |
| 2026-01-12 | `fc03f29c` | Enable deployment to dev servers and fix bootstrap peer configuration (#721) |
| 2026-01-12 | `a028b868` | fix(lib-network): Implement NonceCache singleton pattern [DB-013] (#719) |
| 2026-01-12 | `09fc33f9` | feat(lib-storage): Replace println! with tracing in DHT module [DB-011] (#717) |
| 2026-01-12 | `8a82af28` | Unify DhtPeerIdentity in lib-identity (#718) |
| 2026-01-12 | `fee3f415` | fix(protocols): Add detailed error logging for component initialization (#723) |
| 2026-01-12 | `1376d287` | fix(lib-network): Remove unused rocksdb dependency [DB-005] (#679) (#724) |
| 2026-01-12 | `e7e84210` | 627 featlib blockchain add dao proposaltype for difficulty parameter updates (#674) |
| 2026-01-12 | `781c1f45` | fix: Resolve compilation errors and warnings - Jan 12 (#730) |
| 2026-01-12 | `34f44193` | Add comprehensive DHT message signing tests (#726) |
| 2026-01-12 | `39753f3a` | feat(lib-storage): Add comprehensive backend integration tests [DB-014] (#725) |
| 2026-01-12 | `4b69f2f8` | feat(storage): Add comprehensive load tests [DB-016] (#727) |
| 2026-01-12 | `27d3f97a` | Add root registry scaffolding and resolver facade (#728) |
| 2026-01-12 | `6a7de9ca` | fix: Extract DomainRecord from DomainLookupResponse in name resolver (#732) |
| 2026-01-12 | `d4a13cf9` | Fix discovery to use bootstrap peers before genesis (#733) |
| 2026-01-12 | `1982292c` | feat(storage): Enable persistent DHT storage with SledBackend (#734) |
| 2026-01-13 | `cc85800b` | Use persistent storage for monitoring stats (#735) |
| 2026-01-13 | `8a50e31e` | feat(lib-blockchain): Add root_registry module for .sov naming system (#655) (#729) |
| 2026-01-13 | `f8d0dc03` | Use global blockchain provider for identity registration (#737) |
| 2026-01-13 | `7a262ef2` | fix(network): Add MeshTrustUhp mode for storage provider sharing (#738) |
| 2026-01-13 | `2d7ea54f` | feat(security): Implement QUIC/TLS certificate pinning via DHT discovery (#740) |
| 2026-01-13 | `f2e7c8cf` | Feature/lib blockchain implement difficulty parameter update execution in block processing (#731) |
| 2026-01-13 | `abcbc5a3` | feat(security): Add PinnedCertVerifier for production-safe TLS pinning (#741) |
| 2026-01-13 | `1f1dfdf9` | Add SOV Unified Implementation Base (#742) |
| 2026-01-13 | `69fa22ab` | feat(sov): Implement Week 2 Governance, Treasury, and Tribute Contracts (#745) |
| 2026-01-13 | `2fa5ab43` | fix(cli/runtime): QUIC port config and genesis fallback on sync failure (#749) |
| 2026-01-13 | `6c33ae2d` | Week 3: DAO Treasury and Sunset Contracts (#746) |
| 2026-01-13 | `1f57d89d` | Week 4: Documentation - Implementation Plan Updated (#747) |
| 2026-01-13 | `b495ca81` | feat(contracts): Phase 3 Welfare Issuer Adapter (Issue #658) (#748) |
| 2026-01-13 | `eea12d24` | Week 5: Large-Scale UBI Distribution Testing (#750) |
| 2026-01-14 | `ba6a3f77` | Week 7: Consensus Fee Integration & SOV Transaction Types (92% Complete) (#754) |
| 2026-01-14 | `b63bebdd` | Week 8: Performance Validation & Scale Testing (Setup) (#755) |
| 2026-01-14 | `a90a33a4` | Week 9: Full Transaction Execution Layer Implementation (617 tests) (#756) |
| 2026-01-14 | `a876b441` | Week 10: Complete Transaction Execution in Blocks (4 Phases, 14 Tests) (#761) |
| 2026-01-14 | `38ad0ab7` | Refactor adjust_difficulty() to use DifficultyConfig instead of hardcoded constants (#763) |
| 2026-01-14 | `daeb6f3f` | fix(deploy): Add --config flag to systemd service templates (#764) |
| 2026-01-14 | `8ed9def4` | Feature/lib blockchain add comprehensive difficulty parameter tests (#765) |
| 2026-01-14 | `fbb5d5e8` | Week 11: Fee Distribution Pipeline Integration (Complete - 4 Phases, 15 Tests, 617 Passing) (#762) |
| 2026-01-14 | `e0d99835` | Week 10 Phase 1: Transaction Extraction & Audit Trail (Per-TX Fee Tracking) (#767) |
| 2026-01-14 | `4be3ff3a` | Issue #617: Complete Fee Distribution Integration into Consensus Engine (#772) |
| 2026-01-14 | `3cb4f909` | Blockchain Operational Implementation: All 4 Phases Complete (Receipts, Contract State, Economic Features, API Endpoints) (#774) |
| 2026-01-14 | `eb778214` | test: Web4 CLI Complete Functional Testing (Domains & Deployments) #537 (#647) |
| 2026-01-14 | `02f898fe` | SOV Management CLI Commands (Issue #622) (#777) |
| 2026-01-14 | `455c15cc` | Phase 1: Complete All 5 Critical Blockchain Issues (#779) |
| 2026-01-14 | `8e19a2eb` | Phase 2: Issues #6-8 - Fork Detection, UTXO Snapshots, Call Depth Limits (#781) |
| 2026-01-14 | `4c354ebb` | feat(issue-9): Complete token persistence consistency implementation (#783) |
| 2026-01-14 | `d1939158` | feat(fee-router): Complete pool addresses configuration (Issue #10) (#784) |
| 2026-01-14 | `1156788d` | \Add comprehensive documentation for difficulty parameter governance system (#780) |
| 2026-01-15 | `3e3f8d7b` | feat(phase-2): Complete Issues #11-13 - Events, Serialization, Byzantine Evidence (#788) |
| 2026-01-15 | `032e0f59` | Phase 1: SOV Staking Contract for DAO Launches (#SOV_SWAP_001) (#794) |
| 2026-01-15 | `31689dc6` | Phase 2: LP Positions & Three-Stream Reward Distribution (#SOV_SWAP_002) (#795) |
| 2026-01-15 | `6de7ad77` | feat(brokerage): DAO token buyback and direct sale mechanisms (#3/4) (#796) |
| 2026-01-15 | `b7023307` | feat(employment): Employment contract registry with tax and profit-sharing (#4/5) (#797) |
| 2026-01-15 | `41e3af43` | feat(launch): DAO launch orchestrator for end-to-end DAO creation (#5/5) - FINAL (#798) |
| 2026-01-15 | `bcd06155` | fix(ubi): Resolve 5 critical distribution issues (#799) |
| 2026-01-15 | `89556535` | feat: implement node type-based service guards for mining/validation (#787) |
| 2026-01-16 | `9c721ec5` | fix(storage): Use directory paths for sled databases (#801) |
| 2026-01-16 | `119b0bba` | fix(mesh-discovery): Eliminate redundant hardware detection scans (#802) |
| 2026-01-16 | `5936a131` | feat: Implement production-ready TypeScript SDK for ZHTP/Web4 API (sdk-ts v1.0.0) |
| 2026-01-16 | `6a324707` | fix(cli): Migrate all CLI commands from HTTP to QUIC protocol (#803) |
| 2026-01-16 | `ad9a1074` | feat: Implement production-ready TypeScript SDK for ZHTP/Web4 API (sdk-ts v1.0.0) (#805) |
| 2026-01-16 | `731ae59f` | docs: Move internal documentation to privateDocs folder (#807) |
| 2026-01-16 | `f7ff70df` | feat(sdk-ts): Implement production-ready TypeScript SDK for ZHTP/Web4 API (#806) |
| 2026-01-16 | `035fa9aa` | feat(sdk-ts): Phase 3 - Real QUIC Transport + Real Post-Quantum Cryptography (#809) |
| 2026-01-16 | `fca8eb54` | fix(runtime): Add wallet welcome bonus, blockchain persistence, and QUIC stream fix (#810) |
| 2026-01-17 | `0c140775` | feat(lib-network): Add handshake-only feature for iOS FFI builds (#812) |
| 2026-01-17 | `6afe3d97` | feat(sdk-ts): Implement DeployManager and ContentManager for site deployment (#814) |
| 2026-01-17 | `e8136b46` | fix(ci): Clear nonce caches before restart to prevent sled DB corruption (#815) |
| 2026-01-18 | `64cb16b7` | feat(security): Implement UHP v2 session authentication with HMAC-SHA3-256 (#816) |
| 2026-01-18 | `1e51e754` | fix(uhp-v2): Fix session key derivation and counter validation bugs (#817) |
| 2026-01-18 | `62079abd` | feat(sdk-ts): Align MAC computation with Rust UHP v2 implementation (#818) |
| 2026-01-18 | `f0db3891` | feat: UHP v2 handshake (SDK-TS) + GOLDEN_RULES.md + security cleanup (#820) |
| 2026-01-18 | `e48a04b7` | fix(ci): Deploy zhtp node binary instead of zhtp-cli (#822) |
| 2026-01-19 | `3d66c8af` | feat(wire): Add CBOR/JSON support for ZHTP wire protocol (#823) |
| 2026-01-19 | `b88b2f2b` | feat(crypto): Add Dilithium5 signature support and lib-client library (#824) |
| 2026-01-19 | `0cacb58b` | feat(lib-client): Add C FFI exports for iOS without uniffi-bindgen (#825) |
| 2026-01-20 | `297ca7fc` | fix: Identity validation, storage singleton, and iOS handshake compatibility (#827) |
| 2026-01-22 | `c95f4848` | fix: Wallet balance sync, testnet validator stake, and iOS QUIC debugging (#835) |
| 2026-01-22 | `04081831` | fix: Remove malformed authentication_wrapper. file from Git index (#839) |
| 2026-01-22 | `e9e4dabf` | fix: Store dilithium_pk with PrivateKey for transaction signing (#837) |
| 2026-01-23 | `36a3e587` | Prepare deploy script for CI (#847) |
| 2026-01-23 | `add47545` | Sdk deploy pr (#848) |
| 2026-01-23 | `4582d629` | Sdk randombytes fix (#849) |
| 2026-01-23 | `11365144` | Add Linux-only release workflow for zhtp-cli (#861) |
| 2026-01-24 | `c8ee4227` | Add reusable deploy-site workflow for Web4 deployments (#883) |
| 2026-01-24 | `996da0c8` | Remove invalid --no-absolute-names tar option (#893) |
| 2026-01-24 | `9045929d` | feat(#841): Implement persistent contract storage with crash recovery (#860) |
| 2026-01-24 | `20317d3d` | Fix deploy-site workflow CLI arguments (#894) |
| 2026-01-24 | `97d830e0` | Fix deploy-site workflow CLI arguments (#895) |
| 2026-01-24 | `b5415b3d` | Add workflow_dispatch trigger to deploy-site (#896) |
| 2026-01-24 | `08f3a23e` | Simplify deploy-site workflow (#897) |
| 2026-01-24 | `0e46abc6` | Fix deploy-site as reusable workflow (#898) |
| 2026-01-24 | `2bb27465` | Restore all workflow features (#899) |
| 2026-01-24 | `b2fb83fc` | Add workflow_dispatch for manual execution (#900) |
| 2026-01-20 | `c18ed2bd` | Harden node identity initialization |
| 2026-01-21 | `72f91730` | fix: Add system dependencies and Rust toolchain to SonarCloud workflow |
| 2026-01-23 | `1d20112c` | fix(ci): Add Clippy run step and remove trailing-dot file |
| 2026-01-24 | `41058c19` | security: Add audit logging and remove redundant env var read |
| 2026-01-24 | `4b695254` | Remove workflow_dispatch - use caller workflows for manual execution (#903) |
| 2026-01-25 | `5f713d93` | Add server env vars to deploy step (#904) |
| 2026-01-25 | `cd7c572f` | fix: pass SPKI as CLI argument for QUIC connection (#905) |
| 2026-01-25 | `62adbbd3` | feat(#843): ABI Standardization System - Complete Implementation (#901) |
| 2026-01-25 | `98300dd9` | fix: Set fee to 0 for wallet registration system transactions (#906) |
| 2026-01-25 | `3407f40f` | fix: fallback to --trust-node when SPKI not provided (#908) |
| 2026-01-26 | `561dd91b` | feat(#842): Cross-Contract Call Infrastructure - Complete Implementation (#910) |
| 2026-01-26 | `28c9059c` | fix(#907): Register QUIC mesh peers in MeshRouter for block broadcasting (#909) |
| 2026-01-26 | `9f1ffce9` | feat(#844): UBI Distribution - Complete Prep Phase (#914) |
| 2026-01-26 | `0081d2a4` | feat(#844): Phase C - UBI Distribution Treasury Kernel Client Implementation (#918) |
| 2026-01-27 | `950d415b` | feat(#844): Treasury Kernel Implementation - All 7 Phases Complete (#919) |
| 2026-01-27 | `108a002d` | fix(#916): Forward received block/tx announcements from lib-network to zhtp (#917) |
| 2026-01-27 | `7854a2e3` | fix(#837): Resolve dilithium_pk and UBI test compilation issues (#921) |
| 2026-01-27 | `d044d676` | fix(#922): Enforce SPKI pinning for bootstrap peer TLS certificates (#923) |
| 2026-01-27 | `ab561be7` | feat(#167): Wire protocol handlers to storage - TransportManager integration (#924) |
| 2026-01-27 | `a2fc7e05` | fix(#920): Resolve post-bootstrap sync issues — wallet balances, nonce cache, DHT persistence (#926) |
| 2026-01-28 | `a4525a33` | feat(#851): Treasury Kernel M1 — Single Balance Mutation Authority (#927) |
| 2026-01-28 | `75b1e575` | feat(#852): Treasury Kernel M2 — Mint/Burn Authority Lockdown (#929) |
| 2026-01-28 | `6d044c01` | feat(#853): Treasury Kernel M3 — Vesting & Time Locks (#930) |
| 2026-01-28 | `812c082b` | feat(#854): Treasury Kernel M4 — Role Registry + Assignment Snapshots (#932) |
| 2026-01-28 | `aef44029` | feat(#855): Treasury Kernel M5 — Cap Ledger Enforcement (#934) |
| 2026-01-28 | `2b8317e1` | feat(#856): Treasury Kernel M6 — Metric Book + Epoch Finality (#945) |
| 2026-01-28 | `be5c6232` | feat(#857): Treasury Kernel M7 — Compensation Engine Activation (#958) |
| 2026-01-28 | `b2f8703c` | feat(#858): Treasury Kernel M8 — Governance Execution Completion (#960) |
| 2026-01-28 | `5472c40c` | Add BFT finality issue templates (#962) |
| 2026-01-28 | `2e30ff40` | fix: Replace DefaultHasher with BLAKE3 for deterministic computation hashing (#969) |
| 2026-01-28 | `33c6506e` | Fix/831 bug domain validation rejected subdomains (#928) |
| 2026-01-29 | `92b692bc` | Wire MeshRouter to ConsensusEngine for multi-node BFT (#991) |
| 2026-01-30 | `96b2b9a6` | feat: SOV Token Completion - Fee Deduction, UBI Minting, Treasury Balance (#1016, #1017, #1018) (#1019) |
| 2026-01-30 | `84235e78` | feat: Token API with session-based authorization (#1022) |
| 2026-01-30 | `64d2e837` | feat(security): Decouple token operations from identity registration (#1023) |
| 2026-01-31 | `d24e450c` | fix: Remove redundant permissions check from token handler (#1024) |
| 2026-01-30 | `940d7df5` | feat(#64): Add encrypted seed storage module (#1027) |
| 2026-01-30 | `217e67d3` | refactor(tests): Deduplicate test helpers across lib-network and lib-identity (#1029) |
| 2026-01-30 | `25b4b707` | fix(#846): Block sync fix - register QUIC peers in MeshRouter |
| 2026-01-30 | `d9bd1752` | feat: Restore network tests with common_network_test module |
| 2026-01-30 | `83566561` | feat(#878): NODE-PoUW Phase 1 - Challenge Generation |
| 2026-01-30 | `b265358d` | feat(pouw): Phase 2 Receipt Validation + Phase 3 Reward Calculation |
| 2026-01-31 | `a4c276d3` | Revert: PRs #1030, #1031, #1032, #1033 merged without human review (#1034) |
| 2026-01-31 | `1b867869` | fix(lib-client): Import canonical types for bincode compatibility (#1039) |
| 2026-01-31 | `f773cb7e` | fix(token-tx): Use all-zero key_id in zeroed signature (#1040) |
| 2026-02-01 | `9b6a433d` | fix(persistence): Versioned blockchain storage + token fixes (#1061) |
| 2026-02-01 | `b8362b90` | fix(lib-network): Resolve platform-specific compilation errors (#1063) |
| 2026-02-01 | `d9cbb04a` | fix(build.rs): Use TARGET env var for cross-compilation framework detection (#1065) |
| 2026-02-01 | `830b3639` | fix: Prevent blockchain data loss on file corruption (#1067) |
| 2026-02-01 | `685cafff` | fix(token): Handler param types + post-quantum fee calculation (#1066) |
| 2026-02-01 | `2387e747` | feat(runtime): Implement canonical startup methods for Issue #454 (#1070) |
| 2026-02-01 | `390c6511` | fix(#846): Block sync fix - register QUIC peers in MeshRouter |
| 2026-02-01 | `7bd13fff` | feat(#878): NODE-PoUW Phase 1 - Challenge Generation |
| 2026-02-01 | `cbd6fb32` | feat: Network integration tests |
| 2026-02-01 | `07ada61a` | feat(#879, #880): NODE-PoUW Phase 2+3 - Receipt Validation + Rewards |
| 2026-02-01 | `b0c346bd` | feat(#881): Phase 4 - Security Hardening and Monitoring |
| 2026-02-01 | `d7342e96` | feat(#882): Phase 5 - Stress Testing and Production Readiness |
| 2026-02-01 | `f438f346` | fix: Deduplicate mesh formation test logic for SonarCloud compliance |
| 2026-02-02 | `f0b6e912` | feat(lib-blockchain): Incremental blockchain storage refactor (Phases 2-3) (#1071) |
| 2026-02-02 | `7ab87235` | fix: Add missing Transaction fields and make sled non-optional (#1073) |
| 2026-02-02 | `a8baf4d3` | fix: Calculate token transaction fee dynamically based on serialized size (#1074) |
| 2026-02-02 | `6e14eb01` | feat(consensus-core): Snapshot V2 with DID identity support (#1075) |
| 2026-02-02 | `a4debfe0` | fix: Correct is_system_transaction logging for token contracts (#1076) |
| 2026-02-02 | `4a53b4af` | feat: Enforce centralized Web4 deployment configuration (#1077) |
| 2026-02-02 | `66414176` | feat(identity): Complete DID seed recovery implementation (#1083) |
| 2026-02-03 | `2b4c4248` | feat(lib-client): Add generic contract transaction builder (#1084) |
| 2026-02-02 | `a872835b` | feat(#1078): Web4 Deployment Workflow & Documentation (#1080) |
| 2026-02-02 | `b452e175` | fix(#1078): Update deploy-site.yml SHA to development commit (#1086) |
| 2026-02-02 | `d4c653a6` | fix(#1078): Add ZHTP_SERVER and ZHTP_SERVER_SPKI secrets to deploy workflow (#1087) |
| 2026-02-02 | `0cc6449f` | chore: Update deploy-site.yml SHA to d4c653a (#1088) |
| 2026-02-03 | `c73a2311` | feat(lib-client): Add generic contract transaction builder (#1089) |
| 2026-02-03 | `5f1e526c` | fix: Token fee deduction and domain registration signing (#1079) |
| 2026-02-03 | `94f57f86` | feat(web4): Charge domain registration fees in SOV instead of ZHTP (#1090) |
| 2026-02-04 | `14c727a6` | fix: SOV token minting, recovery phrases, and content storage (#1092) |
| 2026-02-04 | `f2287603` | feat/fix: Recovery phrase validation and comprehensive testing for PR #1092 (#1093) |
| 2026-02-04 | `3995290e` | cleanup: Remove test scripts with hardcoded phrases and unused constants (#1096) |
| 2026-02-05 | `203712e7` | fix(lib-client): Deterministic seed recovery and migration endpoint (#1099) |
| 2026-02-05 | `e828b7fd` | fix(crypto): Accept legacy 4864-byte Dilithium5 secret keys (#1100) |
| 2026-02-05 | `8c5d6fa6` | fix(identity): Seed-only migration endpoint and lib-client FFI (#1101) |
| 2026-02-06 | `8a9a47f9` | fix(crypto): Consistent Dilithium implementation for seed-derived keys (#1102) |
| 2026-02-06 | `929ae24e` | fix: Support crystals-dilithium 4864-byte keys + migration persistence (#1103) |
| 2026-02-06 | `6b510c94` | fix(lib-client): Derive keys from master_seed for working identity recovery (#1104) |
| 2026-02-08 | `1c4613ee` | Root-key-anchored DID architecture (ADR-0004) (#1110) |
| 2026-02-08 | `104e5275` | feat(lib-client): C FFI wrappers for HandshakeState (#1115) |
| 2026-02-09 | `27fe0bae` | fix(lib-client): Remove DID from registration proof message format (#1116) |
| 2026-02-09 | `6b327c03` | fix(lib-client): Update domain functions to use JSON request format (#1117) |
| 2026-02-11 | `f1785f68` | fix(token): Add DID resolution for transfer recipient (#1118) |
| 2026-02-11 | `0afb22f9` | feat(lib-client): Add Android JNI export for SOV wallet transfer (#1121) |
| 2026-02-11 | `993da988` | fix(token): Fix SOV transfer fee, TokenMint validation, and balance migration (#1122) |
| 2026-02-11 | `ebf28a90` | feat: Configurable fee model, DAO governance APIs, and client fee calculation (#1123) |
| 2026-02-12 | `d2f37355` | feat(runtime): Initial chain sync to prevent genesis forks (#1124) |
| 2026-02-12 | `bd8d0b9b` | Token system overhaul: constants, auth, replay protection, fee routing (#1135) |
| 2026-02-13 | `691e004b` | Add auth and profile onboarding for zhtp-cli (#1136) |
| 2026-02-13 | `18c8fef3` | feat: Block explorer with paginated API endpoints and WASM frontend (#1137) |
| 2026-02-16 | `23e5e8bc` | fix(web4): Populate content_mappings from deploy manifest and fix wallet_id handling (#1138) |
| 2026-02-16 | `b6dcc458` | feat(explorer): Implement detail views (#1139) |
| 2026-02-17 | `e52b731f` | Add Claude Code GitHub Workflow (#1140) |
| 2026-02-17 | `239e92b8` | [BFT-A] Remove fork/reorg logic (#936) (#1142) |
| 2026-02-17 | `70e1fc63` | Enhance Copilot instructions with CI/CD workflows and troubleshooting (#1197) |
| 2026-02-17 | `e205caa2` | [BFT-A] Remove PoW mining + nonce validation (#935) (#1141) |
| 2026-02-17 | `0cfaa3cf` | [BFT-A] Remove chain evaluation + difficulty governance (#937) (#1143) |
| 2026-02-17 | `c50f59f7` | feat/cr tok 002 dao delegate hardening (#1161) |
| 2026-02-17 | `c694b867` | feat/token dao deploy readiness batch (#1198) |
| 2026-02-17 | `9fa67b47` | [BFT-A] Network block receipt -> proposal-only (#938) (#1144) |
| 2026-02-17 | `dce8175b` | [BFT-A] Quorum + proposal-scoped vote aggregation (#941) (#1146) |
| 2026-02-17 | `aa4ebfe1` | [BFT-A] Document safety/liveness assumptions (#942) (#1147) |
| 2026-02-17 | `f6117b88` | [BFT-A] Commit-only persistence (#939) (#1145) |
| 2026-02-17 | `5cb43908` | [BFT-A] Remove hybrid/PoW consensus engines (#946) (#1148) |
| 2026-02-17 | `15d51e5f` | chore/dev sync ignore local artifacts (#1218) |
| 2026-02-17 | `1002ead8` | [BFT-A] Epic Integration - All 38 PRs Merged (#1215) |
| 2026-02-17 | `81837a20` |  connection limits (#985) (#1181) |
| 2026-02-17 | `6a34db81` | Fix DOS/DoS spelling inconsistencies in connection limit error messages (#1216) |
| 2026-02-17 | `2c7845e2` |  jail exit + stake restoration (#980) (#1185) |
| 2026-02-18 | `82253f25` | feat(blockchain): implement atomic commit journal and fix overflow tests (#1219) |
| 2026-02-18 | `e364510c` | Add GitHub Actions workflow to summarize new issues (#1220) |
| 2026-02-18 | `da622806` | feat(BFT-H-1005): define protocol upgrade mechanism and version gating (#1233) |
| 2026-02-18 | `96a9a250` | feat(BFT-H-1006): define backward compatibility policy for old nodes (#1234) |
| 2026-02-18 | `419dab53` | feat(BFT-H-1007): Define emergency halt / kill-switch semantics (#1235) |
| 2026-02-18 | `fad57df9` | feat(BFT-J-1014): Expose consensus liveness/latency/fork-rate metrics (#1237) |
| 2026-02-18 | `4a020643` | feat(BFT-J-1013): Deterministic consensus logging for auditability (#1236) |
| 2026-02-18 | `f79c704c` | feat(BFT-J-1015): Add explicit invariant checks + fail-fast on violation (#1238) |
| 2026-02-18 | `1c9e012f` | feat(BFT-I-1009): define consensus signature schemes and aggregation … (#1239) |
| 2026-02-18 | `bfcf6d23` | docs(test): define epic-1222 e2e lane scope (#1240) |
| 2026-02-18 | `797162ea` | docs(exec): define epic-1222 execution-pipeline lane scope (#1241) |
| 2026-02-18 | `d21cb8eb` | feat(alpha): Integrate lib_identity::NodeId into mesh networking (#1242) |
| 2026-02-18 | `8bfdeb0c` | feat(BFT-G-1001): define genesis contents and validator snapshot validation (#1245) |
| 2026-02-18 | `0f57c347` | feat(BFT-G-1002): enforce bootstrap to highest committed BFT height (#1246) |
| 2026-02-18 | `ad0a72dd` | feat(BFT-G-1003): Define genesis trust assumptions + checkpoint rules (#1247) |
| 2026-02-18 | `ed8438ed` | feat(BFT-I-1010): Specify canonical hash functions for consensus-critical data (#1248) |
| 2026-02-18 | `eccb6f41` | feat(BFT-I-1011): Define key rotation + validator identity binding (#1249) |
| 2026-02-18 | `6833b2ca` | Feat: Replace CLI UDP ping with QUIC control ping (#1262) |
| 2026-02-18 | `9366ee41` | Docs: Update documentation for QUIC migration (#1263) |
| 2026-02-18 | `7c2375f8` | fix(dao): accept legacy and canonical CLI payloads for propose/vote |
| 2026-02-18 | `ddbb75ec` | fix: Remove ZHTP router bypass paths (Ticket 2.6) (#508) |
| 2026-02-18 | `f990c836` | Complete Phase 6 lifecycle management for RootRegistry domains with block-height-based (#1085) |
| 2026-02-18 | `7a062427` | Fix Web4 domain update + history CID consistency (#1098) |
| 2026-02-18 | `92d0ac02` | docs(web4): add CLI pubkey base64 encoding step for keystore secrets (#1105) |
| 2026-02-18 | `d27ca53d` | feat(#453): Implement canonical node type detection system (#1119) |
| 2026-02-18 | `b58c5548` | docs(alpha): Add ALPHA_RELEASE_NOTES.md for v0.1.0-alpha.1 |
| 2026-02-18 | `73ff6170` | Identity messaging MVP: DID fan-out, store-and-forward, receipts (#1064) |
| 2026-02-18 | `b769a0db` | feat(pouw): Add PoUW handler stub for QUIC endpoints |
| 2026-02-18 | `fae1aab1` | feat(pouw): Wire PoUW handler into ZhtpRouter |
| 2026-02-18 | `3cf793d2` | fix: MeshHandshake import and wire PoUW handler |
| 2026-02-18 | `7341764d` | Merge pull request #1266 from SOVEREIGN-NET/fix/1227-dao-cli-schema-compat |
| 2026-02-18 | `5feb10e7` | fix: resolve build errors in zhtp |
| 2026-02-18 | `62aaea46` | feat(contract): enforce canonical deployment transaction schema |
| 2026-02-18 | `311a39f2` | fix(tx): harden deployment schema decoding and creation errors |
| 2026-02-18 | `7c11e77b` | Merge pull request #1270 from SOVEREIGN-NET/fix/1225-contract-deployment-schema-enforcement |
| 2026-02-18 | `295e7df8` | feat(cli): add contract deploy/call and raw tx broadcast commands |
| 2026-02-18 | `774a37ef` | fix: restore workspace test-target compilation compatibility |
| 2026-02-18 | `0702386f` | fix(cli): align contract commands with canonical schema helpers |
| 2026-02-18 | `794ceba8` | fix(cli): make deploy tx builder work without inputs and add command tests |
| 2026-02-18 | `f7382ab5` | Merge pull request #1271 from SOVEREIGN-NET/fix/1226-cli-contract-deploy-call-raw-broadcast |
| 2026-02-18 | `e8cf5b2c` | test(e2e): add multi-node contract+dao lifecycle sync/replay tests (#1232) (#1273) |
| 2026-02-18 | `cb6a072b` | fix(dao): harden treasury proposal execution path (#1231) (#1275) |
| 2026-02-18 | `6c03fd1f` | fix(api): enable canonical contract deploy/call submission (#1229) (#1276) |
| 2026-02-18 | `499d5ae6` | feat(api): add canonical contract index/state/info query endpoints (#1230) (#1274) |
| 2026-02-18 | `7faa381c` | fix(sync): route contract/DAO imports through canonical runtime replay (#1268) |
| 2026-02-18 | `4ad5754a` | feat(identity): add ProofsSecretAdapter for lib-proofs compatibility (#1272) |
| 2026-02-18 | `4313bedb` | fix(blockchain): Fix genesis block validation and executor compatibility (#1277) |
| 2026-02-18 | `0dc84013` | docs(alpha): Add ALPHA_RELEASE_NOTES.md for v0.1.0-alpha.1 |
| 2026-02-18 | `db4fd07c` | feat(pouw): Add PoUW handler stub for QUIC endpoints |
| 2026-02-18 | `70ddee56` | feat(pouw): Wire PoUW handler into ZhtpRouter |
| 2026-02-18 | `01d407ff` | fix: MeshHandshake import and wire PoUW handler |
| 2026-02-18 | `a927ef85` | fix: resolve build errors in zhtp |
| 2026-02-18 | `5298b8cd` | feat(pouw): Integrate reward calculation in submit endpoint |
| 2026-02-19 | `789422af` | Address Copilot feedback for PoUW reward endpoint |
| 2026-02-19 | `0798eedc` | Merge pull request #1296 from SOVEREIGN-NET/feature/pouw-blockchain-rewards |
| 2026-02-19 | `e7127180` | fix(arch): Add BlockExecutor field to Blockchain - foundation for single source of truth |
| 2026-02-18 | `83153f1b` | fix(arch): Use BlockExecutor in process_and_commit_block when configured |
| 2026-02-18 | `de2d3a9e` | fix: Remove duplicate begin_block call in executor path |
| 2026-02-18 | `9ab5e87a` | fix(arch): Make BlockExecutor primary path with legacy fallback |
| 2026-02-18 | `806a4901` | feat(storage): Add nonce storage to BlockchainStore for replay protection |
| 2026-02-19 | `041a19d3` | feat(executor): Enforce sender authorization for TokenTransfer (#1299) |
| 2026-02-18 | `43900fd7` | feat(executor): Enforce minting authority and supply cap for TokenMint (#1300) |
| 2026-02-18 | `80baedf4` | Update zhtp/src/api/handlers/pouw/mod.rs |
| 2026-02-18 | `6a158b3e` | feat(pouw): Implement rate limiting in PoUW handler endpoints (#1280) |
| 2026-02-18 | `c2aafc3c` | fix: document reward_calculator usage and resolve build errors in PoUW handler (#1281) |
| 2026-02-19 | `d60ac781` | Merge pull request #1278 from SOVEREIGN-NET/feature/pouw-quic-endpoints |
| 2026-02-18 | `7669475a` | feat(epic-1317): Complete token platform phases 1-4 infrastructure |
| 2026-02-19 | `d3e5e932` | fix(arch): Unify dual-state - BlockExecutor as single source of truth (#1297) (#1323) |
| 2026-02-19 | `d136ce3b` | Merge feature/pouw-quic-endpoints into fix/1297-unify-dual-state |
| 2026-02-19 | `a0c1aef5` | fix(crypto): Disable dev mode signatures in production (Issue #1009) |
| 2026-02-18 | `e1a1eece` | fix(blockchain): replay contract execution via canonical runtime during store load |
| 2026-02-18 | `e20f06e9` | fix(blockchain): preserve token replay semantics and contract heights |
| 2026-02-18 | `9a6d9e3c` | fix(blockchain): populate contract_blocks for contracts missing deployment heights after replay (#1319) |
| 2026-02-18 | `914bc77f` | Initial plan (#1320) |
| 2026-02-19 | `2ab916a2` | Merge pull request #1267 from SOVEREIGN-NET/fix/1223-contract-runtime-canonical-block-processing |
| 2026-02-19 | `873ac156` | Merge pull request #1324 from SOVEREIGN-NET/fix/1297-unify-dual-state |
| 2026-02-19 | `7565acfc` | Merge pull request #1325 from SOVEREIGN-NET/fix/1009-consensus-signature-scheme |
| 2026-02-10 | `ba97dbbc` | feat(#454): Implement canonical node startup dispatch based on NodeType |
| 2026-02-11 | `4e4fd16b` | fix(#454): Handle Option<NodeType> from PR #1119 |
| 2026-02-11 | `1f7ae739` | fix: Remove duplicate node_type field in Default impl |
| 2026-02-12 | `2a1e8078` | fix(#454): Remove emojis from relay node startup messages to comply with no-emoji rule |
| 2026-02-18 | `f272775b` | fix(config): align derive_node_role edge detection with derive_node_type criteria |
| 2026-02-18 | `588c9328` | fix(config): Document Relay node type requires explicit configuration (#1321) |
| 2026-02-18 | `a837f614` | Fix node_type/node_role divergence in RuntimeOrchestrator initialization (#1322) |
| 2026-02-19 | `aa08688a` | Merge pull request #1120 from SOVEREIGN-NET/454-node-startup-consolidation |
| 2026-02-19 | `2896f405` | feat(pouw): Add comprehensive stress tests (POUW-Phase-6) |
| 2026-02-19 | `ca9d2411` | fix(treasury): Add Treasury Kernel infrastructure for SOV/DAO token control (#859) |
| 2026-02-19 | `21b2a9f8` | test(pouw): address reviewer feedback in stress tests |
| 2026-02-19 | `ed7ff376` | Merge pull request #1326 from SOVEREIGN-NET/feat/pouw-stress-tests |
| 2026-02-19 | `68e0aee0` | feat(pouw): Add identity registry validation (POUW-Phase-5) |
| 2026-02-19 | `561679c2` | Merge pull request #1327 from SOVEREIGN-NET/feat/pouw-identity-validation |
| 2026-02-19 | `ee5f65a0` | Merge pull request #1328 from SOVEREIGN-NET/fix/859-enable-kernel-only-mode |
| 2026-02-19 | `1cb25957` | feat(pouw): Add user rewards API endpoints |
| 2026-02-19 | `9e137253` | fix: Comment out RuntimeOrchestrator creation in UnifiedServer (#1329) |
| 2026-02-19 | `ca62a30d` | feat(pouw): PoUW-BETA complete reward system — all 12 issues (#1375) |
| 2026-02-20 | `dbaa2a01` | Fix #1332: enforce canonical typed TokenCreation transactions (#1373) |
| 2026-02-20 | `029c2670` | TOKEN-DAO #1333: execute ContractDeployment/ContractExecution in BlockExecutor canonical path (#1363) |
| 2026-02-20 | `8ec12a36` | TOKEN-DAO #1334: unify contract deployment memo encoding/decoding format (#1362) |
| 2026-02-20 | `db8abf7a` | TOKEN-DAO #1335: move CLI token mint/transfer to typed txs and disable burn (#1360) |
| 2026-02-20 | `44bbf339` | TOKEN-DAO #1336: execute DAO proposal/vote/execution txs in BlockExecutor canonical path (#1365) |
| 2026-02-20 | `68d07ce6` | TOKEN-DAO: complete Treasury Kernel Phase 5 UBI mint/event/persistence wiring (#1378) |
| 2026-02-20 | `18906ea4` | TOKEN-DAO: wire DAO registry register/list/get into canonical DAO execution path (#1377) |
| 2026-02-20 | `e0960e58` | TOKEN-DAO #1339: default store-backed blockchain initialization to canonical executor path (#1366) |
| 2026-02-20 | `c91cf9b6` | Fix #1340: enforce canonical contract deploy/call API validation (#1376) |
| 2026-02-20 | `2ac9a31e` | test(ci): add and enforce TOKEN-DAO readiness gate suite (#1367) |
| 2026-02-20 | `06a6720e` | TOKEN-DAO #1342: fix contract deployment memo decoding causing Invalid block replay failure (#1356) |
| 2026-02-20 | `5d53a2c2` | fix(cli): remove stale Migrate test references and fix Site keystore type (#1379) |
| 2026-02-20 | `f6d1a7e7` | feat(pouw): register Web4GatewayHandler for host-based routing rewards (#1386) |
| 2026-02-20 | `d7ba5931` | feat(pouw): persist reward state across restarts and refactor to Arc<RewardCalculator> (#1397) |
| 2026-02-20 | `aa8e1820` | feat(pouw): add stats, epochs, receipts, and disputes API endpoints (#1398) |
| 2026-02-20 | `deca0052` | feat(pouw): implement on-chain SOV payout background task (#1400) |
| 2026-02-20 | `9022f9b9` | feat(pouw): per-user reward transaction ledger and transactions endpoint (#1402) |
| 2026-02-20 | `d5dfd588` | fix(pouw): remove broken Ed25519 sig path — system is pure PQC (Dilithium5 only) (#1403) |
| 2026-02-20 | `8f1ff690` | fix(blockchain): propagate ContractExecution errors and restore TokenStateSnapshot on load (#1406) |
| 2026-02-20 | `e552fde3` | feat(contract): dispatch execution by deployed contract_id (#1396) |
| 2026-02-20 | `ffdf35a4` | feat(validation): enforce token mint authorization parity in precheck (#1399) |
| 2026-02-20 | `9725d7dc` | feat(token): enforce treasury-kernel routing for protected mint and burn (#1401) |
| 2026-02-20 | `6306a17d` | feat(dao): add canonical factory create execution and replay compatibility (#1404) |
| 2026-02-20 | `cb7df7e2` | Phase 5: Integrate verification requirements into RootRegistry via NamespacePolicy (#1082) |
| 2026-02-20 | `a15a6d70` | docs(alpha): Add ALPHA_RELEASE_NOTES.md for v0.1.0-alpha.1 (#1269) |
| 2026-02-20 | `74ada96d` | DAO-READY #1391: Index DAO registry for O(1) reads (#1405) |
| 2026-02-20 | `72f03806` | DAO-READY #1394: Complete CLI contract lifecycle and DAO registry/factory flows (#1407) |
| 2026-02-20 | `7ec60713` | DAO-READY #1395: Add release gate suite and checklist docs (#1408) |
| 2026-02-21 | `31ef3d1d` | DAO-READY #1389: add canonical deployed-contract registry and generic contract queries (#1409) |
| 2026-02-21 | `568a0d99` | SOV Token Economics: Bonding Curve Token Launch System (#1410) |
| 2026-02-21 | `5324e885` | DAO-READY #1413: Explicitly detect and reject HTTP request-line payloads on QUIC (#1416) |
| 2026-02-21 | `60932ae3` | network: remove unused client_http_alpns helper (#1414) (#1418) |
| 2026-02-21 | `d8352fd3` | quic: explicitly map legacy http ALPN identifiers (#1412) (#1415) |
| 2026-02-21 | `d944d824` | DAO-READY #1411: Stop advertising unsupported HTTP-compat ALPNs (#1417) |
| 2026-02-21 | `b7cded7c` | feat(ffi): Add C FFI functions for bonding curve transactions (#1434) |
| 2026-02-21 | `03ea6107` | VALIDATORS: Add readiness gate suite and migration checks (#1426) (#1435) |
| 2026-02-21 | `317e6396` | VALIDATORS: backport main-only merges to development (#1439) |
| 2026-02-21 | `3dbbc359` | fix(config): add missing gateway_enabled field to ProtocolsConfig (#1440) |
| 2026-02-21 | `6745a4bb` | fix(config): remove tcp from default NetworkConfig protocols list (#1441) |
| 2026-02-21 | `363b4585` | fix(consensus): set validator keypair after identity + validator sync (#1442) |
| 2026-02-23 | `1ce4f236` | feat(lib-client): add zhtp_client_sign_pouw_receipt_json FFI (#1444) |
| 2026-02-23 | `c45e10ff` | fix(pouw): move payout task out of Bluetooth handler into start() (#1445) |
| 2026-02-24 | `263cfa20` | TokenCreation: enforce 20% treasury allocation at deploy time (#1447) |
| 2026-02-24 | `cfde862f` | fix(mempool): enforce fee==0 for TokenTransfer to match BlockExecutor Phase 2 rules (#1450) |
| 2026-02-24 | `24aac368` | fix: gate MeshRoutingEvent re-export with transport features (#1451) |
| 2026-02-25 | `2448402c` | feat(lib-client): add zhtp_client_get_sov_token_id FFI (#1452) |
| 2026-02-26 | `ab409d44` | feat(blockchain): initialize DAO treasury wallet deterministically (#1448) |
| 2026-02-26 | `b1bd2026` | fix(blockchain): repair SOV backfill inflation and sync token balances from Sled (#1453) |
| 2026-02-27 | `d7e5eccc` | fix(wallet): canonical user transaction history endpoint (#1481) |
| 2026-02-27 | `10bbdda3` | feat(dao): Bootstrap Council governance phase (#1465) (#1472) |
| 2026-02-26 | `f7751905` | feat(dao): fix treasury execution with balance model and epoch caps (#1466) |
| 2026-02-27 | `f06217b8` | fix(dao-2): address PR #1473 review issues |
| 2026-02-27 | `7ce73161` | fix(dao-2): add real implementations for all 6 claimed test cases |
| 2026-02-27 | `db71645a` | refactor(lib-client): enforce PoUWController as sole integration path |
| 2026-02-27 | `cd71f437` | fix(dao-prefix-router): add missing use imports and fix return type in doctests |
| 2026-02-27 | `01a8f72d` | fix(dao-2): make execution_params mandatory and validate spending category end-to-end |
| 2026-02-27 | `f24c33c4` | fix(lib-client): sign PoUW receipts with canonical bincode encoding |
| 2026-02-27 | `a6633ef1` | fix(sonar): address reliability bug and exclude RN PoUW path from coverage gate |
| 2026-02-27 | `87435ee1` | feat(dao): fix treasury execution with balance model and epoch caps (#1473) |
| 2026-02-26 | `5aed4540` | feat(dao): implement voting power reform (dao-5, closes #1469) |
| 2026-02-27 | `20daf45b` | Merge pull request #1497 from SOVEREIGN-NET/feat/lib-client-pouw-canonical-controller-only |
| 2026-02-27 | `6ae34e27` | fix(dao-5): address all 13 PR review issues on voting power reform |
| 2026-02-27 | `1c819853` | fix(pouw): block receipts when challenge policy lacks requested proof types |
| 2026-02-27 | `ed00556a` | Initial plan |
| 2026-02-27 | `f5b63b11` | fix: prevent false negative in _ensureChallenge when time advances between checks |
| 2026-02-27 | `37033d5a` | Merge pull request #1499 from SOVEREIGN-NET/copilot/sub-pr-1498 |
| 2026-02-27 | `f1d786d1` | Merge pull request #1498 from SOVEREIGN-NET/fix/pouw-web4-challenge-guard |
| 2026-02-28 | `23ef21b5` | Merge pull request #1474 from SOVEREIGN-NET/feature/dao-5-voting-power |
| 2026-02-28 | `e8a44a7a` | feat(oracle): CBE-only state model + v4 migration (#1455) (#1480) |
| 2026-02-28 | `f3d97ec3` | fix(docs): add missing imports in dao_prefix_router doctests (#1479) |
| 2026-02-28 | `e08b73c5` | feat(dao): governance phase transitions with decentralization snapshots (#1467) (#1475) |
| 2026-02-28 | `28c755d4` | feat(dao): hybrid governance — co-sign, veto, and epoch rate limiting (#1468) (#1476) |
| 2026-02-28 | `f16bad9c` | feat(dao): full DAO phase — auto-execution and council dissolution (#1470) (#1477) |
| 2026-02-28 | `9d341bab` | feat(dao): emergency treasury freeze with 80% validator threshold (#1471) (#1478) |
| 2026-02-28 | `6946b498` | feat(oracle): deterministic gossip admission + finalization (#1459) (#1500) |
| 2026-02-28 | `b0a4d705` | feat(oracle): deterministic gossip admission + finalization (#1459) (#1501) |
| 2026-02-28 | `4ea4c0fa` | feat(blockchain): CBE graduation oracle gate + staleness checks (#1461) (#1502) |
| 2026-02-28 | `0d7245d3` | fix(network): repair block propagation and add observer sync loop (#1503) |
| 2026-02-28 | `262e055a` | docs: reorganize md files into docs/guides and docs/specs folders (#1657) |
| 2026-02-28 | `1add4693` | refactor(types): import canonical types from lib-types |
| 2026-03-01 | `2f85f2ac` | feat(fees): add Unstaking transaction kind (#1658) |
| 2026-03-01 | `563d4862` | FEES-8/9: Document multiplier rationale (#1659) |
| 2026-03-01 | `95f48e73` | fix(types): remove orphan rule violations from storage module |
| 2026-03-01 | `c54aa4df` | fix(storage): restore missing types and trait (reviewer feedback) |
| 2026-03-01 | `0f64778d` | Initial plan |
| 2026-03-01 | `1080f4a7` | fix: import AddressExt trait where Address::ZERO is used |
| 2026-03-01 | `008eee42` | TYPES-2/3/4/5: Remove duplicate types from lib-blockchain (#1660) |
| 2026-03-01 | `7f6b2293` | TYPES-6: Remove duplicate BlockHeight from root_registry (#1661) |
| 2026-03-01 | `8951c1cc` | Merge copilot/sub-pr-1660: Fix extension trait imports for Address::ZERO |
| 2026-03-01 | `bfdc584e` | feat(consensus): bootstrap all 4 nodes as BFT validators (#1598) |
| 2026-03-01 | `6f419893` | TYPES-1: Merge duplicate NodeId definitions (CRITICAL) (#1663) |
| 2026-03-01 | `47420d8c` | refactor(types): move PeerId from lib-storage to lib-types (#1664) |
| 2026-03-01 | `dd71866c` | fix(identity): clean up deprecated code and dead code allowances (#1665) |
| 2026-03-01 | `18066e43` | fix(tokens): remove deprecated apply_token_transfer from public API (#1672) |
| 2026-03-01 | `ca4035d0` | TYPES-9 & TYPES-10: Move fee and consensus primitives to lib-types (#1670) |
| 2026-03-01 | `12e816b4` | fix(protocols): return errors for unimplemented ZK validations (#1678) |
| 2026-03-01 | `85c1fd8d` | TYPES-12: Move mempool primitives from lib-mempool to lib-types (#1680) |
| 2026-03-01 | `e8966b95` | feat(oracle): oracle attestation pipeline with Dilithium committee (#1679) |
| 2026-03-01 | `4be17096` | TYPES-13: Document type architecture rule (#1681) |
| 2026-03-01 | `98ea1d71` | fix(protocols): enable secure transfers and remove placeholder values (#1683) |
| 2026-03-01 | `6c613efa` | ORACLE-1: Enforce governance-only oracle committee membership (#1702) |
| 2026-03-01 | `704600e0` | Add CI type duplication check (TYPES-14) (#1711) |
| 2026-03-01 | `25bdf90c` | ORACLE-2: Derive epoch_id from block timestamp, not wall clock (#1712) |
| 2026-03-01 | `77a6bf93` | fix(types): add StorageStats to lib-types (#1715) |
| 2026-03-01 | `ca649c9e` | ORACLE-3/4/5: Exchange price feed, slashing, and staleness (#1714) |
| 2026-03-02 | `734a773d` | ORACLE-6: Add oracle governance transaction types and execution handler (#1716) |
| 2026-03-02 | `183e237a` | fix(tests): fix compilation errors (#1718) |
| 2026-03-02 | `888f92ea` | ORACLE-7: Apply pending oracle updates at epoch boundaries (#1717) |
| 2026-03-02 | `0017d056` | ORACLE-9: Add oracle attestation signature verification at block execution time (#1720) |
| 2026-03-02 | `dec2bb47` | ORACLE-10: Include oracle_state in BlockchainImport for initial sync (#1721) |
| 2026-03-02 | `a91321e4` | ORACLE-8: Add authorization gate to oracle state mutation methods (#1719) |
| 2026-03-02 | `c8849ae2` | ORACLE-12: Add committee_for_epoch() for unified producer/consumer committee source (#1723) |
| 2026-03-02 | `d7023971` | ORACLE-13: BlockExecutor Integration and CBE Gate Fixes (#1724) |
| 2026-03-03 | `6f3613bd` | ORACLE-11: Implement cancellation mechanism for pending oracle updates (#1722) |
| 2026-03-03 | `e355996d` | STORAGE-1: clean stale TODO noise and remove warning sources (#1727) |
| 2026-03-03 | `4f97435c` | ORACLE-16: Comprehensive oracle integration test suite (#1729) |
| 2026-03-03 | `5e8df8ac` | fix(lib-client): Remove duplicate oracle_attestation_data fields (#1733) |
| 2026-03-03 | `3b2ab015` | chore(lib-network): reduce warnings and deprecations (#1728) |
| 2026-03-03 | `e8c77c58` | NETWORK-2: Replace critical unwrap/expect calls with proper error handling (#1730) |
| 2026-03-03 | `5a04a320` | NETWORK-3: Fix race condition in tokio duplex streams (#1732) |
| 2026-03-03 | `2b48910f` | NETWORK-4: Add panic recovery to network services (#1734) |
| 2026-03-03 | `8fff7348` | NETWORK-7: Complete peer registry migration (Ticket #149) (#1738) |
| 2026-03-03 | `5c8464d1` | Implement remaining #1690 oracle DAO API/CLI support and tests (#1735) |
| 2026-03-03 | `ce17389f` | NETWORK-5: Implement DHT storage stubs (#1736) |
| 2026-03-03 | `1fd7544f` | fix(consensus): break partition deadlock and credit SOV on wallet registration (#1737) |
| 2026-03-03 | `d3ae2629` | feat(FEES): Complete lib-fees audit findings (#1569) (#1739) |
| 2026-03-03 | `23e67664` | NETWORK-9: Complete TLS pinning implementation (Issue #739) (#1742) |
| 2026-03-03 | `ca4bc100` | fix(lib-network): Add missing imports for compilation (#1743) |
| 2026-03-04 | `f870858f` | DHT: move runtime/API off stub and add integration adapter (#1756) |
| 2026-03-04 | `21a52b3e` | fix(crypto): CRYPTO-1/2/3 - Consolidate PQ constants and remove deprecated method (#1755) |
| 2026-03-06 | `799987d1` | fix(consensus): allow single-validator BFT and fix peer sync for all node types (#1767) |
| 2026-03-06 | `e2ce779f` | Codex/consensus round dynamics (#1790) |
| 2026-03-06 | `bab77192` | fix(consensus): bootstrap validator key seeding and consensus round improvements (#1791) |
| 2026-03-06 | `5c9b5243` | feat(observer): add consensus state encoder with classification and e… (#1792) |
| 2026-03-06 | `00e17795` | [ORACLE][EPIC] Spec v1 to Code Deep Remediation - Phase 1: Protocol Version + Activation Gate (#1794) |
| 2026-03-06 | `188af8f6` | [ORACLE][R3] Canonicalize Attestation Execution Path (Shadow -> Cutover) (#1772) (#1796) |
| 2026-03-06 | `9b1cf3b4` | fix(oracle,wire): oracle committee resilience and 64MB wire messages (#1797) |
| 2026-03-06 | `becd9d38` | [ORACLE][R3] Align CBE Graduation Formula with Spec §2 (#1773) (#1798) |
| 2026-03-06 | `6d3620b2` | [ORACLE][R4] Normalize Epoch Tracking Semantics + Migration (#1774) (#1799) |
| 2026-03-07 | `3df78908` | [ORACLE][R8] Compliance Gate Suite + Release Readiness (#1780) (#1802) |
| 2026-03-07 | `c1ad69e5` | test(observer): add deterministic replay and anomaly scenario test suite (#1789) (#1804) |
| 2026-03-07 | `c2f4ffb3` | feat(api): implement missing monitoring and network status endpoints (#1801) (#1803) |
| 2026-03-08 | `2542d1ce` | fix(lib-client): force fee=0 for TokenCreation system transactions (#1808) |
| 2026-03-08 | `4428550c` | [ORACLE][R8] Source Oracle Producer Policy from On-Chain Config (#1775) (#1800) |
| 2026-03-08 | `a12b8eab` | fix(lib-client): export C FFI wrapper for PoUW receipt JSON signing (#1809) |
| 2026-03-08 | `61a5a140` | fix(token-creation): calculate correct fee and skip identity check for TokenCreation (#1810) |
| 2026-03-09 | `45e62dcb` | fix(lib-network): stop leaking sled DBs in bootstrap ZhtpClient (#1811) |
| 2026-03-09 | `90667b4d` | fix(token-creation): canonical dao-governed creation fee (#1812) |
| 2026-03-09 | `f25a500e` | fix(oracle,consensus): epoch mismatch, committee restore, and consensus round improvements (#1807) |
| 2026-03-09 | `f96823f5` | fix(lib-network): use anyhow::anyhow! consistently in wifi_direct.rs (#1813) |
| 2026-03-09 | `30404a38` | fix(lib-network): add missing anyhow macro import in wifi_direct.rs (#1814) |
| 2026-03-09 | `63dc5c2a` | [ORACLE] Complete Epic #1769 Partial Implementations (#1776, #1777, #1778, #1779) (#1815) |
| 2026-03-09 | `2fca6e64` | Epic #1781: Complete Consensus Observer Scoring Layer (Round Dynamics & Behavioral Grammar v0.1) (#1817) |
| 2026-03-09 | `6c545909` | fix(lib-network): use singleton nonce cache for bootstrap clients (#1816) |
| 2026-03-09 | `0d6c79f0` | feat(api): expose observer metrics via API endpoints (#1788) (#1806) |
| 2026-03-09 | `22a2f9e6` | oracle: add pair-aware price and variation endpoints (#1795) |
| 2026-03-10 | `5a4f1625` | [CBE Token Launch] Piecewise Linear Bonding Curve - Fix CBE Genesis Curve Type (#1854) |
| 2026-03-10 | `a73364ed` | [CBE Token Launch] Genesis Allocation - 100B Supply Distribution (#1843) (#1855) |
| 2026-03-10 | `8b8b77ef` | [CBE Token Launch] Reserve and Treasury 20/80 Split (#1844) (#1856) |
| 2026-03-10 | `e36ec476` | Issue #1845: Pre-Graduation Sell with Token Burn - Comprehensive Test Suite (#1857) |
| 2026-03-10 | `91037fee` | Issue #1846: Graduation Threshold Detection - $269K USD (#1858) |
| 2026-03-10 | `15ea8d87` | Issue #1847: Oracle Observer Mode - Read-Only Price Reporting (#1859) |
| 2026-03-11 | `2d9637d0` | Issue #1848: AMM Pool Creation for Bonding Curve Graduation (#1860) |
| 2026-03-11 | `bad3a993` | fix(cbe): graduation threshold precision, staleness, and overflow safety (#1846) (#1861) |
| 2026-03-11 | `2ec51b60` | Issue #1849: Implement Protocol-Owned Liquidity (POL) Pool with hardened security (#1868) |
| 2026-03-11 | `5568ecf6` | Issue #1850: Implement REST API Endpoints for Bonding Curve (#1869) |
| 2026-03-11 | `22310e9f` | Issue #1851: Full Lifecycle Integration Tests for CBE Token (#1870) |
| 2026-03-11 | `bdc03749` | Implement epic #1862 BFT-only startup and canonical commit path (#1871) |
| 2026-03-11 | `9c1c6089` | feat(bonding-curve): graduation threshold 2,745,966 and 40/60 reserve split (#1872) |
| 2026-03-11 | `34f5bc5e` | Issue #1852: Refactor #1819 to Document-Compliant Architecture - Oracle Observer-Only (#1873) |
| 2026-03-12 | `9b9c6506` | fix: oracle Mode A/B pricing, BFT startup and consensus fixes (#1876) |
| 2026-03-15 | `954eedeb` | feat(tsr): Treasury Signer Registration — InitEntityRegistry (TSR-1..6) (#1891) |
| 2026-03-16 | `177edd76` | fix(cbe-0): persist cbe_token in storage, fix genesis invariant (#1911) |
| 2026-03-16 | `74aa3d20` | feat(#1877): Mobile-to-web authentication delegation - Phase 1/2/3 (#1914) |
| 2026-03-17 | `2d60ef65` | feat(genesis): deterministic genesis from genesis.toml (GENESIS-1 #1909) (#1913) |
| 2026-03-17 | `c9081273` | fix(consensus): halt on BFT commit failure instead of silent divergence (#1915) |
| 2026-03-17 | `f266d6dd` | fix(consensus): auto-wipe sled on N=3 consecutive hash-mismatch from ahead peers (#1916) (#1917) |
| 2026-03-17 | `baf5edfb` | fix(genesis): correct misleading comment in legacy create_genesis_block() (#1918) |
| 2026-03-19 | `a2a16aac` | docs: add comprehensive security audit report |
| 2026-03-19 | `d614517c` | docs: add comprehensive security audit report |
| 2026-03-19 | `63f9f801` | security: remediate high-severity dependencies, DoS panic vectors, and hardcoded secrets |
| 2026-03-19 | `52db5024` | docs: add MrCakes931 attribution to security audit report |
| 2026-03-19 | `69ee8fb4` | feat: implement Clara security layer and finalize audit documentation |
| 2026-03-19 | `b8449ce6` | chore: consolidate security audit documentation and hardening updates |
| 2026-03-19 | `7104dea0` | security: restore and harden network environment |
| 2026-03-19 | `a35dbf6e` | docs: finalize security audit reports and project status |
| 2026-03-19 | `63ef78dd` | docs: finalize security audit reports and project status |
| 2026-03-19 | `f4b6d95e` | docs: finalize security audit reports and project status |
| 2026-03-19 | `84136f04` | docs: finalize security audit reports and project status |
| 2026-03-19 | `e2adbfbd` | security: apply enterprise-grade VAPT remediation and hardening |
| 2026-03-19 | `bc564952` | security: full-scope VAPT remediation and enterprise hardening |
| 2026-03-19 | `a94aca63` | final: comprehensive audit archive, compliance labeling, and decentralization verification |
| 2026-03-19 | `42274362` | audit: genesis-to-current systemic hardening and ability mapping |
| 2026-03-19 | `586da44a` | optimization: activate unrealized abilities and reduce redundant allocations |
| 2026-03-19 | `0f50a512` | infra: implement automated security monitoring and pre-push hooks - Tagged MrCakes931 |
| 2026-03-19 | `d0a6e5c8` | feat: migrate single-authority admin logic to decentralized governance stubs - MrCakes931 Alignment |
| 2026-03-19 | `2addad16` | docs: create local issue backlog due to repository settings - Tagged MrCakes931 |
| 2026-03-19 | `dd251700` | final: absolute logic alignment and governance refactor - Tagged MrCakes931 |

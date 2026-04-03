import Foundation
import React

// Import the UniFFI-generated module (from XCFramework)
// This will be available after building with: uniffi-bindgen generate uniffi/zhtp_client.udl --language swift
import ZhtpClient

/// React Native Native Module for ZHTP Identity Provisioning
/// Wraps the UniFFI-generated Swift bindings from lib-client
@objc(NativeIdentityProvisioning)
class NativeIdentityProvisioning: NSObject {

    // MARK: - Stored Identity (in-memory, encrypt before persisting)
    private var currentIdentity: Identity?
    private var currentSession: Session?
    private var handshakeState: HandshakeState?

    // MARK: - Module Setup

    @objc
    static func moduleName() -> String {
        return "NativeIdentityProvisioning"
    }

    @objc
    static func requiresMainQueueSetup() -> Bool {
        return false
    }

    // MARK: - Identity Generation

    /// Generate a new identity with post-quantum keys
    /// Keys are generated locally and NEVER leave the device
    @objc
    func generateIdentity(
        _ deviceId: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let identity = try ZhtpClient.generateIdentity(deviceId: deviceId)
                self.currentIdentity = identity

                let result: [String: Any] = [
                    "did": identity.did,
                    "deviceId": identity.deviceId,
                    "nodeId": self.dataToBase64(identity.nodeId),
                    "publicKey": self.dataToBase64(identity.publicKey),
                    "kyberPublicKey": self.dataToBase64(identity.kyberPublicKey),
                    "createdAt": identity.createdAt,
                    // Note: Private keys are NOT exposed to JS for security
                    // They remain in native Swift memory only
                ]

                resolve(result)
            } catch {
                reject("IDENTITY_ERROR", "Failed to generate identity: \(error.localizedDescription)", error)
            }
        }
    }

    /// Restore identity from master seed (for recovery/migration)
    @objc
    func restoreIdentityFromSeed(
        _ masterSeedBase64: String,
        deviceId: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                guard let seedData = Data(base64Encoded: masterSeedBase64) else {
                    reject("INVALID_SEED", "Invalid base64 seed data", nil)
                    return
                }

                let identity = try ZhtpClient.restoreIdentityFromSeed(
                    masterSeed: [UInt8](seedData),
                    deviceId: deviceId
                )
                self.currentIdentity = identity

                let result: [String: Any] = [
                    "did": identity.did,
                    "deviceId": identity.deviceId,
                    "nodeId": self.dataToBase64(identity.nodeId),
                    "publicKey": self.dataToBase64(identity.publicKey),
                    "kyberPublicKey": self.dataToBase64(identity.kyberPublicKey),
                    "createdAt": identity.createdAt,
                ]

                resolve(result)
            } catch {
                reject("RESTORE_ERROR", "Failed to restore identity: \(error.localizedDescription)", error)
            }
        }
    }

    /// Get public identity (safe to send to server for registration)
    @objc
    func getPublicIdentity(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded. Call generateIdentity first.", nil)
            return
        }

        do {
            let publicIdentity = try ZhtpClient.getPublicIdentity(identity: identity)

            let result: [String: Any] = [
                "did": publicIdentity.did,
                "publicKey": self.dataToBase64(publicIdentity.publicKey),
                "kyberPublicKey": self.dataToBase64(publicIdentity.kyberPublicKey),
                "nodeId": self.dataToBase64(publicIdentity.nodeId),
            ]

            resolve(result)
        } catch {
            reject("PUBLIC_IDENTITY_ERROR", "Failed to get public identity: \(error.localizedDescription)", error)
        }
    }

    /// Sign a registration proof for server registration
    @objc
    func signRegistrationProof(
        _ timestamp: Double,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded. Call generateIdentity first.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let signature = try ZhtpClient.signRegistrationProof(
                    identity: identity,
                    timestamp: UInt64(timestamp)
                )
                resolve(self.dataToBase64(signature))
            } catch {
                reject("SIGN_ERROR", "Failed to sign registration proof: \(error.localizedDescription)", error)
            }
        }
    }

    /// Sign an arbitrary message
    @objc
    func signMessage(
        _ messageBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded. Call generateIdentity first.", nil)
            return
        }

        guard let messageData = Data(base64Encoded: messageBase64) else {
            reject("INVALID_MESSAGE", "Invalid base64 message data", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let signature = try ZhtpClient.signMessage(
                    identity: identity,
                    message: [UInt8](messageData)
                )
                resolve(self.dataToBase64(signature))
            } catch {
                reject("SIGN_ERROR", "Failed to sign message: \(error.localizedDescription)", error)
            }
        }
    }

    /// Sign a PoUW receipt JSON payload using canonical bincode receipt encoding
    @objc
    func signPouwReceipt(
        _ receiptJson: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded. Call generateIdentity first.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let signature = try ZhtpClient.signPouwReceiptJson(
                    identity: identity,
                    receiptJson: receiptJson
                )
                resolve(self.dataToBase64(signature))
            } catch {
                reject("SIGN_ERROR", "Failed to sign PoUW receipt: \(error.localizedDescription)", error)
            }
        }
    }

    // MARK: - UHP v2 Handshake

    /// Initialize handshake with channel binding
    @objc
    func initHandshake(
        _ channelBindingBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded. Call generateIdentity first.", nil)
            return
        }

        guard let channelBinding = Data(base64Encoded: channelBindingBase64) else {
            reject("INVALID_BINDING", "Invalid base64 channel binding", nil)
            return
        }

        do {
            self.handshakeState = HandshakeState(
                identity: identity,
                channelBinding: [UInt8](channelBinding)
            )
            resolve(true)
        } catch {
            reject("HANDSHAKE_INIT_ERROR", "Failed to initialize handshake: \(error.localizedDescription)", error)
        }
    }

    /// Step 1: Create ClientHello message
    @objc
    func createClientHello(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let handshake = handshakeState else {
            reject("NO_HANDSHAKE", "No handshake in progress. Call initHandshake first.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let clientHello = try handshake.createClientHello()
                resolve(self.dataToBase64(clientHello))
            } catch {
                reject("CLIENT_HELLO_ERROR", "Failed to create ClientHello: \(error.localizedDescription)", error)
            }
        }
    }

    /// Step 2: Process ServerHello and create ClientFinish
    @objc
    func processServerHello(
        _ serverHelloBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let handshake = handshakeState else {
            reject("NO_HANDSHAKE", "No handshake in progress. Call initHandshake first.", nil)
            return
        }

        guard let serverHelloData = Data(base64Encoded: serverHelloBase64) else {
            reject("INVALID_SERVER_HELLO", "Invalid base64 ServerHello data", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let clientFinish = try handshake.processServerHello(data: [UInt8](serverHelloData))
                resolve(self.dataToBase64(clientFinish))
            } catch {
                reject("SERVER_HELLO_ERROR", "Failed to process ServerHello: \(error.localizedDescription)", error)
            }
        }
    }

    /// Step 3: Finalize handshake and get session
    @objc
    func finalizeHandshake(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let handshake = handshakeState else {
            reject("NO_HANDSHAKE", "No handshake in progress. Call initHandshake first.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let result = try handshake.finalize()

                // Create session from handshake result
                self.currentSession = try Session(
                    sessionKey: result.sessionKey,
                    sessionId: result.sessionId,
                    peerDid: result.peerDid
                )

                // Clear handshake state
                self.handshakeState = nil

                let response: [String: Any] = [
                    "sessionId": self.dataToBase64(result.sessionId),
                    "peerDid": result.peerDid,
                    "peerPublicKey": self.dataToBase64(result.peerPublicKey),
                    // Note: sessionKey is NOT exposed to JS for security
                ]

                resolve(response)
            } catch {
                reject("FINALIZE_ERROR", "Failed to finalize handshake: \(error.localizedDescription)", error)
            }
        }
    }

    // MARK: - Session Encryption

    /// Encrypt data using the current session
    @objc
    func encrypt(
        _ plaintextBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let session = currentSession else {
            reject("NO_SESSION", "No session established. Complete handshake first.", nil)
            return
        }

        guard let plaintext = Data(base64Encoded: plaintextBase64) else {
            reject("INVALID_PLAINTEXT", "Invalid base64 plaintext data", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let ciphertext = try session.encrypt(plaintext: [UInt8](plaintext))
                resolve(self.dataToBase64(ciphertext))
            } catch {
                reject("ENCRYPT_ERROR", "Failed to encrypt: \(error.localizedDescription)", error)
            }
        }
    }

    /// Decrypt data using the current session
    @objc
    func decrypt(
        _ ciphertextBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let session = currentSession else {
            reject("NO_SESSION", "No session established. Complete handshake first.", nil)
            return
        }

        guard let ciphertext = Data(base64Encoded: ciphertextBase64) else {
            reject("INVALID_CIPHERTEXT", "Invalid base64 ciphertext data", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let plaintext = try session.decrypt(ciphertext: [UInt8](ciphertext))
                resolve(self.dataToBase64(plaintext))
            } catch {
                reject("DECRYPT_ERROR", "Failed to decrypt: \(error.localizedDescription)", error)
            }
        }
    }

    // MARK: - Identity Persistence (encrypted)

    /// Export identity for secure storage (encrypts private keys)
    @objc
    func exportIdentityEncrypted(
        _ passwordBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded.", nil)
            return
        }

        guard let password = Data(base64Encoded: passwordBase64) else {
            reject("INVALID_PASSWORD", "Invalid base64 password", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                // Serialize identity to JSON
                let identityJson = try ZhtpClient.serializeIdentity(identity: identity)
                guard let jsonData = identityJson.data(using: .utf8) else {
                    reject("SERIALIZE_ERROR", "Failed to serialize identity", nil)
                    return
                }

                // Encrypt with password-derived key
                let encrypted = try ZhtpClient.encryptOneshot(
                    key: [UInt8](password),
                    plaintext: [UInt8](jsonData)
                )

                resolve(self.dataToBase64(encrypted))
            } catch {
                reject("EXPORT_ERROR", "Failed to export identity: \(error.localizedDescription)", error)
            }
        }
    }

    /// Import identity from encrypted storage
    @objc
    func importIdentityEncrypted(
        _ encryptedBase64: String,
        passwordBase64: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let encrypted = Data(base64Encoded: encryptedBase64),
              let password = Data(base64Encoded: passwordBase64) else {
            reject("INVALID_DATA", "Invalid base64 data", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                // Decrypt
                let jsonData = try ZhtpClient.decryptOneshot(
                    key: [UInt8](password),
                    ciphertext: [UInt8](encrypted)
                )

                guard let jsonString = String(data: Data(jsonData), encoding: .utf8) else {
                    reject("DECRYPT_ERROR", "Failed to decode decrypted data", nil)
                    return
                }

                // Deserialize identity
                let identity = try ZhtpClient.deserializeIdentity(json: jsonString)
                self.currentIdentity = identity

                let result: [String: Any] = [
                    "did": identity.did,
                    "deviceId": identity.deviceId,
                    "nodeId": self.dataToBase64(identity.nodeId),
                    "publicKey": self.dataToBase64(identity.publicKey),
                    "kyberPublicKey": self.dataToBase64(identity.kyberPublicKey),
                    "createdAt": identity.createdAt,
                ]

                resolve(result)
            } catch {
                reject("IMPORT_ERROR", "Failed to import identity: \(error.localizedDescription)", error)
            }
        }
    }

    /// Get master seed for backup (SENSITIVE - show warning to user!)
    /// This is the single master seed used to derive all wallets.
    @objc
    func getMasterSeedForBackup(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded.", nil)
            return
        }

        // Return master seed as base64
        resolve(self.dataToBase64(identity.masterSeed))
    }

    /// Get 24-word seed phrase for backup (SENSITIVE - show warning to user!)
    @objc
    func getSeedPhraseForBackup(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded.", nil)
            return
        }

        do {
            let phrase = try ZhtpClient.getSeedPhrase(identity: identity)
            resolve(phrase)
        } catch {
            reject("SEED_PHRASE_ERROR", "Failed to get seed phrase: \(error.localizedDescription)", error)
        }
    }

    /// Export keystore for CI/CD deployment (SENSITIVE - contains private keys!)
    /// Returns base64-encoded tarball ready to use as GitHub secret ZHTP_KEYSTORE_B64
    @objc
    func exportKeystoreForCICD(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let keystoreB64 = try ZhtpClient.exportKeystoreBase64(identity: identity)
                resolve(keystoreB64)
            } catch {
                reject("EXPORT_ERROR", "Failed to export keystore: \(error.localizedDescription)", error)
            }
        }
    }

    // MARK: - Utility Functions

    /// Check if identity is loaded
    @objc
    func hasIdentity(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        resolve(currentIdentity != nil)
    }

    /// Check if session is established
    @objc
    func hasSession(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        resolve(currentSession != nil)
    }

    /// Get current DID
    @objc
    func getCurrentDid(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        guard let identity = currentIdentity else {
            reject("NO_IDENTITY", "No identity loaded.", nil)
            return
        }
        resolve(identity.did)
    }

    /// Clear session (disconnect)
    @objc
    func clearSession(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        currentSession = nil
        handshakeState = nil
        resolve(true)
    }

    /// Clear all state (logout)
    @objc
    func clearAll(
        _ resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        currentIdentity = nil
        currentSession = nil
        handshakeState = nil
        resolve(true)
    }

    // MARK: - Helpers

    private func dataToBase64(_ bytes: [UInt8]) -> String {
        return Data(bytes).base64EncodedString()
    }
}

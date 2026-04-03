import { NativeModules, Platform } from 'react-native';

// =============================================================================
// Types
// =============================================================================

export interface PublicIdentity {
  did: string;
  publicKey: string; // base64
  kyberPublicKey: string; // base64
  nodeId: string; // base64
}

export interface IdentityInfo {
  did: string;
  deviceId: string;
  nodeId: string; // base64
  publicKey: string; // base64
  kyberPublicKey: string; // base64
  createdAt: number;
}

export interface HandshakeResult {
  sessionId: string; // base64
  peerDid: string;
  peerPublicKey: string; // base64
}

// =============================================================================
// Native Module Interface
// =============================================================================

interface NativeIdentityProvisioningInterface {
  // Identity Generation
  generateIdentity(deviceId: string): Promise<IdentityInfo>;
  restoreIdentityFromSeed(masterSeedBase64: string, deviceId: string): Promise<IdentityInfo>;
  getPublicIdentity(): Promise<PublicIdentity>;
  signRegistrationProof(timestamp: number): Promise<string>; // base64 signature
  signMessage(messageBase64: string): Promise<string>; // base64 signature
  signPouwReceipt(receiptJson: string): Promise<string>; // base64 signature
  exportKeystoreForCICD(): Promise<string>; // base64 keystore tarball for GitHub Actions

  // UHP v2 Handshake
  initHandshake(channelBindingBase64: string): Promise<boolean>;
  createClientHello(): Promise<string>; // base64
  processServerHello(serverHelloBase64: string): Promise<string>; // base64 ClientFinish
  finalizeHandshake(): Promise<HandshakeResult>;

  // Session Encryption
  encrypt(plaintextBase64: string): Promise<string>; // base64 ciphertext
  decrypt(ciphertextBase64: string): Promise<string>; // base64 plaintext

  // Identity Persistence
  exportIdentityEncrypted(passwordBase64: string): Promise<string>; // base64 encrypted
  importIdentityEncrypted(encryptedBase64: string, passwordBase64: string): Promise<IdentityInfo>;
  getMasterSeedForBackup(): Promise<string>; // base64 seed
  getSeedPhraseForBackup(): Promise<string>; // 24-word phrase

  // Utility
  hasIdentity(): Promise<boolean>;
  hasSession(): Promise<boolean>;
  getCurrentDid(): Promise<string>;
  clearSession(): Promise<boolean>;
  clearAll(): Promise<boolean>;
}

// =============================================================================
// Module Loading
// =============================================================================

const LINKING_ERROR =
  `The package 'NativeIdentityProvisioning' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- The ZhtpClient.xcframework is properly linked in Xcode\n' +
  '- You are not using Expo Go (native modules require a development build)';

const NativeIdentityProvisioningModule = NativeModules.NativeIdentityProvisioning
  ? (NativeModules.NativeIdentityProvisioning as NativeIdentityProvisioningInterface)
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    ) as NativeIdentityProvisioningInterface;

// =============================================================================
// Exported Wrapper Class
// =============================================================================

/**
 * ZHTP Identity Provisioning for React Native
 *
 * Provides post-quantum cryptographic identity management:
 * - Dilithium5 digital signatures
 * - Kyber1024 key encapsulation
 * - UHP v2 mutual authentication
 * - ChaCha20-Poly1305 session encryption
 *
 * SECURITY: Private keys never leave native code.
 * All cryptographic operations happen in Swift/Rust.
 */
export class IdentityProvisioning {
  private static instance: IdentityProvisioning | null = null;

  static getInstance(): IdentityProvisioning {
    if (!IdentityProvisioning.instance) {
      IdentityProvisioning.instance = new IdentityProvisioning();
    }
    return IdentityProvisioning.instance;
  }

  // ---------------------------------------------------------------------------
  // Identity Management
  // ---------------------------------------------------------------------------

  /**
   * Generate a new identity with post-quantum keys.
   * Keys are generated locally and NEVER leave the device.
   */
  async generateIdentity(deviceId: string): Promise<IdentityInfo> {
    return NativeIdentityProvisioningModule.generateIdentity(deviceId);
  }

  /**
   * Restore identity from master seed (for recovery/migration).
   * @param masterSeed - 32-byte seed as base64
   */
  async restoreFromSeed(masterSeed: string, deviceId: string): Promise<IdentityInfo> {
    return NativeIdentityProvisioningModule.restoreIdentityFromSeed(masterSeed, deviceId);
  }

  /**
   * Get public identity (safe to send to server for registration).
   */
  async getPublicIdentity(): Promise<PublicIdentity> {
    return NativeIdentityProvisioningModule.getPublicIdentity();
  }

  /**
   * Sign a registration proof for server registration.
   */
  async signRegistrationProof(timestamp: number = Date.now()): Promise<string> {
    return NativeIdentityProvisioningModule.signRegistrationProof(timestamp);
  }

  /**
   * Sign an arbitrary message.
   * @param message - Message as base64
   */
  async signMessage(message: string): Promise<string> {
    return NativeIdentityProvisioningModule.signMessage(message);
  }

  /**
   * Sign a PoUW receipt JSON payload using canonical bincode receipt encoding.
   */
  async signPouwReceipt(receiptJson: string): Promise<string> {
    return NativeIdentityProvisioningModule.signPouwReceipt(receiptJson);
  }

  // ---------------------------------------------------------------------------
  // UHP v2 Handshake
  // ---------------------------------------------------------------------------

  /**
   * Initialize a new handshake with channel binding.
   * Call this before starting the 3-leg handshake.
   */
  async initHandshake(channelBinding: string): Promise<void> {
    await NativeIdentityProvisioningModule.initHandshake(channelBinding);
  }

  /**
   * Step 1: Create ClientHello message.
   * Send the returned bytes to the server.
   */
  async createClientHello(): Promise<string> {
    return NativeIdentityProvisioningModule.createClientHello();
  }

  /**
   * Step 2: Process ServerHello and create ClientFinish.
   * Send the returned ClientFinish bytes to the server.
   */
  async processServerHello(serverHello: string): Promise<string> {
    return NativeIdentityProvisioningModule.processServerHello(serverHello);
  }

  /**
   * Step 3: Finalize handshake and establish session.
   * After this, you can use encrypt/decrypt.
   */
  async finalizeHandshake(): Promise<HandshakeResult> {
    return NativeIdentityProvisioningModule.finalizeHandshake();
  }

  // ---------------------------------------------------------------------------
  // Session Encryption
  // ---------------------------------------------------------------------------

  /**
   * Encrypt data using the current session.
   * Requires completed handshake.
   */
  async encrypt(plaintext: string): Promise<string> {
    return NativeIdentityProvisioningModule.encrypt(plaintext);
  }

  /**
   * Decrypt data using the current session.
   * Requires completed handshake.
   */
  async decrypt(ciphertext: string): Promise<string> {
    return NativeIdentityProvisioningModule.decrypt(ciphertext);
  }

  // ---------------------------------------------------------------------------
  // Identity Persistence
  // ---------------------------------------------------------------------------

  /**
   * Export identity encrypted with a password.
   * Store the result securely (e.g., Keychain).
   */
  async exportEncrypted(password: string): Promise<string> {
    const passwordBase64 = Buffer.from(password, 'utf-8').toString('base64');
    return NativeIdentityProvisioningModule.exportIdentityEncrypted(passwordBase64);
  }

  /**
   * Get the 24-word seed phrase for backup.
   */
  async getSeedPhraseForBackup(): Promise<string> {
    return NativeIdentityProvisioningModule.getSeedPhraseForBackup();
  }

  /**
   * Import identity from encrypted backup.
   */
  async importEncrypted(encrypted: string, password: string): Promise<IdentityInfo> {
    const passwordBase64 = Buffer.from(password, 'utf-8').toString('base64');
    return NativeIdentityProvisioningModule.importIdentityEncrypted(encrypted, passwordBase64);
  }

  /**
   * Get master seed for backup.
   * WARNING: This is sensitive! Show appropriate warnings to user.
   */
  async getMasterSeedForBackup(): Promise<string> {
    return NativeIdentityProvisioningModule.getMasterSeedForBackup();
  }

  /**
   * Export keystore for CI/CD deployment (GitHub Actions).
   * Returns base64-encoded tarball to store as ZHTP_KEYSTORE_B64 secret.
   * WARNING: This contains private keys! Handle with care.
   */
  async exportKeystoreForCICD(): Promise<string> {
    return NativeIdentityProvisioningModule.exportKeystoreForCICD();
  }

  // ---------------------------------------------------------------------------
  // State Management
  // ---------------------------------------------------------------------------

  async hasIdentity(): Promise<boolean> {
    return NativeIdentityProvisioningModule.hasIdentity();
  }

  async hasSession(): Promise<boolean> {
    return NativeIdentityProvisioningModule.hasSession();
  }

  async getCurrentDid(): Promise<string> {
    return NativeIdentityProvisioningModule.getCurrentDid();
  }

  async clearSession(): Promise<void> {
    await NativeIdentityProvisioningModule.clearSession();
  }

  async clearAll(): Promise<void> {
    await NativeIdentityProvisioningModule.clearAll();
  }
}

// =============================================================================
// Convenience Exports
// =============================================================================

export const identityProvisioning = IdentityProvisioning.getInstance();

export default NativeIdentityProvisioningModule;

/**
 * ZHTP Proof-of-Useful-Work (PoUW) Controller for React Native
 *
 * Captures Web4 routing and content-serving events and submits them as
 * PoUW receipts to the node's reward gateway.
 *
 * Integrates with the existing `IdentityProvisioning` native module for
 * signing receipts using the device's ZHTP identity key.
 *
 * Reference: PoUW-BETA #1353
 */

import { NativeModules, Platform } from 'react-native';
import { identityProvisioning } from './NativeIdentityProvisioning';

// =============================================================================
// Constants
// =============================================================================

const POUW_VERSION = 1;
const DEFAULT_BATCH_INTERVAL_MS = 30_000; // 30 seconds
const DEFAULT_MAX_BATCH_SIZE = 20;
const MIN_BYTES_PER_RECEIPT = 1024;

// =============================================================================
// Types
// =============================================================================

/** PoUW proof types mirroring server-side ProofType enum */
export type ProofType =
  | 'hash'
  | 'merkle'
  | 'signature'
  | 'web4manifestroute'
  | 'web4contentserved';

/** Receipt submitted by the client after completing useful work */
export interface Receipt {
  version: number;
  task_id: string;       // hex
  client_did: string;
  client_node_id: string; // hex
  provider_id: string;    // hex
  content_id: string;     // hex
  proof_type: ProofType;
  bytes_verified: number;
  result_ok: boolean;
  started_at: number;     // unix seconds
  finished_at: number;    // unix seconds
  receipt_nonce: string;  // hex
  challenge_nonce: string; // hex
  aux?: string;           // JSON string with Web4 context fields
}

/** Receipt with client's signature */
export interface SignedReceipt {
  receipt: Receipt;
  sig_scheme: string;
  signature: string; // hex
}

/** Batch of receipts for submission to /api/v1/pouw/submit */
export interface ReceiptBatch {
  version: number;
  client_did: string;
  receipts: SignedReceipt[];
}

/** Server response from /api/v1/pouw/submit */
export interface SubmitResponse {
  accepted: string[];
  rejected: Array<{ receipt_nonce: string; reason: string }>;
  server_time: number;
}

/** Challenge token issued by the node */
export interface ChallengeToken {
  version: number;
  node_id: string;        // hex
  task_id: string;        // hex
  challenge_nonce: string; // hex
  issued_at: number;
  expires_at: number;
  policy: {
    max_receipts: number;
    max_bytes_total: number;
    min_bytes_per_receipt: number;
    allowed_proof_types: ProofType[];
  };
  node_signature: string; // hex
}

/** Config for PoUWController */
export interface PoUWControllerConfig {
  /** Base URL of the node's API (e.g., "https://node.example.sov:9334") */
  nodeApiBase: string;
  /** Interval between batch submissions in milliseconds */
  batchIntervalMs?: number;
  /** Maximum receipts per batch */
  maxBatchSize?: number;
}

// =============================================================================
// Helpers
// =============================================================================

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function base64ToHex(b64: string): string {
  const binary = atob(b64);
  let hex = '';
  for (let i = 0; i < binary.length; i++) {
    hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBase64(hex: string): string {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return btoa(String.fromCharCode(...bytes));
}

// =============================================================================
// PoUWController
// =============================================================================

/**
 * PoUW Controller for React Native apps.
 *
 * Usage:
 * ```ts
 * const pouw = PoUWController.getInstance({
 *   nodeApiBase: 'https://node.sovereign.network:9334',
 * });
 * await pouw.start();
 *
 * // When device routes a Web4 manifest through the mesh:
 * await pouw.recordWeb4ManifestRoute({
 *   manifestCid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
 *   domain: 'central.sov',
 *   routeHops: 3,
 *   manifestSizeBytes: 4096,
 *   quicSessionId: sessionIdBytes,  // 8 bytes from UHP v2 session
 * });
 * ```
 */
export class PoUWController {
  private static instance: PoUWController | null = null;

  private config: Required<PoUWControllerConfig>;
  private pendingReceipts: SignedReceipt[] = [];
  private activeChallenge: ChallengeToken | null = null;
  private batchTimer: ReturnType<typeof setInterval> | null = null;
  private clientDid: string | null = null;
  private clientNodeId: string | null = null;
  private isRunning = false;

  private constructor(config: PoUWControllerConfig) {
    this.config = {
      nodeApiBase: config.nodeApiBase,
      batchIntervalMs: config.batchIntervalMs ?? DEFAULT_BATCH_INTERVAL_MS,
      maxBatchSize: config.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE,
    };
  }

  static getInstance(config?: PoUWControllerConfig): PoUWController {
    if (!PoUWController.instance) {
      if (!config) {
        throw new Error('PoUWController must be initialized with config on first call');
      }
      PoUWController.instance = new PoUWController(config);
    }
    return PoUWController.instance;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Start the PoUW controller.
   * Fetches initial identity info and starts the batch submission timer.
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    // Load current DID and node ID
    const identity = await identityProvisioning.getPublicIdentity();
    this.clientDid = identity.did;
    this.clientNodeId = base64ToHex(identity.nodeId);

    // Fetch initial challenge
    await this._refreshChallenge(['web4manifestroute', 'web4contentserved', 'hash']);

    // Start periodic batch submission
    this.batchTimer = setInterval(() => {
      this._submitBatch().catch(() => {
        // Silently swallow — next tick will retry
      });
    }, this.config.batchIntervalMs);

    this.isRunning = true;
  }

  /** Stop the PoUW controller and flush any pending receipts. */
  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
    if (this.pendingReceipts.length > 0) {
      await this._submitBatch();
    }
    this.isRunning = false;
  }

  // ---------------------------------------------------------------------------
  // Web4 Receipt Recording
  // ---------------------------------------------------------------------------

  /**
   * Record that the device successfully routed a Web4 manifest request
   * through the mesh network.
   *
   * Called by the mesh routing layer on successful manifest delivery.
   *
   * @param opts.manifestCid - CID of the manifest that was routed
   * @param opts.domain - .sov domain associated with the manifest
   * @param opts.routeHops - Number of mesh hops used
   * @param opts.manifestSizeBytes - Size of the manifest in bytes
   * @param opts.quicSessionId - First 8 bytes of the UHP v2 QUIC session ID
   */
  async recordWeb4ManifestRoute(opts: {
    manifestCid: string;
    domain: string;
    routeHops: number;
    manifestSizeBytes: number;
    quicSessionId: Uint8Array; // 8 bytes
  }): Promise<void> {
    const bytes = Math.max(opts.manifestSizeBytes, MIN_BYTES_PER_RECEIPT);
    const aux = JSON.stringify({
      manifest_cid: opts.manifestCid,
      domain: opts.domain,
      route_hops: opts.routeHops,
      quic_session_id: bytesToHex(opts.quicSessionId.slice(0, 8)),
    });
    await this._createAndQueueReceipt('web4manifestroute', bytes, aux);
  }

  /**
   * Record that the device served Web4 content to a requesting peer,
   * optionally from its local cache.
   *
   * Called by the Web4 content cache layer on a successful cache serve.
   *
   * @param opts.manifestCid - CID of the manifest for the served content
   * @param opts.domain - .sov domain associated with the content
   * @param opts.contentSizeBytes - Size of the content served in bytes
   * @param opts.servedFromCache - Whether the content was served from cache
   * @param opts.quicSessionId - First 8 bytes of the UHP v2 QUIC session ID
   */
  async recordWeb4ContentServed(opts: {
    manifestCid: string;
    domain: string;
    contentSizeBytes: number;
    servedFromCache: boolean;
    quicSessionId: Uint8Array; // 8 bytes
  }): Promise<void> {
    const bytes = Math.max(opts.contentSizeBytes, MIN_BYTES_PER_RECEIPT);
    const aux = JSON.stringify({
      manifest_cid: opts.manifestCid,
      domain: opts.domain,
      served_from_cache: opts.servedFromCache,
      quic_session_id: bytesToHex(opts.quicSessionId.slice(0, 8)),
    });
    await this._createAndQueueReceipt('web4contentserved', bytes, aux);
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  /**
   * Build, sign, and queue a receipt.
   */
  private async _createAndQueueReceipt(
    proofType: ProofType,
    bytesVerified: number,
    aux: string,
  ): Promise<void> {
    // Ensure we have a fresh challenge
    await this._ensureChallenge([proofType]);
    if (!this.activeChallenge) return;
    if (!this.clientDid || !this.clientNodeId) return;

    const now = nowSecs();
    const receipt: Receipt = {
      version: POUW_VERSION,
      task_id: this.activeChallenge.task_id,
      client_did: this.clientDid,
      client_node_id: this.clientNodeId,
      provider_id: '',
      content_id: randomHex(32),
      proof_type: proofType,
      bytes_verified: bytesVerified,
      result_ok: true,
      started_at: now - 1,
      finished_at: now,
      receipt_nonce: randomHex(32),
      challenge_nonce: this.activeChallenge.challenge_nonce,
      aux,
    };

    const signed = await this._signReceipt(receipt);
    this.pendingReceipts.push(signed);

    // Submit immediately if batch is full
    if (this.pendingReceipts.length >= this.config.maxBatchSize) {
      await this._submitBatch();
    }
  }

  /**
   * Sign a receipt using the device's identity key.
   * Serializes the receipt to JSON and signs with the native signMessage method.
   */
  private async _signReceipt(receipt: Receipt): Promise<SignedReceipt> {
    // Canonical serialization: sort keys for determinism
    const receiptBytes = JSON.stringify(receipt, Object.keys(receipt).sort());
    const receiptB64 = btoa(receiptBytes);
    const sigB64 = await identityProvisioning.signMessage(receiptB64);

    return {
      receipt,
      // Canonical PoUW submit path uses Dilithium5 only.
      sig_scheme: 'dilithium5',
      signature: base64ToHex(sigB64),
    };
  }

  /**
   * Submit the pending batch to the node's /api/v1/pouw/submit endpoint.
   */
  private async _submitBatch(): Promise<SubmitResponse | null> {
    if (this.pendingReceipts.length === 0) return null;
    if (!this.clientDid) return null;

    const toSubmit = this.pendingReceipts.splice(0, this.config.maxBatchSize);

    const batch: ReceiptBatch = {
      version: POUW_VERSION,
      client_did: this.clientDid,
      receipts: toSubmit,
    };

    try {
      const response = await fetch(`${this.config.nodeApiBase}/api/v1/pouw/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batch),
      });

      if (!response.ok) {
        // Re-queue on transient errors (will retry next tick)
        this.pendingReceipts.unshift(...toSubmit);
        return null;
      }

      return (await response.json()) as SubmitResponse;
    } catch {
      // Network error — re-queue for next batch
      this.pendingReceipts.unshift(...toSubmit);
      return null;
    }
  }

  /**
   * Ensure we have a valid, non-expired challenge that allows the given proof type.
   * Fetches a new challenge from the node if needed.
   */
  private async _ensureChallenge(proofTypes: ProofType[]): Promise<void> {
    const now = nowSecs();
    const hasValid =
      this.activeChallenge !== null &&
      this.activeChallenge.expires_at > now + 60 &&
      proofTypes.every(pt =>
        this.activeChallenge!.policy.allowed_proof_types.includes(pt),
      );

    if (!hasValid) {
      await this._refreshChallenge(proofTypes);
    }
  }

  /**
   * Fetch a new challenge from the node.
   */
  private async _refreshChallenge(proofTypes: ProofType[]): Promise<void> {
    const cap = proofTypes.join(',');
    try {
      const response = await fetch(
        `${this.config.nodeApiBase}/api/v1/pouw/challenge?cap=${encodeURIComponent(cap)}`,
      );
      if (!response.ok) return;

      const data = await response.json();
      // Token is base64-encoded JSON
      const tokenJson = atob(data.token);
      this.activeChallenge = JSON.parse(tokenJson) as ChallengeToken;
    } catch {
      // Challenge fetch failed — receipts will accumulate until next refresh
    }
  }

  // ---------------------------------------------------------------------------
  // Status / Debug
  // ---------------------------------------------------------------------------

  /** Number of receipts waiting to be submitted */
  get pendingCount(): number {
    return this.pendingReceipts.length;
  }

  /** Whether the controller is actively running */
  get running(): boolean {
    return this.isRunning;
  }

  /** Current active challenge expiry (unix seconds), or 0 if none */
  get challengeExpiresAt(): number {
    return this.activeChallenge?.expires_at ?? 0;
  }
}

// =============================================================================
// Convenience export
// =============================================================================

export default PoUWController;

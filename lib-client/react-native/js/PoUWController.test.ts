/**
 * Unit tests for PoUWController Web4 receipt construction.
 *
 * Tests run with Jest in a Node environment (no native modules needed)
 * because we mock IdentityProvisioning.
 *
 * Reference: PoUW-BETA #1353
 */

import { PoUWController } from './PoUWController';

// ---------------------------------------------------------------------------
// Mock native module
// ---------------------------------------------------------------------------

jest.mock('./NativeIdentityProvisioning', () => ({
  identityProvisioning: {
    getPublicIdentity: jest.fn().mockResolvedValue({
      did: 'did:zhtp:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // 32 bytes base64
      kyberPublicKey: 'AAAA',
      nodeId: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    }),
    signMessage: jest.fn().mockResolvedValue(
      // Mock 64-byte Ed25519 signature, base64
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ),
  },
}));

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock atob/btoa for Node.js environment
if (typeof atob === 'undefined') {
  (global as any).atob = (b64: string) =>
    Buffer.from(b64, 'base64').toString('binary');
  (global as any).btoa = (str: string) =>
    Buffer.from(str, 'binary').toString('base64');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_NODE_API = 'http://localhost:9334';
const TEST_SESSION_ID = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

function makeMockChallenge(proofTypes: string[]) {
  const token = JSON.stringify({
    version: 1,
    node_id: 'aa'.repeat(32),
    task_id: 'bb'.repeat(16),
    challenge_nonce: 'cc'.repeat(32),
    issued_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    policy: {
      max_receipts: 20,
      max_bytes_total: 10 * 1024 * 1024,
      min_bytes_per_receipt: 1024,
      allowed_proof_types: proofTypes,
    },
    node_signature: 'dd'.repeat(64),
  });
  return {
    token: btoa(token),
    expires_at: Math.floor(Date.now() / 1000) + 3600,
  };
}

function makeSubmitResponse() {
  return {
    accepted: ['nonce1'],
    rejected: [],
    server_time: Math.floor(Date.now() / 1000),
  };
}

function resetControllerSingleton() {
  // Access private static field for test isolation
  (PoUWController as any).instance = null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PoUWController', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetControllerSingleton();
  });

  // -------------------------------------------------------------------------
  // Test 1: Web4ManifestRoute receipt construction
  // -------------------------------------------------------------------------
  test('recordWeb4ManifestRoute creates a valid Web4ManifestRoute receipt', async () => {
    // Setup: mock challenge fetch + submit
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeMockChallenge(['web4manifestroute', 'web4contentserved', 'hash']),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeSubmitResponse(),
      });

    const controller = PoUWController.getInstance({ nodeApiBase: TEST_NODE_API });
    await controller.start();

    await controller.recordWeb4ManifestRoute({
      manifestCid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
      domain: 'central.sov',
      routeHops: 3,
      manifestSizeBytes: 4096,
      quicSessionId: TEST_SESSION_ID,
    });

    // Should have 1 pending receipt
    expect(controller.pendingCount).toBe(1);

    // Force submission
    await (controller as any)._submitBatch();

    const submitCall = mockFetch.mock.calls.find(
      ([url]: [string]) => url.includes('/api/v1/pouw/submit'),
    );
    expect(submitCall).toBeDefined();

    const body = JSON.parse(submitCall[1].body);
    expect(body.receipts).toHaveLength(1);

    const signed = body.receipts[0];
    expect(signed.receipt.proof_type).toBe('web4manifestroute');
    expect(signed.receipt.bytes_verified).toBeGreaterThanOrEqual(1024);
    expect(signed.receipt.challenge_nonce).toBe('cc'.repeat(32));
    expect(signed.receipt.task_id).toBe('bb'.repeat(16));
    expect(signed.sig_scheme).toBe('ed25519');
    expect(signed.signature).toBeTruthy();

    // Verify aux fields
    const aux = JSON.parse(signed.receipt.aux);
    expect(aux.manifest_cid).toBe(
      'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
    );
    expect(aux.domain).toBe('central.sov');
    expect(aux.route_hops).toBe(3);
    expect(aux.quic_session_id).toBe('0102030405060708');

    await controller.stop();
  });

  // -------------------------------------------------------------------------
  // Test 2: Web4ContentServed receipt construction
  // -------------------------------------------------------------------------
  test('recordWeb4ContentServed creates a valid Web4ContentServed receipt', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeMockChallenge(['web4manifestroute', 'web4contentserved', 'hash']),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeSubmitResponse(),
      });

    const controller = PoUWController.getInstance({ nodeApiBase: TEST_NODE_API });
    await controller.start();

    await controller.recordWeb4ContentServed({
      manifestCid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
      domain: 'app.sov',
      contentSizeBytes: 65536,
      servedFromCache: true,
      quicSessionId: TEST_SESSION_ID,
    });

    expect(controller.pendingCount).toBe(1);
    await (controller as any)._submitBatch();

    const submitCall = mockFetch.mock.calls.find(
      ([url]: [string]) => url.includes('/api/v1/pouw/submit'),
    );
    const body = JSON.parse(submitCall[1].body);
    const signed = body.receipts[0];

    expect(signed.receipt.proof_type).toBe('web4contentserved');
    expect(signed.receipt.bytes_verified).toBe(65536);

    const aux = JSON.parse(signed.receipt.aux);
    expect(aux.manifest_cid).toBeTruthy();
    expect(aux.served_from_cache).toBe(true);
    expect(aux.quic_session_id).toBe('0102030405060708');

    await controller.stop();
  });

  // -------------------------------------------------------------------------
  // Test 3: Both receipt types are included in the same batch
  // -------------------------------------------------------------------------
  test('manifest route and content served receipts are batched together', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeMockChallenge(['web4manifestroute', 'web4contentserved', 'hash']),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => makeSubmitResponse(),
      });

    const controller = PoUWController.getInstance({ nodeApiBase: TEST_NODE_API });
    await controller.start();

    await controller.recordWeb4ManifestRoute({
      manifestCid: 'cid1',
      domain: 'foo.sov',
      routeHops: 2,
      manifestSizeBytes: 2048,
      quicSessionId: TEST_SESSION_ID,
    });
    await controller.recordWeb4ContentServed({
      manifestCid: 'cid2',
      domain: 'bar.sov',
      contentSizeBytes: 8192,
      servedFromCache: false,
      quicSessionId: TEST_SESSION_ID,
    });

    expect(controller.pendingCount).toBe(2);
    await (controller as any)._submitBatch();

    const submitCall = mockFetch.mock.calls.find(
      ([url]: [string]) => url.includes('/api/v1/pouw/submit'),
    );
    const body = JSON.parse(submitCall[1].body);
    expect(body.receipts).toHaveLength(2);

    const types = body.receipts.map((r: any) => r.receipt.proof_type);
    expect(types).toContain('web4manifestroute');
    expect(types).toContain('web4contentserved');

    await controller.stop();
  });

  // -------------------------------------------------------------------------
  // Test 4: QUIC session ID is correctly captured in aux
  // -------------------------------------------------------------------------
  test('quic_session_id hex in aux is exactly 8 bytes from the provided session ID', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeMockChallenge(['web4manifestroute', 'web4contentserved', 'hash']),
    });

    const controller = PoUWController.getInstance({ nodeApiBase: TEST_NODE_API });
    await controller.start();

    // Session ID longer than 8 bytes — only first 8 should be used
    const longSessionId = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02]);
    await controller.recordWeb4ManifestRoute({
      manifestCid: 'cid',
      domain: 'test.sov',
      routeHops: 1,
      manifestSizeBytes: 1024,
      quicSessionId: longSessionId,
    });

    const pending = (controller as any).pendingReceipts;
    const aux = JSON.parse(pending[0].receipt.aux);
    expect(aux.quic_session_id).toBe('deadbeefcafebabe'); // exactly 8 bytes
    expect(aux.quic_session_id).toHaveLength(16); // 8 bytes = 16 hex chars

    await controller.stop();
  });

  // -------------------------------------------------------------------------
  // Test 5: Minimum bytes enforcement (manifestSizeBytes < MIN = clamped to MIN)
  // -------------------------------------------------------------------------
  test('bytes_verified is clamped to minimum 1024 when input is smaller', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => makeMockChallenge(['web4manifestroute', 'web4contentserved', 'hash']),
    });

    const controller = PoUWController.getInstance({ nodeApiBase: TEST_NODE_API });
    await controller.start();

    await controller.recordWeb4ManifestRoute({
      manifestCid: 'cid',
      domain: 'test.sov',
      routeHops: 1,
      manifestSizeBytes: 100, // below minimum
      quicSessionId: TEST_SESSION_ID,
    });

    const pending = (controller as any).pendingReceipts;
    expect(pending[0].receipt.bytes_verified).toBe(1024);

    await controller.stop();
  });
});

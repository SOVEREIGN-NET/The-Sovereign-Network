/**
 * ZHTP wire protocol encoding/decoding
 * 4-byte big-endian length prefix + CBOR payload
 * Max message size: 16MB
 *
 * V2 MAC uses HMAC-SHA3-256 with canonical request format matching Rust server.
 */

import { encode, decode } from 'cbor';
import { sha3_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { ZhtpRequest, ZhtpResponse } from './types.js';

const MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB
const FRAME_HEADER_SIZE = 4; // 4-byte big-endian length

/**
 * Encode ZHTP request to wire format
 */
export function encodeRequest(request: ZhtpRequest): Uint8Array {
  const payload = encode({
    method: request.method,
    path: request.path,
    sessionId: request.sessionId,
    sequence: Number(request.sequence),
    timestamp: Number(request.timestamp),
    body: request.body,
    requestMac: Array.from(request.requestMac),
  });

  const length = payload.byteLength;
  if (length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${length} > ${MAX_MESSAGE_SIZE}`);
  }

  // Prepend 4-byte big-endian length
  const frame = new Uint8Array(FRAME_HEADER_SIZE + length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, length, false); // false = big-endian
  frame.set(payload, FRAME_HEADER_SIZE);

  return frame;
}

/**
 * Decode ZHTP response from wire format
 */
export function decodeResponse(frame: Uint8Array): ZhtpResponse {
  if (frame.length < FRAME_HEADER_SIZE) {
    throw new Error('Frame too small');
  }

  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const length = view.getUint32(0, false); // false = big-endian

  if (frame.length < FRAME_HEADER_SIZE + length) {
    throw new Error(`Incomplete frame: expected ${length}, got ${frame.length - FRAME_HEADER_SIZE}`);
  }

  if (length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${length} > ${MAX_MESSAGE_SIZE}`);
  }

  const payload = frame.subarray(FRAME_HEADER_SIZE, FRAME_HEADER_SIZE + length);
  const decoded = decode(payload) as Record<string, any>;

  return {
    statusCode: decoded.statusCode || 200,
    headers: decoded.headers || {},
    body: decoded.body ? new Uint8Array(decoded.body) : undefined,
  };
}

/**
 * Method byte constants (must match Rust CanonicalRequest)
 */
const METHOD_GET = 0;
const METHOD_POST = 1;
const METHOD_PUT = 2;
const METHOD_DELETE = 3;

/**
 * Convert method string to byte
 */
function methodToByte(method: string): number {
  switch (method.toUpperCase()) {
    case 'GET': return METHOD_GET;
    case 'POST': return METHOD_POST;
    case 'PUT': return METHOD_PUT;
    case 'DELETE': return METHOD_DELETE;
    default: return METHOD_GET;
  }
}

/**
 * Build canonical request bytes (must match Rust CanonicalRequest::to_bytes)
 *
 * Wire format:
 * - method: 1 byte (0=GET, 1=POST, 2=PUT, 3=DELETE)
 * - path_len: u16 BE
 * - path: UTF-8 bytes
 * - body_len: u32 BE
 * - body: raw bytes
 */
export function buildCanonicalRequest(
  method: string,
  path: string,
  body?: Uint8Array,
): Uint8Array {
  const methodByte = methodToByte(method);
  const pathBytes = new TextEncoder().encode(path);
  const bodyBytes = body || new Uint8Array(0);

  // Calculate total size: 1 + 2 + path.len + 4 + body.len
  const totalSize = 1 + 2 + pathBytes.length + 4 + bodyBytes.length;
  const canonical = new Uint8Array(totalSize);
  const view = new DataView(canonical.buffer);

  let offset = 0;

  // Method (1 byte)
  canonical[offset++] = methodByte;

  // Path length (u16 BE) + path bytes
  view.setUint16(offset, pathBytes.length, false); // big-endian
  offset += 2;
  canonical.set(pathBytes, offset);
  offset += pathBytes.length;

  // Body length (u32 BE) + body bytes
  view.setUint32(offset, bodyBytes.length, false); // big-endian
  offset += 4;
  canonical.set(bodyBytes, offset);

  return canonical;
}

/**
 * Compute V2 request MAC using HMAC-SHA3-256
 *
 * MAC = HMAC-SHA3-256(mac_key, canonical_bytes(request) || counter || session_id)
 *
 * Must match Rust compute_v2_mac in lib-network/src/handshake/security.rs
 *
 * @param macKey - 32-byte MAC key derived from session
 * @param method - HTTP method (GET, POST, PUT, DELETE)
 * @param path - Request path
 * @param sessionId - 32-byte session ID (as Uint8Array, not string)
 * @param counter - Request counter (u64)
 * @param body - Optional request body
 */
export function computeRequestMac(
  macKey: Uint8Array,
  sessionId: Uint8Array,
  method: string,
  path: string,
  counter: bigint,
  body?: Uint8Array,
): Uint8Array {
  // Build canonical request bytes
  const canonicalBytes = buildCanonicalRequest(method, path, body);

  // Counter as u64 big-endian
  const counterBytes = new Uint8Array(8);
  const counterView = new DataView(counterBytes.buffer);
  counterView.setBigUint64(0, counter, false); // big-endian

  // Combine: canonical_bytes || counter || session_id
  const combined = new Uint8Array(canonicalBytes.length + 8 + 32);
  let offset = 0;

  combined.set(canonicalBytes, offset);
  offset += canonicalBytes.length;

  combined.set(counterBytes, offset);
  offset += 8;

  combined.set(sessionId, offset);

  // HMAC-SHA3-256
  return hmac(sha3_256, macKey, combined);
}

/**
 * Verify request MAC
 */
export function verifyRequestMac(
  macKey: Uint8Array,
  sessionId: Uint8Array,
  method: string,
  path: string,
  counter: bigint,
  body: Uint8Array | undefined,
  providedMac: Uint8Array,
): boolean {
  const computed = computeRequestMac(macKey, sessionId, method, path, counter, body);
  return constantTimeEquals(computed, providedMac);
}

/**
 * Constant-time comparison to prevent timing attacks
 */
function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * Increment sequence number atomically
 */
export function incrementSequence(current: bigint): bigint {
  return current + 1n;
}

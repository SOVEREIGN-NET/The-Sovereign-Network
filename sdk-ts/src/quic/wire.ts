/**
 * ZHTP wire protocol encoding/decoding
 * 4-byte big-endian length prefix + CBOR payload
 * Max message size: 16MB
 */

import { encode, decode } from 'cbor';
import { blake3 } from '@noble/hashes/blake3';
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
 * Compute request MAC using BLAKE3-HMAC
 * MAC = BLAKE3-HMAC(appKey, sessionId || sequence || bodyHash)
 */
export function computeRequestMac(
  appKey: Uint8Array,
  sessionId: string,
  sequence: bigint,
  body?: Uint8Array,
): Uint8Array {
  // Hash body if present
  let bodyHash: Uint8Array;
  if (body && body.length > 0) {
    bodyHash = blake3(body);
  } else {
    bodyHash = new Uint8Array(32); // Zero hash for empty body
  }

  // Combine: sessionId || sequence || bodyHash
  const sessionIdBytes = new TextEncoder().encode(sessionId);
  const sequenceBytes = new Uint8Array(8);
  const view = new DataView(sequenceBytes.buffer);
  view.setBigInt64(0, sequence, false); // false = big-endian

  const combined = new Uint8Array(sessionIdBytes.length + 8 + 32);
  combined.set(sessionIdBytes, 0);
  combined.set(sequenceBytes, sessionIdBytes.length);
  combined.set(bodyHash, sessionIdBytes.length + 8);

  // BLAKE3-HMAC (key is first 32 bytes of appKey, or full appKey if longer)
  return blake3.create(appKey).update(combined).digest();
}

/**
 * Verify request MAC
 */
export function verifyRequestMac(
  appKey: Uint8Array,
  sessionId: string,
  sequence: bigint,
  body: Uint8Array | undefined,
  providedMac: Uint8Array,
): boolean {
  const computed = computeRequestMac(appKey, sessionId, sequence, body);
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

/**
 * Default header used to transport the masked auth payload between client
 * and server. The value carried by this header is a single base64-encoded
 * JSON object containing `x-api-key`, `x-timestamp`, `x-nonce`, `x-signature`.
 */
export const DEFAULT_HEADER_NAME = 'X-Signature';

/**
 * Default allowed clock skew between client and server, in seconds.
 *
 * 5 minutes is the industry standard (matches AWS SigV4 and most cloud APIs).
 * Lower → safer against replay, but more sensitive to clock drift.
 * Higher → more forgiving of unsynced clocks, but widens the replay window.
 */
export const DEFAULT_TIMESTAMP_WINDOW_SECONDS = 300;

/**
 * Default HMAC algorithm. SHA-256 is the recommended baseline.
 * SHA-512 is supported as an opt-in for callers who want a wider digest.
 */
export const DEFAULT_SIGNATURE_ALGORITHM = 'sha256' as const;

/**
 * Field names inside the inner (decoded) auth payload.
 * Lowercase form because, after JSON-decoding, these are object keys, not
 * HTTP headers. They mirror typical HTTP header naming for familiarity.
 */
export const PAYLOAD_FIELDS = {
  apiKey: 'x-api-key',
  timestamp: 'x-timestamp',
  nonce: 'x-nonce',
  signature: 'x-signature',
} as const;

/**
 * Protocol version. Reserved for future use — currently always 1.
 * If the wire format changes, bump this and add a `x-version` field
 * to the inner payload.
 */
export const PROTOCOL_VERSION = 1;

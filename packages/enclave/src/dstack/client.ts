/**
 * DstackClient port: the only view of the TEE key agent the rest of this
 * package sees. `real.ts` adapts the vendor SDK; `fake.ts` is deterministic
 * for tests and local runs. Callers never import the vendor SDK directly, so
 * a vendor exit is one new adapter.
 */

/** dstack GetKey returns a 32-byte secp256k1 scalar. */
export const DSTACK_KEY_BYTES = 32;

/** TDX quote report_data is at most 64 bytes; the agent zero-pads shorter input. */
export const DSTACK_REPORT_DATA_MAX_BYTES = 64;

/** Signature chain links are recoverable secp256k1 signatures: r || s || recid. */
export const SIGNATURE_CHAIN_LINK_BYTES = 65;

export interface DstackInfo {
  /** KMS namespace for key derivation. Same appId => same keys on any node. */
  appId: string;
  /** Hash of the running app-compose; changes with every compose edit. */
  composeHash: string;
  /** This CVM instance. Differs between replicas of one app. */
  instanceId: string;
  /** Guest agent version when the agent exposes it (dstack >= 0.5.7). */
  osVersion?: string;
}

/**
 * Derived key plus the evidence that it came from this app on a genuine TEE.
 *
 *   signatureChain[0]: app root key over keccak256(purpose || ":" || hex(pubkey))
 *   signatureChain[1]: KMS root over keccak256("dstack-kms-issued" || ":" || appId || sec1(appRootPubkey))
 *
 * A verifier recovers the app root key from [0], then checks [1] against the
 * published KMS root. Only `path` shapes `key`; `purpose` is only in [0].
 */
export interface DerivedKey {
  key: Uint8Array;
  signatureChain: Uint8Array[];
}

export interface DstackQuote {
  quote: Uint8Array;
  eventLog?: string;
}

export interface DstackClient {
  info(): Promise<DstackInfo>;
  deriveKey(path: string, purpose: string): Promise<DerivedKey>;
  quote(reportData: Uint8Array): Promise<DstackQuote>;
}

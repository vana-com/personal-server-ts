/**
 * §2.1 namespace and key check, §2.3 control-row hashes.
 *
 *   K_ns     = deriveScopeKey(masterKey, NAMESPACE_KEY_LABEL)   (host)
 *   ns       = hex(first 8 bytes of HMAC-SHA256(K_ns, utf8(canonicalJson([c, accountId]))))
 *   keyCheck = hex(first 8 bytes of HMAC-SHA256(K_ns, utf8("key-check")))
 *
 * The host derives K_ns and passes an HMAC port bound to it.
 */

import {
  HEX16,
  keccakHex,
  toHex,
  utf8,
  type Keccak256,
  type NamespaceHmac,
} from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import { canonicalJson } from "./json.js";

/** The `deriveScopeKey` label the host uses to derive `K_ns`. */
export const NAMESPACE_KEY_LABEL = "pdpp-stream-sync/namespace/v1";

/** The namespace of connectors that declare no account identity. */
export const IDENTITYLESS_NS = "";

export const KEY_CHECK_MESSAGE = "key-check";
export const ACTIVE_DATA_PREFIX = "pdpp.stream-sync.connection.active.v1:";
export const ACTIVE_METADATA_LABEL =
  "pdpp.stream-sync.connection.active.metadata.v1";
/** Same labels as the Personal Server tombstone constants. */
export const TOMBSTONE_DATA_LABEL = "vana.data-point.tombstone.v1";
export const TOMBSTONE_METADATA_LABEL = "vana.data-point.tombstone.metadata.v1";

async function first8Hex(
  hmac: NamespaceHmac,
  message: Uint8Array,
): Promise<string> {
  const digest = await hmac(message);
  if (digest.length < 8) {
    throw new InvalidArgumentError(
      "namespace HMAC returned fewer than 8 bytes",
    );
  }
  return toHex(digest.subarray(0, 8));
}

export async function deriveNs(
  hmac: NamespaceHmac,
  connector: string,
  accountId: string,
): Promise<string> {
  if (typeof accountId !== "string" || accountId === "") {
    throw new InvalidArgumentError(
      "accountId must be a non-empty string; identity-less connectors use IDENTITYLESS_NS",
    );
  }
  return first8Hex(hmac, utf8(canonicalJson([connector, accountId])));
}

export async function deriveKeyCheck(hmac: NamespaceHmac): Promise<string> {
  return first8Hex(hmac, utf8(KEY_CHECK_MESSAGE));
}

export interface ControlHashes {
  /** keccak256("pdpp.stream-sync.connection.active.v1:" + keyCheck) */
  readonly activeData: `0x${string}`;
  readonly activeMetadata: `0x${string}`;
  readonly tombstoneData: `0x${string}`;
  readonly tombstoneMetadata: `0x${string}`;
}

/** The registry hashes a device writes and recognises for its own key. */
export async function controlHashes(
  keccak256: Keccak256,
  keyCheck: string,
): Promise<ControlHashes> {
  if (!HEX16.test(keyCheck)) {
    throw new InvalidArgumentError("keyCheck must be 16 lowercase hex");
  }
  return {
    activeData: await keccakHex(keccak256, utf8(ACTIVE_DATA_PREFIX + keyCheck)),
    activeMetadata: await keccakHex(keccak256, utf8(ACTIVE_METADATA_LABEL)),
    tombstoneData: await keccakHex(keccak256, utf8(TOMBSTONE_DATA_LABEL)),
    tombstoneMetadata: await keccakHex(
      keccak256,
      utf8(TOMBSTONE_METADATA_LABEL),
    ),
  };
}

/**
 * Deterministic in-process DstackClient for tests and DSTACK_FAKE=1 runs.
 *
 * Mirrors the 0.5.x agent: an app root key is fixed by appId, and a derived
 * key is HKDF-SHA256(salt "RATLS", app root key, info = path). `purpose` does
 * not touch the key; it only appears in signatureChain[0], exactly as on the
 * real agent. Two fakes with one appId agree on every key, as two CVMs under
 * one app_id do. Fake app IDs use the real agent's bare 40-character hex
 * form. Signature chains are real secp256k1 signatures over the real agent's
 * messages, so a verifier can be tested here; the "KMS root" is a fixed fake
 * key, so nothing here is attested.
 */

import { createHash, hkdfSync } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, toHex } from "viem";
import { sign } from "viem/accounts";
import {
  DSTACK_KEY_BYTES,
  type DerivedKey,
  type DstackClient,
  type DstackInfo,
  type DstackQuote,
} from "./client.js";

const HKDF_DIGEST = "sha256";
/** Same salt the guest agent uses for path derivation. */
const DSTACK_KDF_SALT = "RATLS";
/** Fake-only salt turning appId into an app root key. */
const FAKE_APP_ROOT_SALT = "vana.ps-enclave.fake-dstack.app-root.v1";
/** Fake KMS root: fixed so chains from any fake instance verify alike. */
const FAKE_KMS_ROOT_KEY = createHash("sha256")
  .update("vana.ps-enclave.fake-dstack.kms-root.v1")
  .digest();
const KMS_ISSUED_PREFIX = "dstack-kms-issued";
const DEFAULT_COMPOSE_HASH = "fake-compose-hash";
const DEFAULT_INSTANCE_ID = "fake-instance";
const COMPRESSED = true;
const APP_ID_PATTERN = /^[0-9a-f]{40}$/;

export interface FakeDstackOptions {
  appId: string;
  composeHash?: string;
  instanceId?: string;
}

export function createFakeDstackClient(
  options: FakeDstackOptions,
): DstackClient {
  if (!APP_ID_PATTERN.test(options.appId)) {
    throw new Error("fake dstack appId must be 40 lowercase hex characters");
  }

  const info: DstackInfo = {
    appId: options.appId,
    composeHash: options.composeHash ?? DEFAULT_COMPOSE_HASH,
    instanceId: options.instanceId ?? DEFAULT_INSTANCE_ID,
    osVersion: "fake",
  };
  const appRootKey = fakeAppRootKey(options.appId);

  return {
    info: async () => ({ ...info }),
    deriveKey: (path, purpose) =>
      fakeDerivedKey(options.appId, appRootKey, path, purpose),
    quote: async (reportData) => fakeQuote(options.appId, reportData),
  };
}

/** Public key of the fake KMS root, for verifier tests. */
export function fakeKmsRootPublicKey(): Uint8Array {
  return secp256k1.getPublicKey(FAKE_KMS_ROOT_KEY, COMPRESSED);
}

function fakeAppRootKey(appId: string): Uint8Array {
  return hkdf(Buffer.from(appId, "utf8"), FAKE_APP_ROOT_SALT, "");
}

async function fakeDerivedKey(
  appId: string,
  appRootKey: Uint8Array,
  path: string,
  purpose: string,
): Promise<DerivedKey> {
  const key = hkdf(appRootKey, DSTACK_KDF_SALT, path);
  const pubkeyHex = Buffer.from(
    secp256k1.getPublicKey(key, COMPRESSED),
  ).toString("hex");
  const appRootPubkey = secp256k1.getPublicKey(appRootKey, COMPRESSED);

  const link0 = await signLink(appRootKey, `${purpose}:${pubkeyHex}`);
  const link1 = await signLink(
    FAKE_KMS_ROOT_KEY,
    Buffer.concat([
      Buffer.from(`${KMS_ISSUED_PREFIX}:`, "utf8"),
      Buffer.from(appId, "hex"),
      appRootPubkey,
    ]),
  );

  return { key, signatureChain: [link0, link1] };
}

function hkdf(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return new Uint8Array(
    hkdfSync(
      HKDF_DIGEST,
      ikm,
      Buffer.from(salt, "utf8"),
      Buffer.from(info, "utf8"),
      DSTACK_KEY_BYTES,
    ),
  );
}

// r || s || recid, the agent's `sign_digest_recoverable` layout.
async function signLink(
  privateKey: Uint8Array,
  message: string | Uint8Array,
): Promise<Uint8Array> {
  const hash = keccak256(
    typeof message === "string" ? Buffer.from(message, "utf8") : message,
  );
  const { r, s, yParity } = await sign({ hash, privateKey: toHex(privateKey) });

  return Buffer.concat([
    Buffer.from(r.slice(2).padStart(64, "0"), "hex"),
    Buffer.from(s.slice(2).padStart(64, "0"), "hex"),
    Buffer.from([yParity ?? 0]),
  ]);
}

// Not a TDX quote: a stable digest so callers can exercise plumbing.
function fakeQuote(appId: string, reportData: Uint8Array): DstackQuote {
  const quote = createHash("sha256")
    .update(appId, "utf8")
    .update(reportData)
    .digest();

  return { quote: new Uint8Array(quote), eventLog: "[]" };
}

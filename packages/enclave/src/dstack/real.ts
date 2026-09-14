/**
 * Real DstackClient over the dstack guest agent socket.
 *
 * Vendor surface relied on: @phala/dstack-sdk 0.5.8, pinned exactly. This is
 * the v0 API matching dstack OS 0.5.x (checked 2026-09-02 against
 * dist/index.d.mts of the published tarball, and confirmed against a live
 * dstack 0.5.9 guest agent):
 *
 *   new DstackClient(endpoint?: string)
 *     probes /var/run/dstack.sock, /run/dstack.sock, /var/run/dstack/dstack.sock,
 *     /run/dstack/dstack.sock; DSTACK_SIMULATOR_ENDPOINT overrides.
 *   getKey(path?: string, purpose?: string, algorithm?: string)
 *     : Promise<{ key: Uint8Array(32); signature_chain: Uint8Array[2] }>
 *   info(): Promise<{ app_id; instance_id; app_cert; tcb_info; compose_hash; os_image_hash; ... }>
 *   getQuote(report_data: string | Buffer | Uint8Array)
 *     : Promise<{ quote: Hex; event_log: string }>
 *   version(): Promise<{ version: string; rev: string }>   // agent >= 0.5.7, throws older
 *
 * Key derivation (guest-agent v0.5.8 `get_key`):
 *   key = HKDF-SHA256(salt = "RATLS", ikm = app_root_key, info = path, 32 bytes)
 * Only `path` enters the KDF. `purpose` and `algorithm` are NOT
 * domain-separating: they only shape signature_chain[0]. Distinct paths per
 * use are what keep the wallet key and the sealing key apart.
 *
 * Signature chain (both links r || s || recid, 65 bytes):
 *   [0] app root key over keccak256(purpose || ":" || hex(pubkey))
 *   [1] KMS root  over keccak256("dstack-kms-issued" || ":" || app_id || sec1_compressed(app_root_pubkey))
 *
 * Why pinned: dstack 0.6 exposes a `/v1` API with a different KDF ("v1 keys
 * are not v0 keys"); moving the image to 0.6 rotates every derived wallet.
 * Do not use TappdClient (0.3.x, /var/run/tappd.sock).
 */

import { DstackClient as SdkDstackClient } from "@phala/dstack-sdk";
import {
  DSTACK_KEY_BYTES,
  DSTACK_REPORT_DATA_MAX_BYTES,
  type DerivedKey,
  type DstackClient,
  type DstackInfo,
  type DstackQuote,
} from "./client.js";

const SECP256K1 = "secp256k1";
const HEX_PREFIX = "0x";

export function createRealDstackClient(endpoint?: string): DstackClient {
  const sdk = new SdkDstackClient(endpoint);

  return {
    info: () => readInfo(sdk),
    deriveKey: (path, purpose) => readKey(sdk, path, purpose),
    quote: (reportData) => readQuote(sdk, reportData),
  };
}

// compose_hash sits at the top level on 0.5.x agents and inside tcb_info on
// the same OS line; older agents carry it only in the event log, so it may
// come back empty there.
async function readInfo(sdk: SdkDstackClient): Promise<DstackInfo> {
  const info = await sdk.info();
  const osImageHash = info.os_image_hash ?? info.tcb_info?.os_image_hash;

  return {
    appId: info.app_id,
    composeHash: info.compose_hash ?? info.tcb_info?.compose_hash ?? "",
    instanceId: info.instance_id,
    ...(osImageHash === undefined ? {} : { osImageHash }),
    osVersion: await readVersion(sdk),
  };
}

// Older agents lack the Version RPC; the field is optional for that reason.
async function readVersion(sdk: SdkDstackClient): Promise<string | undefined> {
  try {
    const { version } = await sdk.version();
    return version;
  } catch {
    return undefined;
  }
}

async function readKey(
  sdk: SdkDstackClient,
  path: string,
  purpose: string,
): Promise<DerivedKey> {
  const { key, signature_chain } = await sdk.getKey(path, purpose, SECP256K1);

  if (key.length !== DSTACK_KEY_BYTES) {
    throw new Error(
      `dstack GetKey returned ${key.length} bytes, expected ${DSTACK_KEY_BYTES}`,
    );
  }

  return { key, signatureChain: signature_chain };
}

async function readQuote(
  sdk: SdkDstackClient,
  reportData: Uint8Array,
): Promise<DstackQuote> {
  if (reportData.length > DSTACK_REPORT_DATA_MAX_BYTES) {
    throw new Error(
      `report data is ${reportData.length} bytes, max ${DSTACK_REPORT_DATA_MAX_BYTES}`,
    );
  }

  const result = await sdk.getQuote(reportData);
  const hex = result.quote.startsWith(HEX_PREFIX)
    ? result.quote.slice(HEX_PREFIX.length)
    : result.quote;

  return {
    quote: new Uint8Array(Buffer.from(hex, "hex")),
    eventLog: result.event_log,
  };
}

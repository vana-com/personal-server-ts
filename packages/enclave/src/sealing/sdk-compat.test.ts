/**
 * An unsealed signature re-derives the SDK scope key and decrypts a real SDK
 * OpenPGP blob:
 *
 *   owner wallet ─sign "vana-master-key-v1"─> signature (65 bytes)
 *   signature ─deriveScopeKey─> scope key ─OpenPGP─> blob ciphertext (fixture)
 *   node A: seal(signature)            node B: unseal -> re-derive -> decrypt
 */

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  MASTER_KEY_MESSAGE,
  decryptWithPassword,
  deriveMasterKey,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/node";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createFakeDstackClient } from "../dstack/fake.js";
import { userPsId } from "../identity/paths.js";
import { seal, unseal } from "./envelope.js";

const APP = "identity-app";
const CHAIN_ID = 14800;
const SCOPE = "fixture";
const BLOB_BYTES = 1024;
const MASTER_SIGNATURE_BYTES = 65;

// PS hex-encodes the scope key without 0x as the OpenPGP password
// (packages/core/src/sync/workers/upload.ts).
function scopePassword(signature: `0x${string}`): string {
  return Buffer.from(
    deriveScopeKey(deriveMasterKey(signature), SCOPE),
  ).toString("hex");
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// ~1 KB JSON document, padded to the target size.
function fixtureBlob(): Uint8Array {
  const doc = { scope: SCOPE, items: [] as string[] };
  while (JSON.stringify(doc).length < BLOB_BYTES) {
    doc.items.push(`item-${doc.items.length}`);
  }

  return new TextEncoder().encode(JSON.stringify(doc));
}

describe("SDK sealing compatibility", () => {
  it("seals on node A, unseals on node B, decrypts the blob", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const signature = await owner.signMessage({ message: MASTER_KEY_MESSAGE });
    const id = userPsId(CHAIN_ID, owner.address);

    const plaintext = fixtureBlob();
    const blob = await encryptWithPassword(plaintext, scopePassword(signature));

    const nodeA = createFakeDstackClient({ appId: APP, instanceId: "node-a" });
    const envelope = await seal(nodeA, id, deriveMasterKey(signature));

    const nodeB = createFakeDstackClient({ appId: APP, instanceId: "node-b" });
    const unsealed = await unseal(nodeB, id, envelope);
    const recovered = `0x${Buffer.from(unsealed).toString("hex")}` as const;
    const decrypted = await decryptWithPassword(blob, scopePassword(recovered));

    expect(unsealed).toHaveLength(MASTER_SIGNATURE_BYTES);
    expect(recovered).toBe(signature);
    expect(sha256(decrypted)).toBe(sha256(plaintext));
    expect(plaintext.length).toBeGreaterThanOrEqual(BLOB_BYTES);
    expect(JSON.stringify(envelope).length).toBeLessThan(BLOB_BYTES);
  });

  it("negative: envelope re-labelled for another user does not open", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const signature = await owner.signMessage({ message: MASTER_KEY_MESSAGE });
    const node = createFakeDstackClient({ appId: APP });

    const envelope = await seal(
      node,
      userPsId(CHAIN_ID, owner.address),
      deriveMasterKey(signature),
    );
    const other = userPsId(
      CHAIN_ID,
      privateKeyToAccount(generatePrivateKey()).address,
    );

    await expect(unseal(node, other, envelope)).rejects.toThrow();
  });
});

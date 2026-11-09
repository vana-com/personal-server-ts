/**
 * One owner signature has three byte forms that all verify: canonical
 * (v = 27/28, low s), v = 0/1, and the high-s twin (s' = n - s, v flipped).
 * The writer normalizes the signature before it derives stream keys, so the
 * reader must derive the same keys from every form.
 */

import { deriveKeyCheck } from "@opendatalabs/personal-server-ts-stream-sync";
import { hexToBytes, keccak256, parseSignature, toBytes, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { createStreamSyncKeyPorts } from "../stream-sync/crypto.js";
import { createStreamSyncReadKeys } from "./keys.js";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;

// A fixed test key, not a secret.
const account = privateKeyToAccount(
  "0x4242424242424242424242424242424242424242424242424242424242424242",
);
const signed = parseSignature(
  await account.sign({ hash: keccak256(toBytes("vana-master-key-v1")) }),
);
const r = BigInt(signed.r);
const s = BigInt(signed.s);
const parity = signed.yParity ?? 0;

const bytes65 = (rr: bigint, ss: bigint, v: number): Uint8Array => {
  const out = new Uint8Array(65);
  out.set(hexToBytes(toHex(rr, { size: 32 })), 0);
  out.set(hexToBytes(toHex(ss, { size: 32 })), 32);
  out[64] = v;
  return out;
};

if (s > HALF_N) throw new Error("viem returned a high-s signature");

const CANONICAL = bytes65(r, s, 27 + parity);
const V01 = bytes65(r, s, parity);
const HIGH_S = bytes65(r, N - s, 27 + (1 - parity));

const FORMS = {
  canonical: CANONICAL,
  "v=0/1": V01,
  "high-s twin": HIGH_S,
} as const;

const SCOPE = "pdpp.c~.s";
const CLEAR = new TextEncoder().encode("part bytes");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// The writer path: keys from the canonical signature, as the writer derives them.
const writer = createStreamSyncKeyPorts(CANONICAL);
const writerKeyCheck = await deriveKeyCheck((message) =>
  writer.namespaceHmac(message),
);
const CIPHER = await writer.encrypt(SCOPE, CLEAR);

describe("createStreamSyncReadKeys over every form of one owner signature", () => {
  it("writer and reader agree on the canonical form", async () => {
    const reader = await createStreamSyncReadKeys(CANONICAL);
    expect(reader.keyCheck).toBe(writerKeyCheck);
    expect(hex(await reader.decrypt(SCOPE, CIPHER))).toBe(hex(CLEAR));
  });

  describe.each(Object.entries(FORMS))("form %s", (_name, form) => {
    it("derives the writer's keyCheck", async () => {
      const reader = await createStreamSyncReadKeys(form);
      expect(reader.keyCheck).toBe(writerKeyCheck);
    });

    it("decrypts what the writer encrypted", async () => {
      const reader = await createStreamSyncReadKeys(form);
      expect(hex(await reader.decrypt(SCOPE, CIPHER))).toBe(hex(CLEAR));
    });
  });
});

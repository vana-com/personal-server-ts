import { describe, expect, it } from "vitest";

import { canonicalizeJson } from "../derivatives/e2ee/jcs.js";
import type { Grant } from "../pdpp/types.js";

import vectors from "./__fixtures__/grant-fingerprint-vectors.json";
import {
  GRANT_FINGERPRINT_DOMAIN,
  grantFingerprint,
  grantMatchesFingerprint,
  isGrantFingerprint,
  isGrantSalt,
  newGrantSalt,
} from "./grant-fingerprint.js";

const first = vectors.vectors[0]!;
const grant = first.grant as Grant;

describe("grant fingerprint", () => {
  it.each(vectors.vectors)(
    "matches the shared vector: $name",
    async ({ grant, salt, canonical, fingerprint }) => {
      expect(
        canonicalizeJson({ domain: GRANT_FINGERPRINT_DOMAIN, salt, grant }),
      ).toBe(canonical);
      expect(await grantFingerprint(grant as Grant, salt)).toBe(fingerprint);
    },
  );

  it("fits one on-chain slot entry and never looks like a scope name", async () => {
    const entry = await grantFingerprint(grant, first.salt);
    expect(new TextEncoder().encode(entry).length).toBeLessThanOrEqual(128);
    expect(isGrantFingerprint(entry)).toBe(true);
    expect(isGrantFingerprint("chatgpt.conversations")).toBe(false);
  });

  it("does not depend on member order or on members that are undefined", async () => {
    const reordered = Object.fromEntries(
      Object.entries(grant).reverse(),
    ) as unknown as Grant;
    const withUndefined = { ...grant, expires_at: undefined } as Grant;
    expect(await grantFingerprint(reordered, first.salt)).toBe(
      first.fingerprint,
    );
    expect(await grantFingerprint(withUndefined, first.salt)).toBe(
      first.fingerprint,
    );
  });

  it("changes with any change to the terms", async () => {
    const narrowed: Grant = {
      ...grant,
      streams: [{ ...grant.streams[0]!, fields: ["id", "title"] }],
    };
    expect(await grantFingerprint(narrowed, first.salt)).not.toBe(
      first.fingerprint,
    );
  });

  it("matches only the grant and salt it was made from", async () => {
    expect(
      await grantMatchesFingerprint(grant, first.salt, first.fingerprint),
    ).toBe(true);
    expect(
      await grantMatchesFingerprint(grant, newGrantSalt(), first.fingerprint),
    ).toBe(false);
    expect(
      await grantMatchesFingerprint(
        grant,
        first.salt,
        first.fingerprint.toUpperCase(),
      ),
    ).toBe(false);
    expect(await grantMatchesFingerprint(grant, "not-a-salt", "gf1:00")).toBe(
      false,
    );
  });

  it("refuses a salt that is not 32 bytes of lowercase hex", async () => {
    for (const salt of ["", "00", "A".repeat(64), "0x" + "00".repeat(31)]) {
      expect(isGrantSalt(salt)).toBe(false);
      await expect(grantFingerprint(grant, salt)).rejects.toThrow(TypeError);
    }
  });

  it("draws a new salt each time", () => {
    const a = newGrantSalt();
    expect(isGrantSalt(a)).toBe(true);
    expect(newGrantSalt()).not.toBe(a);
  });
});

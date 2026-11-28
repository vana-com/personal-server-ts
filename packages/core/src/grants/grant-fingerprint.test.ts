import { describe, expect, it } from "vitest";

import { canonicalizeJson } from "../derivatives/e2ee/jcs.js";
import type { Grant } from "../pdpp/types.js";

import vectors from "./__fixtures__/grant-fingerprint-vectors.json";
import {
  canonicalDataScopes,
  GRANT_FINGERPRINT_DOMAIN,
  grantFingerprint,
  grantMatchesFingerprint,
  isGrantFingerprint,
  isGrantSalt,
  newGrantSalt,
} from "./grant-fingerprint.js";

const first = vectors.vectors[0]!;
const grant = first.grant as Grant;
const scopes = first.data_scopes;

describe("grant fingerprint", () => {
  it.each(vectors.vectors)(
    "matches the shared vector: $name",
    async ({ grant, data_scopes, salt, canonical, fingerprint }) => {
      expect(
        canonicalizeJson({
          domain: GRANT_FINGERPRINT_DOMAIN,
          salt,
          grant,
          data_scopes: canonicalDataScopes(data_scopes),
        }),
      ).toBe(canonical);
      expect(await grantFingerprint(grant as Grant, data_scopes, salt)).toBe(
        fingerprint,
      );
    },
  );

  it("fits one on-chain slot entry and never looks like a scope name", async () => {
    const entry = await grantFingerprint(grant, scopes, first.salt);
    expect(new TextEncoder().encode(entry).length).toBeLessThanOrEqual(128);
    expect(isGrantFingerprint(entry)).toBe(true);
    expect(isGrantFingerprint("chatgpt.conversations")).toBe(false);
  });

  it("does not depend on member order or on members that are undefined", async () => {
    const reordered = Object.fromEntries(
      Object.entries(grant).reverse(),
    ) as unknown as Grant;
    const withUndefined = { ...grant, expires_at: undefined } as Grant;
    expect(await grantFingerprint(reordered, scopes, first.salt)).toBe(
      first.fingerprint,
    );
    expect(await grantFingerprint(withUndefined, scopes, first.salt)).toBe(
      first.fingerprint,
    );
  });

  it("does not depend on member order at any depth", async () => {
    const reorder = (value: unknown): unknown =>
      Array.isArray(value)
        ? value.map(reorder)
        : value !== null && typeof value === "object"
          ? Object.fromEntries(
              Object.entries(value)
                .reverse()
                .map(([k, v]) => [k, reorder(v)]),
            )
          : value;
    expect(
      await grantFingerprint(reorder(grant) as Grant, scopes, first.salt),
    ).toBe(first.fingerprint);
  });

  it("changes when a stream's field list changes", async () => {
    const narrowed: Grant = {
      ...grant,
      streams: [{ ...grant.streams[0]!, fields: ["id", "title"] }],
    };
    expect(await grantFingerprint(narrowed, scopes, first.salt)).not.toBe(
      first.fingerprint,
    );
  });

  it("changes when the data scopes change", async () => {
    const wider = [...scopes, "pdpp.chatgpt.messages"];
    expect(await grantFingerprint(grant, wider, first.salt)).not.toBe(
      first.fingerprint,
    );
  });

  it("matches only the grant, data scopes and salt it was made from", async () => {
    expect(
      await grantMatchesFingerprint(
        grant,
        scopes,
        first.salt,
        first.fingerprint,
      ),
    ).toBe(true);
    expect(
      await grantMatchesFingerprint(
        grant,
        scopes,
        newGrantSalt(),
        first.fingerprint,
      ),
    ).toBe(false);
    expect(
      await grantMatchesFingerprint(
        grant,
        ["pdpp.chatgpt.messages"],
        first.salt,
        first.fingerprint,
      ),
    ).toBe(false);
    expect(
      await grantMatchesFingerprint(
        grant,
        scopes,
        first.salt,
        first.fingerprint.toUpperCase(),
      ),
    ).toBe(false);
    expect(
      await grantMatchesFingerprint(grant, scopes, "not-a-salt", "gf1:00"),
    ).toBe(false);
    expect(
      await grantMatchesFingerprint(grant, [], first.salt, first.fingerprint),
    ).toBe(false);
  });

  it("refuses an empty data scope list or a name that is not printable ASCII", async () => {
    for (const bad of [
      [],
      [""],
      ["pdpp.chatgpt messages"],
      ["pdpp.é"],
      ["a".repeat(129)],
    ]) {
      expect(canonicalDataScopes(bad)).toBeNull();
      await expect(grantFingerprint(grant, bad, first.salt)).rejects.toThrow(
        TypeError,
      );
    }
    expect(canonicalDataScopes(["b", "a", "b"])).toEqual(["a", "b"]);
  });

  it("refuses a salt that is not 32 bytes of lowercase hex", async () => {
    for (const salt of ["", "00", "A".repeat(64), "0x" + "00".repeat(31)]) {
      expect(isGrantSalt(salt)).toBe(false);
      await expect(grantFingerprint(grant, scopes, salt)).rejects.toThrow(
        TypeError,
      );
    }
  });

  it("draws a new salt each time", () => {
    const a = newGrantSalt();
    expect(isGrantSalt(a)).toBe(true);
    expect(newGrantSalt()).not.toBe(a);
  });
});

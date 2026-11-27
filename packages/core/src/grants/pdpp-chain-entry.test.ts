/**
 * Design-2 grant fingerprint, checked against the data gateway's own
 * implementation (data-gateway `lib/pdpp-grants.ts` at 002541d,
 * `computePdppGrantEntry` / `canonicalJson`). The expected values below were
 * printed by running that file on exactly this input; any drift here means
 * `POST /v1/grants` answers PDPP_GRANT_HASH_MISMATCH.
 */

import { describe, expect, it } from "vitest";
import {
  computePdppGrantEntry,
  isPdppGrantEntry,
  newPdppGrantSalt,
  pdppCanonicalJson,
} from "./pdpp-chain-entry.js";

const grant = {
  version: "0.1.0",
  grant_id: "grt_0123456789abcdef01234567",
  issued_at: "2026-11-26T10:00:00.000Z",
  subject: { id: "pws_AbC-_xyz" },
  client: {
    client_id: "https://app.example/client.json",
    client_display: { name: 'Café ☕ \u0007 "q"' },
  },
  source: {
    kind: "connector",
    id: "https://registry.pdpp.dev/connectors/oura",
  },
  source_declaration: { version: "v1" },
  purpose_code: "https://pdpp.dev/purpose/personalization",
  access_mode: "continuous",
  streams: [
    {
      name: "sleep",
      instance_ids: ["i1"],
      fields: ["day", "score"],
      required_fields: ["day"],
      time_constraint: { type: "date", field: "day", since: "2026-01-01" },
    },
  ],
  retention: { max_duration: "P30D" },
  expires_at: "2027-11-26T10:00:00.000Z",
  n: [1, 0.5, -0, 1e21, 123456789012],
  emoji: "😀",
};
const salt = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

describe("design-2 PDPP grant entry (gateway golden vector)", () => {
  it("canonicalizes exactly as the gateway does (RFC 8785)", () => {
    expect(pdppCanonicalJson(grant)).toBe(
      '{"access_mode":"continuous","client":{"client_display":{"name":"Café ☕ \\u0007 \\"q\\""},"client_id":"https://app.example/client.json"},"emoji":"😀","expires_at":"2027-11-26T10:00:00.000Z","grant_id":"grt_0123456789abcdef01234567","issued_at":"2026-11-26T10:00:00.000Z","n":[1,0.5,0,1e+21,123456789012],"purpose_code":"https://pdpp.dev/purpose/personalization","retention":{"max_duration":"P30D"},"source":{"id":"https://registry.pdpp.dev/connectors/oura","kind":"connector"},"source_declaration":{"version":"v1"},"streams":[{"fields":["day","score"],"instance_ids":["i1"],"name":"sleep","required_fields":["day"],"time_constraint":{"field":"day","since":"2026-01-01","type":"date"}}],"subject":{"id":"pws_AbC-_xyz"},"version":"0.1.0"}',
    );
  });

  it("computes the gateway's entry for (grant, salt)", () => {
    expect(computePdppGrantEntry(grant, salt)).toBe(
      "pdpp:sha256:5d27b4adb45ab010f2d6edc24bfb2dde2acd9081e19db1c3ef9231ed650dd091",
    );
  });

  it("is independent of member order and moves with the salt", () => {
    const reordered = JSON.parse(JSON.stringify(grant), (_k, v) =>
      v && typeof v === "object" && !Array.isArray(v)
        ? Object.fromEntries(Object.entries(v).reverse())
        : v,
    );
    expect(computePdppGrantEntry(reordered, salt)).toBe(
      computePdppGrantEntry(grant, salt),
    );
    expect(computePdppGrantEntry(grant, "f".repeat(64))).not.toBe(
      computePdppGrantEntry(grant, salt),
    );
  });

  it("refuses non-I-JSON input and malformed salts", () => {
    expect(() => computePdppGrantEntry({ a: "\ud800" }, salt)).toThrow();
    expect(() => computePdppGrantEntry({ a: Number.NaN }, salt)).toThrow();
    expect(() => computePdppGrantEntry({ a: undefined }, salt)).toThrow();
    expect(() => computePdppGrantEntry(grant, "ABC")).toThrow();
    expect(() => computePdppGrantEntry(grant, salt.toUpperCase())).toThrow();
  });

  it("draws 32-byte lowercase hex salts and well-formed entries", () => {
    const a = newPdppGrantSalt();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(newPdppGrantSalt()).not.toBe(a);
    expect(isPdppGrantEntry(computePdppGrantEntry(grant, a))).toBe(true);
  });
});

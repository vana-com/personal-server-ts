import { describe, expect, it } from "vitest";
import { canonicalJson } from "./envelope.js";
import { receiveReplicaManifest } from "./receive.js";
import {
  decodeReplicaManifest,
  prepareReplicaManifest,
  REPLICA_MAX_FRAGMENTS,
  REPLICA_MAX_JSON_DEPTH,
  replicaDigest,
  ReplicaManifestRefused,
  replicaScope,
} from "./transport.js";
import { unsignedReplicaBatch } from "./writer-identity.test-utils.js";

const owner = `0x${"1".repeat(40)}`;
const writer = "a".repeat(32);
const scope = replicaScope(writer);
const collectedAt = "2026-10-27T00:00:00.000Z";

async function manifestText(count = 3) {
  const manifest = await prepareReplicaManifest({
    owner,
    writer,
    version: 2,
    batch: "b".repeat(32),
    sequence: 2,
    previous: {
      batch: "c".repeat(32),
      digest: replicaDigest(new Uint8Array([1])),
    },
    collectedAt,
    digest: replicaDigest(new Uint8Array([2])),
    totalBytes: count * 3000,
    fragments: Array.from({ length: count }, (_, index) => ({
      digest: `sha256:${index.toString(16).padStart(64, "0")}`,
      bytes: 8000,
    })),
    sign: unsignedReplicaBatch,
    encrypt: async (_scope, bytes) => bytes,
  });
  return new TextDecoder().decode(manifest.plaintext);
}

/** Through the boundary with identity crypto and a commitment that always matches. */
const receive = (plaintext: Uint8Array) =>
  receiveReplicaManifest({
    scope,
    owner,
    maxBytes: 64 * 1024 * 1024,
    read: async () => plaintext,
    decrypt: async (bytes) => bytes,
    committed: () => true,
  });

/** Whether the bytes name a `collectedAt`, without which no commitment can match. */
function namesCollectedAt(text: string) {
  try {
    const value: unknown = JSON.parse(text);
    return (
      typeof value === "object" &&
      value !== null &&
      typeof (value as { collectedAt?: unknown }).collectedAt === "string"
    );
  } catch {
    return false;
  }
}

function nested(depth: number) {
  return `${"[".repeat(depth)}0${"]".repeat(depth)}`;
}

it("accepts an honest manifest at the fragment limit inside the JSON bounds", async () => {
  const text = await manifestText(REPLICA_MAX_FRAGMENTS);
  const receipt = await receive(new TextEncoder().encode(text));
  expect(receipt.tag).toBe("manifest");
}, 60000);

it("refuses an authentic wrapper nested past the depth bound, before parsing", async () => {
  // The review's wrapper: 6000 nested arrays beside a valid collectedAt.
  const text = `{"collectedAt":${JSON.stringify(collectedAt)},"data":{"manifest":null,"padding":${nested(6000)}},"scope":${JSON.stringify(scope)},"version":"1.0"}`;
  const plaintext = new TextEncoder().encode(text);
  await expect(receive(plaintext)).resolves.toEqual({
    tag: "refused",
    reason: "manifest_invalid",
  });
  expect(() => decodeReplicaManifest(plaintext, scope, owner)).toThrow(
    new ReplicaManifestRefused("manifest_invalid"),
  );
  // One level inside the bound still parses; it fails only as a manifest.
  const inside = text.replace(nested(6000), nested(REPLICA_MAX_JSON_DEPTH - 3));
  await expect(receive(new TextEncoder().encode(inside))).resolves.toEqual({
    tag: "refused",
    reason: "manifest_invalid",
  });
});

it("refuses a wrapper of tiny values past the token bound, before parsing", async () => {
  const padding = `[${"0,".repeat(9 * REPLICA_MAX_FRAGMENTS)}0]`;
  const text = `{"collectedAt":${JSON.stringify(collectedAt)},"data":{"manifest":null,"padding":${padding}},"scope":${JSON.stringify(scope)},"version":"1.0"}`;
  await expect(receive(new TextEncoder().encode(text))).resolves.toEqual({
    tag: "refused",
    reason: "manifest_invalid",
  });
});

describe("random and mutated manifests", () => {
  /** mulberry32: a small seeded generator, so a failure replays. */
  function random(seed: number) {
    return () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  type Json =
    null | boolean | number | string | Json[] | { [key: string]: Json };

  function value(next: () => number, depth = 0): Json {
    const pick = Math.floor(next() * (depth > 3 ? 6 : 9));
    switch (pick) {
      case 0:
        return null;
      case 1:
        return next() < 0.5;
      case 2:
        return [0, -1, 1.5, 2 ** 53, 1e308, -0][Math.floor(next() * 6)]!;
      case 3:
        return [
          "",
          "x".repeat(Math.floor(next() * 5000)),
          "\u0000\ud800",
          collectedAt,
        ][Math.floor(next() * 4)]!;
      case 4:
        return `sha256:${"f".repeat(64)}`;
      case 5:
        return Math.floor(next() * 1e6);
      case 6:
        return Array.from({ length: Math.floor(next() * 4) }, () =>
          value(next, depth + 1),
        );
      case 7:
        return Object.fromEntries(
          Array.from({ length: Math.floor(next() * 4) }, (_, index) => [
            ["bytes", "digest", "owner", "fragments", "authority", `k${index}`][
              Math.floor(next() * 6)
            ]!,
            value(next, depth + 1),
          ]),
        );
      default:
        return JSON.parse(nested(1 + Math.floor(next() * 40))) as Json;
    }
  }

  /** Replace, delete or add one node of the decoded wrapper. */
  function mutate(root: Json, next: () => number) {
    const containers: { [key: string]: Json }[] | Json[][] = [];
    const walk = (node: Json) => {
      if (node !== null && typeof node === "object") {
        (containers as unknown[]).push(node);
        for (const child of Object.values(node)) walk(child);
      }
    };
    walk(root);
    const target = (containers as unknown[])[
      Math.floor(next() * containers.length)
    ] as Record<string, Json> | Json[];
    const keys = Object.keys(target);
    const key = keys[Math.floor(next() * keys.length)];
    const action = next();
    if (key !== undefined && action < 0.5)
      (target as Record<string, Json>)[key] = value(next);
    else if (key !== undefined && action < 0.7) {
      if (Array.isArray(target)) target.splice(Number(key), 1);
      else delete target[key];
    } else if (Array.isArray(target)) target.push(value(next));
    else target[`extra${Math.floor(next() * 10)}`] = value(next);
  }

  function edit(text: string, next: () => number) {
    const at = Math.floor(next() * text.length);
    const char = '{}[]",:0a\\'[Math.floor(next() * 10)]!;
    const action = next();
    if (action < 0.4) return text.slice(0, at) + char + text.slice(at + 1);
    if (action < 0.7) return text.slice(0, at) + char + text.slice(at);
    return text.slice(0, at) + text.slice(at + 1);
  }

  it("never escapes the boundary, and is a mismatch only without a collectedAt", async () => {
    const honest = await manifestText();
    const next = random(500);
    const outcomes = new Map<string, number>();
    for (let index = 0; index < 3000; index++) {
      let text: string;
      const kind = next();
      if (kind < 0.6) {
        const tree = JSON.parse(honest) as Json;
        const edits = 1 + Math.floor(next() * 3);
        for (let count = 0; count < edits; count++) mutate(tree, next);
        text = next() < 0.8 ? canonicalJson(tree) : JSON.stringify(tree);
      } else if (kind < 0.9) {
        text = honest;
        const edits = 1 + Math.floor(next() * 3);
        for (let count = 0; count < edits; count++) text = edit(text, next);
      } else text = JSON.stringify(value(next));
      const plaintext = new TextEncoder().encode(text);
      const receipt = await receive(plaintext);
      const label =
        receipt.tag === "refused" ? `refused:${receipt.reason}` : receipt.tag;
      outcomes.set(label, (outcomes.get(label) ?? 0) + 1);
      if (receipt.tag === "mismatch")
        expect(namesCollectedAt(text), text.slice(0, 200)).toBe(false);
      // Decoding alone throws nothing but a typed refusal.
      try {
        decodeReplicaManifest(plaintext, scope, owner);
      } catch (error) {
        expect(error).toBeInstanceOf(ReplicaManifestRefused);
      }
    }
    // The generator reaches refusals, mismatches and valid manifests.
    expect(outcomes.get("refused:manifest_invalid")).toBeGreaterThan(100);
    expect(outcomes.get("mismatch")).toBeGreaterThan(100);
    expect(outcomes.get("manifest")).toBeGreaterThan(0);
  }, 120000);
});

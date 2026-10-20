import { expect, it } from "vitest";
import { fragmentReplicaPayload, replicaScope } from "./transport.js";

it("fragments a large export without changing bytes or exceeding encrypted cap", async () => {
  const bytes = new TextEncoder().encode("😺large JSON record".repeat(2000));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00Z",
    encrypt: async (_scope, bytes) =>
      new Uint8Array([...bytes, ...new Uint8Array(100)]),
    maxBlobBytes: 4096,
    targetChunkBytes: 8000,
  });
  expect(parts.length).toBeGreaterThan(1);
  expect(parts.every((p) => p.encrypted.length <= 4096)).toBe(true);
  expect(parts.map((p) => p.scope)).toEqual(
    parts.map((_, i) => replicaScope("a".repeat(32), "b".repeat(32), i)),
  );
});

it("reassembles byte-identical content and rejects missing, overlapping, swapped or tampered frames", async () => {
  const { assembleReplicaPayload, decodeReplicaFragment } =
    await import("./transport.js");
  const bytes = new TextEncoder().encode("a JSON record 😺".repeat(300));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00.000Z",
    targetChunkBytes: 1500,
    encrypt: async (_scope, bytes) => bytes,
  });
  const fragments = parts.map((p) =>
    decodeReplicaFragment(p.plaintext, p.scope, "owner"),
  );
  expect(assembleReplicaPayload([...fragments].reverse())).toEqual(bytes);
  expect(() =>
    assembleReplicaPayload(
      fragments.map((f) => ({ ...f, digest: `sha256:${"0".repeat(64)}` })),
    ),
  ).toThrow();
  expect(() => assembleReplicaPayload(fragments.slice(1))).toThrow();
  expect(() =>
    assembleReplicaPayload([fragments[0]!, ...fragments.slice(0, -1)]),
  ).toThrow();
  for (const mutation of [
    { offset: 1 },
    { totalBytes: Number.MAX_SAFE_INTEGER },
    { batch: "c".repeat(32) },
    { content: "YQ==" },
    { count: fragments.length + 1 },
  ]) {
    expect(() =>
      assembleReplicaPayload([
        { ...fragments[0]!, ...mutation },
        ...fragments.slice(1),
      ]),
    ).toThrow();
  }
  expect(() =>
    decodeReplicaFragment(parts[0]!.plaintext, parts[0]!.scope, "other-owner"),
  ).toThrow();
});

it("reduces fragment size using actual DPv2 encryption overhead", async () => {
  const { encryptWithPassword, decryptWithPassword } =
    await import("@opendatalabs/vana-sdk/browser");
  const { assembleReplicaPayload, decodeReplicaFragment } =
    await import("./transport.js");
  const bytes = crypto.getRandomValues(new Uint8Array(6500));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00.000Z",
    targetChunkBytes: 6500,
    maxBlobBytes: 4096,
    encrypt: (_scope, bytes) => encryptWithPassword(bytes, "test-password"),
  });
  expect(parts.length).toBeGreaterThan(1);
  expect(parts.every((p) => p.encrypted.length <= 4096)).toBe(true);
  const decoded = await Promise.all(
    parts.map(async (p) =>
      decodeReplicaFragment(
        await decryptWithPassword(p.encrypted, "test-password"),
        p.scope,
        "owner",
      ),
    ),
  );
  expect(assembleReplicaPayload(decoded)).toEqual(bytes);
}, 30000);

it("requires consistent settled head, history and chain instead of same-hash adoption", async () => {
  const { replicaRegistrationState } = await import("./dpv2.js");
  const row = {
    owner: "owner",
    scope: "scope",
    version: "1",
    dataHash: "hash",
    metadataHash: "meta",
    deleted: false,
  };
  const expected = {
    owner: row.owner,
    scope: row.scope,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
  };
  expect(
    replicaRegistrationState(
      { head: null, history: null, chain: null, pending: false },
      expected,
    ),
  ).toBe("absent");
  expect(
    replicaRegistrationState(
      { head: row, history: row, chain: row, pending: false },
      expected,
    ),
  ).toBe("confirmed");
  expect(
    replicaRegistrationState(
      { head: row, history: row, chain: null, pending: true },
      expected,
    ),
  ).toBe("pending");
  for (const mutation of [
    { head: { ...row, version: "9" } },
    { head: null },
    { history: null },
    { chain: null },
    { history: { ...row, metadataHash: "other" } },
    { chain: { ...row, dataHash: "other" } },
    { head: { ...row, deleted: true } },
  ]) {
    expect(
      replicaRegistrationState(
        { head: row, history: row, chain: row, pending: false, ...mutation },
        expected,
      ),
    ).toBe("conflict");
  }
});

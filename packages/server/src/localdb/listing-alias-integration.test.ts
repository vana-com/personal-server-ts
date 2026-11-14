import { afterEach, expect, it, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  decodeHead,
  digestHead,
  encodeHead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "listing-alias",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const h = await remote.head("items", [{ id: "a" }]);
  const decoded = decodeHead(remote.blobs.get(`${h.scope}/${h.blobName}`)!);
  if (decoded.kind !== "ok") throw new Error("invalid fixture");
  const bytes = encodeHead({
    ...decoded.head,
    profile: { key: "fixture-source", version: "1" },
  });
  const digest = await digestHead(async (b) => keccak_256(b), bytes);
  remote.blobs.set(`${h.scope}/${digest.blobName}`, bytes);
  remote.reads.set(h.scope, {
    found: true,
    version: 1,
    dataHash: digest.dataHash,
    metadataHash: remote.hashes.activeMetadata,
    deleted: false,
  });
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: remote.registry,
    blobs: remote.storage,
    signer: { signAddData: async () => "0x00" },
    now: () => 1000,
    newOp: () => `listing-${++op}`,
    logger: { info: vi.fn(), warn: vi.fn() },
  };
  await bootstrapConnections(deps);
  await applyConnection(deps, remote.control);
  const project = vi.fn(() => ({ ok: true as const, payload: { ok: true } }));
  const aliases = {
    aliasScopes: () => ["fixture.summary"],
    aliasTargets: () => [
      { connector: "fixture-source", streams: ["items"], project },
    ],
  };
  return { deps, aliases, project };
}
it("uses the caller alias ports through the real database resolver", async () => {
  const f = await fixture();
  const listing = createLocalListing({ ...f.deps, ...f.aliases }, () => ({
    served: 0,
    gone: 0,
    off: 0,
  }));
  expect(
    (await listing.listScopes({ canRead: () => true })).map((s) => [
      s.scope,
      s.records,
    ]),
  ).toEqual([
    ["fixture.summary", null],
    ["pdpp.fixture-source.items", 1],
  ]);
  expect(f.project).toHaveBeenCalledTimes(1);
});
it("marks each alias with the logical scope it repeats, and no logical scope", async () => {
  const f = await fixture();
  const listing = createLocalListing({ ...f.deps, ...f.aliases }, () => ({
    served: 0,
    gone: 0,
    off: 0,
  }));
  const listed = await listing.listScopes({ canRead: () => true });
  expect(listed.map((s) => [s.scope, s.aliasOf])).toEqual([
    ["fixture.summary", "pdpp.fixture-source.items"],
    ["pdpp.fixture-source.items", undefined],
  ]);
  expect("aliasOf" in listed[1]!).toBe(false);
});
it("does not resolve aliases without a caller and checks grants before projection", async () => {
  const f = await fixture();
  const plain = createLocalListing(f.deps, () => ({
    served: 0,
    gone: 0,
    off: 0,
  }));
  expect(
    (await plain.listScopes({ canRead: () => true })).map((s) => s.scope),
  ).toEqual(["pdpp.fixture-source.items"]);
  const listing = createLocalListing({ ...f.deps, ...f.aliases }, () => ({
    served: 0,
    gone: 0,
    off: 0,
  }));
  expect(await listing.listScopes({ canRead: () => false })).toEqual([]);
  expect(f.project).not.toHaveBeenCalled();
});

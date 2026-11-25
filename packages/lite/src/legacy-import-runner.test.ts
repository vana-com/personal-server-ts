import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createMemoryModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createIndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntime,
} from "./browser-runtime.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import type { SqlDriver } from "../../core/src/localdb/driver.js";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";

// A Lite runtime imports its own legacy scope data (the scope envelopes
// `withLegacyProjection` reads) into stream sync, with no host import code.

const open: IndexedDbPsLiteRuntime[] = [];
const roots: string[] = [];
afterEach(async () => {
  for (const context of open.splice(0)) {
    await context.importWaker?.stop();
    await context.syncManager?.stop();
    await context.closeStreamSync?.();
  }
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

const stream = (name: string) => ({
  name,
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
});
const manifest = JSON.stringify({
  connector_key: "chatgpt",
  version: "1",
  streams: ["memories", "conversations"].map((name) => ({
    name,
    semantics: "mutable_state",
    primary_key: ["id"],
  })),
});
const declaration = {
  connector: "chatgpt",
  version: "1",
  streams: [stream("memories"), stream("conversations")],
};

async function fixture() {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const root = await mkdtemp(join(tmpdir(), "lite-legacy-runner-"));
  roots.push(root);
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const signature = await signOwnerMasterKey(owner);
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const accountModeStore = createMemoryModeRecordStore();
  const boot = async (
    extra: Partial<Parameters<typeof createIndexedDbPsLiteRuntime>[0]> = {},
  ) => {
    const context = await createIndexedDbPsLiteRuntime({
      ownerAddress: owner.address,
      ownerSignature: signature,
      dbName: join(root, "state"),
      storageDbName: join(root, "data"),
      accountModeStore,
      gateway: createMockPsLiteGateway(),
      auth: createBearerTokenPsLiteAuth({ ownerToken: "owner-token" }),
      active: true,
      localDb: {
        openDriver: async (): Promise<SqlDriver> =>
          openBetterSqlite3(join(root, "store.sqlite")),
      },
      streamSyncRegistry: registry,
      streamSyncBlobs: blobs,
      streamSyncDeclarations: () => declaration,
      streamSyncRetainedManifests: () => [manifest],
      configDefaults: {
        sync: { enabled: false },
        gateway: { url: "https://gateway.local" },
      },
      ...extra,
    });
    open.push(context);
    return context;
  };
  const answer = (
    context: IndexedDbPsLiteRuntime,
    state: "on" | "off",
  ): Promise<unknown> =>
    context.accountModeAuthority.submitEvidence({
      owner: owner.address,
      state,
    });
  return { boot, answer, accountModeStore };
}

/** A legacy scope version, written while the account is not switched. */
async function writeLegacy(
  context: IndexedDbPsLiteRuntime,
  scope: string,
  rows: unknown[],
  collectedAt = "2026-11-01T00:00:00.000Z",
) {
  const envelope = createDataFileEnvelope(scope, collectedAt, {
    records: rows,
  });
  await context.storage.writeEnvelopeAndIndex!(envelope, {
    fileId: null,
    schemaId: null,
    scope,
    collectedAt,
  });
}

const scopesOf = (context: IndexedDbPsLiteRuntime) =>
  context.storage.listScopes({}).scopes.map((s) => s.scope);

async function until<T>(check: () => T | null | undefined | false): Promise<T> {
  for (let i = 0; i < 300; i++) {
    const value = check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("timed out");
}

async function records(
  context: IndexedDbPsLiteRuntime,
  streamName = "memories",
) {
  const page = await (
    await context.getLocalSync!()
  ).query.listRecords({
    connectionId: "pdpp.chatgpt~",
    stream: streamName,
  });
  return page.records.map((row) => JSON.parse(row.body));
}

const rows = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ id: `m${i}`, content: `c${i}` }));
const sum = (counts: Record<string, number>) =>
  Object.values(counts).reduce((a, b) => a + b, 0);

it("imports a legacy scope on an On answer by itself; a second run imports nothing more", async () => {
  const f = await fixture();
  const context = await f.boot();
  await f.answer(context, "off");
  await writeLegacy(context, "chatgpt.memories", rows(5));
  await f.answer(context, "on");
  const report = await until(() => context.legacyImportReport());
  expect(report.streams.staged).toBe(1);
  expect(report.rows).toMatchObject({ legacy: 5, staged: 5, refused: 0 });
  expect(await records(context)).toHaveLength(5);

  await context.importWaker!.wake();
  const second = context.legacyImportReport()!;
  expect(second.streams).toMatchObject({ staged: 0, alreadyImported: 1 });
  expect(second.rows.staged).toBe(0);
  expect(await records(context)).toHaveLength(5);
});

it("a boot that is already switched runs the import once the intake exists", async () => {
  const f = await fixture();
  const first = await f.boot({ legacyImporter: { run: async () => {} } });
  await f.answer(first, "off");
  await writeLegacy(first, "chatgpt.memories", rows(3));
  await f.answer(first, "on");
  await first.importWaker!.stop();
  await first.syncManager?.stop();
  await first.closeStreamSync?.();
  open.splice(open.indexOf(first), 1);

  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  const context = await f.boot();
  const report = await until(() => context.legacyImportReport());
  expect(report.rows.staged).toBe(3);
  expect(await records(context)).toHaveLength(3);
  expect(warn).not.toHaveBeenCalled();
});

it("quarantines a row without a full key and still imports the rest: legacy = staged + quarantined + refused", async () => {
  const f = await fixture();
  const context = await f.boot();
  await f.answer(context, "off");
  await writeLegacy(context, "chatgpt.memories", [
    ...rows(4),
    { content: "no id" },
  ]);
  await f.answer(context, "on");
  const report = await until(() => context.legacyImportReport());
  expect(report.rows.quarantined).toEqual({ missing_key_field: 1 });
  expect(report.rows.staged).toBe(4);
  expect(report.rows.legacy).toBe(
    report.rows.staged + sum(report.rows.quarantined) + report.rows.refused,
  );
  expect(report.rows.legacy).toBe(5);
  expect(await records(context)).toHaveLength(4);
});

const twoStreams = async (retire: boolean) => {
  const f = await fixture();
  const context = await f.boot();
  context.config.streamSync.retireLegacy = retire;
  await f.answer(context, "off");
  await writeLegacy(context, "chatgpt.memories", rows(2));
  // One key twice with different bodies: this stream is refused whole.
  await writeLegacy(context, "chatgpt.conversations", [
    { id: "x", title: "a" },
    { id: "x", title: "b" },
  ]);
  await f.answer(context, "on");
  const report = await until(() => context.legacyImportReport());
  return { context, report };
};

it("with retireLegacy off every legacy copy stays", async () => {
  const { context, report } = await twoStreams(false);
  expect(report.retired).toBeNull();
  expect(report.streams.refused).toEqual([
    { reason: "invalid_record", streams: 1, rows: 2 },
  ]);
  expect(scopesOf(context).sort()).toEqual([
    "chatgpt.conversations",
    "chatgpt.memories",
  ]);
});

it("with retireLegacy on imported streams lose their copy and a refused stream keeps its own", async () => {
  const { context, report } = await twoStreams(true);
  expect(report.retired).toEqual({ scopes: 1 });
  expect(scopesOf(context)).toEqual(["chatgpt.conversations"]);
  expect(await records(context)).toHaveLength(2);
});

it("a host-passed legacyImporter overrides the default", async () => {
  const f = await fixture();
  const run = vi.fn(async () => {});
  const context = await f.boot({ legacyImporter: { run } });
  await f.answer(context, "off");
  await writeLegacy(context, "chatgpt.memories", rows(2));
  await f.answer(context, "on");
  await until(() => run.mock.calls.length > 0);
  expect(context.legacyImportReport()).toBeNull();
  expect(await records(context)).toHaveLength(0);
});

it("serves the report on read-status?audit=1", async () => {
  const f = await fixture();
  const context = await f.boot();
  await f.answer(context, "off");
  await writeLegacy(context, "chatgpt.memories", rows(2));
  await f.answer(context, "on");
  await until(() => context.legacyImportReport());
  const response = await context.runtime.fetch(
    new Request("https://ps.local/v1/stream-sync/read-status?audit=1", {
      headers: { authorization: "Bearer owner-token" },
    }),
  );
  const body = (await response.json()) as {
    seedExclusions: { legacyStore: { rows: { staged: number } } };
  };
  expect(body.seedExclusions.legacyStore.rows.staged).toBe(2);
});

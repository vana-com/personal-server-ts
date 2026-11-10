import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalJson,
  digestHead,
  encodeFramePart,
  encodeHead,
  frameOfLine,
  partBlobName,
  pkHash,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type { RecordQuery } from "../../../core/src/localdb/query.js";
import type {
  ReadDecision,
  ResolveInput,
} from "../../../core/src/stream-sync-read/service.js";

const mocked = vi.hoisted(() => ({
  targets: vi.fn(),
  apply: vi.fn(async () => []),
  project: vi.fn(),
}));
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: mocked.apply,
}));

const CONNECTOR = "fixture-source";
const BASE = {
  connection: null,
  cursor: null,
  legacyFile: false,
  isOwnerView: false,
};
const rows = JSON.parse(
  readFileSync(
    new URL(
      "../../../core/src/localdb/resolve-eligibility.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  cases: { control: string; state: string; head: string; decision: string }[];
};
const opened: SqlDriver[] = [];
const dirs: string[] = [];
beforeEach(() => {
  mocked.apply.mockClear();
  mocked.targets.mockImplementation((scope: string) => {
    if (scope.startsWith("pdpp.fixture-source.")) {
      return [
        {
          connector: CONNECTOR,
          streams: [scope.slice("pdpp.fixture-source.".length)],
        },
      ];
    }
    if (scope === "fixture.alias" || scope === "fixture.unsupported") {
      return [
        {
          connector: CONNECTOR,
          streams: ["parents", "children"],
          binding: {
            pdppSource: "https://example.test/connectors/fixture-source",
            pdppStreams: ["parents", "children"],
            primaryKey: { parents: ["id"], children: ["id"] },
            window: { parentStream: "parents", childStream: "children" },
          },
        },
      ];
    }
    return [];
  });
  mocked.project.mockReset();
  mocked.project.mockImplementation((scope: string, records: unknown[]) =>
    scope === "fixture.unsupported"
      ? { ok: false, error: { kind: "unsupported_profile" } }
      : { ok: true, payload: { records } },
  );
});
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const input = (
  scope = "pdpp.fixture-source.items",
  extra: Partial<ResolveInput> = {},
) => ({ ...BASE, scope, ...extra });
const verdict = (d: ReadDecision) =>
  d.kind === "unavailable" ? d.reason : d.kind;
async function drain(d: ReadDecision) {
  if (!("body" in d)) throw new Error("expected a body");
  return JSON.parse(await new Response(d.body).text()) as {
    data: { records: { id: string; value: string }[] };
  };
}

async function fixture() {
  const dir = mkdtempSync(join(process.cwd(), ".resolve-test-"));
  dirs.push(dir);
  const db = openBetterSqlite3(join(dir, "db.sqlite"));
  opened.push(db);
  await openLocalDb(db, {
    owner: "0x1234",
    network: "test",
    deviceId: "fixture",
  });
  const visited = vi.fn();
  const query: RecordQuery = {
    listRecords: vi.fn(),
    getRecord: vi.fn(),
    changesSince: vi.fn(),
    async *streamRecords(connectionId, stream) {
      visited(connectionId, stream);
      const records = await db.query<{
        stream: string;
        recordKey: string;
        pkHash: string;
        body: string;
        emittedAt: number;
      }>(
        `SELECT stream, record_key AS recordKey, pk_hash AS pkHash, body,
                stamp_o AS emittedAt FROM records
         WHERE connection_id = ? AND stream = ? ORDER BY pk_hash`,
        [connectionId, stream],
      );
      yield* records;
    },
  };
  const olderVersions = { read: vi.fn(), list: vi.fn(), counts: vi.fn() };
  const blobs = new Map<string, Uint8Array>();
  const deps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0x1234",
    registry: {},
    blobs: { get: async (key: string) => blobs.get(key) ?? null },
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      decrypt: async (_scope: string, bytes: Uint8Array) => bytes,
    },
    signer: {},
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 5000,
    newOp: () => "test",
  } as unknown as LocalSyncDeps;
  const aliasScopes = (scope: string) =>
    mocked
      .targets(scope)
      .filter((target: { binding?: unknown }) => target.binding)
      .map(
        (target: {
          connector: string;
          streams: string[];
          binding: { window?: { parentStream: string } };
        }) => ({
          connector: target.connector,
          streams: target.streams,
          servedStream: target.binding.window?.parentStream,
          windowed: Boolean(target.binding.window),
          project: (records: readonly unknown[], now: string) =>
            mocked.project(scope, records, { now }),
        }),
      );
  const resolver = createLocalResolver(deps, {
    query,
    olderVersions,
    aliasScopes,
  });
  async function connection(
    control = "active",
    id = "c1",
    ns = "",
    generation = 2,
  ) {
    await db.batch([
      {
        sql: `INSERT OR REPLACE INTO connections
        (connection_id, connector, ns, generation, control_state)
        VALUES (?, ?, ?, ?, ?)`,
        params: [id, CONNECTOR, ns, generation, control],
      },
    ]);
  }
  async function version(
    stream: string,
    version: number,
    complete = true,
    generation = 2,
    id = "c1",
  ) {
    await db.batch([
      {
        sql: `INSERT OR REPLACE INTO stream_versions
        (connection_id, stream, version, generation, head_blob, head_format,
         record_count, observed_at, complete, kind)
        VALUES (?, ?, ?, ?, ?, 3, 1, ?, ?, 'applied')`,
        params: [
          id,
          stream,
          version,
          generation,
          `head-${stream}-${version}`,
          version * 1000,
          Number(complete),
        ],
      },
    ]);
  }
  async function head(
    stream = "items",
    options: {
      version?: number;
      complete?: boolean;
      generation?: number;
      floor?: number;
      profile?: string | null;
      id?: string;
    } = {},
  ) {
    const {
      version: v = 2,
      complete: full = true,
      generation = 2,
      floor = 0,
      profile = CONNECTOR,
      id = "c1",
    } = options;
    await version(stream, v, full, generation, id);
    await db.batch([
      {
        sql: `INSERT OR REPLACE INTO stream_state
        (connection_id, stream, primary_key, semantics, incremental, profile_key,
         profile_version, complete, last_delete_version, head_version,
         head_generation, head_data_hash, head_blob)
        VALUES (?, ?, '["id"]', 'mutable_state', 0, ?, '1.0.0', ?, ?, ?, ?, ?, ?)`,
        params: [
          id,
          stream,
          profile,
          Number(full),
          floor,
          v,
          generation,
          `hash-${stream}-${v}`,
          `head-${stream}-${v}`,
        ],
      },
    ]);
  }
  async function record(stream = "items", value = "installed", id = "c1") {
    await db.batch([
      {
        sql: `INSERT OR REPLACE INTO records
        (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
        VALUES (?, ?, 'hash', 'key', 1000, 'run', ?, 'body-hash')`,
        params: [id, stream, JSON.stringify({ id: "key", value })],
      },
    ]);
  }
  async function clear() {
    await db.batch(
      ["records", "stream_versions", "stream_state", "connections"].map(
        (table) => ({ sql: `DELETE FROM ${table}` }),
      ),
    );
    visited.mockClear();
  }
  return {
    db,
    deps,
    query,
    blobs,
    connection,
    version,
    head,
    record,
    resolver,
    visited,
    olderVersions,
    clear,
  };
}

describe("local resolve", () => {
  it("serves no legacy alias without a host port, while logical streams remain readable", async () => {
    const f = await fixture();
    await f.connection();
    await f.head();
    await f.record();
    const isolated = createLocalResolver(f.deps, {
      query: f.query,
      olderVersions: f.olderVersions,
    });
    expect(verdict(await isolated.resolve(input("fixture.alias")))).toBe(
      "no_data",
    );
    expect(mocked.project).not.toHaveBeenCalled();
    const logical = await isolated.resolve(input());
    expect(logical.kind).toBe("view");
    if ("body" in logical) await logical.body.cancel();
  });

  it("#590 serves each installed complete head, requires all alias streams, and fences partial data", async () => {
    const f = await fixture();
    await f.connection();
    await f.head("items", { version: 2 });
    await f.record();
    await f.version("items", 1);
    // An incomplete observation is history, not permission to replace the
    // installed read image. The apply implementation owns that invariant.
    await f.version("items", 3, false);
    const current = await f.resolver.resolve(input());
    expect(current.kind).toBe("view");
    if (current.kind !== "view") throw new Error("missing complete view");
    expect(current.served?.version).toBe(2);
    expect((await drain(current)).data.records[0]?.value).toBe("installed");

    await f.head("parents", { version: 4 });
    await f.head("children", { version: 3, complete: false });
    expect(verdict(await f.resolver.resolve(input("fixture.alias")))).toBe(
      "no_data",
    );
    expect(f.visited).toHaveBeenCalledTimes(1);
    await f.head("children", { version: 5 });
    const alias = await f.resolver.resolve(input("fixture.alias"));
    expect(alias.kind).toBe("view");
    if (alias.kind !== "view") throw new Error("missing alias");
    expect(alias.served).toEqual({
      scope: "pdpp.fixture-source~.parents",
      version: 4,
    });
    await drain(alias);

    await f.head("items", { version: 3, complete: false, floor: 2 });
    expect(verdict(await f.resolver.resolve(input()))).toBe("no_data");
    await f.head("items", { version: 2, complete: false, floor: 2 });
    expect(verdict(await f.resolver.resolve(input()))).toBe("deleted");
    await f.clear();
    await f.connection();
    await f.head("items", { complete: false });
    expect(
      verdict(
        await f.resolver.resolve(input(undefined, { isOwnerView: true })),
      ),
    ).toBe("no_data");
    expect(f.visited).not.toHaveBeenCalled();
  });

  it("retains the complete head after a partial image replaces records, with history disabled and a fresh resolver", async () => {
    const f = await fixture();
    await f.connection();
    await f.head("items", { version: 1 });
    const scope = streamScope(CONNECTOR, "", "items");
    const sha = async (bytes: Uint8Array) => sha256(bytes);
    const value = { id: "original", value: "retained" };
    const k = await pkHash(sha, value, ["id"]);
    const frame = await frameOfLine(
      sha,
      k,
      canonicalJson({ o: 1000, r: "run", v: value }),
    );
    const part = (await encodeFramePart(sha, "", [{ k, bytes: frame.bytes }]))!;
    const head = encodeHead({
      connector: CONNECTOR,
      ns: "",
      stream: "items",
      generation: 2,
      complete: true,
      format: 4,
      lastDeleteVersion: 0,
      keyCheck: "0000000000000000",
      observedAt: 1000,
      parts: [part.entry],
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      recordCount: 1,
    });
    const { blobName } = await digestHead(
      async (bytes) => keccak_256(bytes),
      head,
    );
    f.blobs.set(`${scope}/${blobName}`, head);
    f.blobs.set(`${scope}/${partBlobName(2, part.entry.hash)}`, part.data);
    await f.db.batch([
      {
        sql: "UPDATE stream_versions SET head_blob = ?, head_format = 4 WHERE version = 1",
        params: [blobName],
      },
    ]);
    await f.head("items", { version: 2, complete: false });
    await f.record("items", "partial");
    const historyOff = {
      ...f.olderVersions,
      read: vi.fn(async () => "gone" as const),
    };
    const fresh = createLocalResolver(f.deps, {
      query: f.query,
      olderVersions: historyOff,
    });
    const result = await fresh.resolve(input());
    expect(result.kind).toBe("view");
    if (result.kind !== "view") throw new Error("missing retained view");
    expect(result.served?.version).toBe(1);
    expect((await drain(result)).data.records).toEqual([value]);
    expect(historyOff.read).not.toHaveBeenCalled();
    await f.db.batch([
      { sql: "UPDATE stream_state SET last_delete_version = 1" },
    ]);
    expect(verdict(await fresh.resolve(input()))).toBe("no_data");
  });

  it("#573 exercises the 3 x 5 x 2 JSON matrix; foreign and older images never win", async () => {
    const f = await fixture();
    expect(rows.cases).toHaveLength(30);
    expect(
      new Set(
        rows.cases.map((r) => JSON.stringify([r.control, r.state, r.head])),
      ).size,
    ).toBe(30);
    for (const row of rows.cases) {
      await f.clear();
      await f.connection(row.control);
      if (row.state !== "absent" && row.state !== "foreign_key") {
        await f.head("items", {
          complete: row.head === "complete",
          generation: row.state === "older_generation" ? 1 : 2,
          floor: row.state === "tombstoned" ? 2 : 0,
        });
      }
      // The apply port must reject a foreign-key head before it enters records.
      // A rejected observation alone is never an installed head.
      if (row.state === "foreign_key")
        await f.version("items", 9, row.head === "complete");
      const result = await f.resolver.resolve(input());
      expect(verdict(result), JSON.stringify(row)).toBe(row.decision);
      if ("body" in result) await result.body.cancel();
      else expect(f.visited).not.toHaveBeenCalled();
    }
    await f.clear();
    await f.connection();
    await f.head();
    await f.record();
    await f.connection("foreign", "foreign", "ffffffffffffffff");
    await f.head("items", { id: "foreign", version: 99 });
    const result = await f.resolver.resolve(input());
    expect(result.kind).toBe("view");
    if (result.kind !== "view") throw new Error("missing current-key view");
    expect(result.ns).toBe("");
    await drain(result);
  });

  it("#569 refuses unsupported window profiles, mismatched binding keys, and deleted connections before body construction", async () => {
    const f = await fixture();
    await f.connection();
    await f.head("parents");
    await f.head("children");
    expect(
      verdict(await f.resolver.resolve(input("fixture.unsupported"))),
    ).toBe("no_data");
    expect(f.visited).not.toHaveBeenCalled();
    expect(mocked.project).toHaveBeenCalledTimes(1);
    await f.head("children", { profile: "another-profile" });
    mocked.project.mockClear();
    expect(verdict(await f.resolver.resolve(input("fixture.alias")))).toBe(
      "no_data",
    );
    expect(mocked.project).not.toHaveBeenCalled();
    expect(f.visited).not.toHaveBeenCalled();
    await f.db.batch([
      {
        sql: "UPDATE connections SET deleted_at = 1000 WHERE connection_id = 'c1'",
      },
    ]);
    expect(verdict(await f.resolver.resolve(input("fixture.alias")))).toBe(
      "deleted",
    );
    expect(f.visited).not.toHaveBeenCalled();
  });

  it("#596 preserves no-data/deleted route decisions, treats empty selectors as latest, and binds served to the read head", async () => {
    const f = await fixture();
    // HTTP maps these pinned decisions to STREAM_DATA_NOT_FOUND/404 and 410.
    // ResolveInput itself intentionally has neither HTTP nor history selectors.
    expect(await f.resolver.resolve(input())).toEqual({
      kind: "unavailable",
      reason: "no_data",
    });
    await f.connection("deleted");
    expect(await f.resolver.resolve(input())).toEqual({
      kind: "unavailable",
      reason: "deleted",
    });
    await f.connection();
    await f.head("items", { version: 7 });
    await f.record();
    const withEmptySelectors = { ...input(), fileId: "", at: "" };
    const result = await f.resolver.resolve(withEmptySelectors);
    expect(result.kind).toBe("view");
    if (result.kind !== "view") throw new Error("missing latest view");
    expect(result.served).toEqual({
      scope: "pdpp.fixture-source~.items",
      version: 7,
    });
    expect((await drain(result)).data.records).toEqual([
      { id: "key", value: "installed" },
    ]);
    expect(f.olderVersions.read).not.toHaveBeenCalled();
    const again = await f.resolver.resolve(
      input(undefined, { cursor: result.cursor }),
    );
    expect(again.kind).toBe("view");
    if ("body" in again) await again.body.cancel();
    await f.head("items", { version: 8 });
    expect(
      await f.resolver.resolve(input(undefined, { cursor: result.cursor })),
    ).toEqual({ kind: "cursor_stale" });
  });
});

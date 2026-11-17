import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { legacyAliasScopes } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { readerOf, type SqlDriver } from "../../../core/src/localdb/driver.js";
import type { RecordQuery } from "../../../core/src/localdb/query.js";
import { COMPLETE_PAGE_SIZE } from "../../../core/src/localdb/complete-read.js";
import { PartialViewMoved } from "../../../core/src/localdb/partial-read.js";
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
  const aliasTargets = (scope: string) =>
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
    aliasScopes: () => ["fixture.alias", "fixture.unsupported"].values(),
    aliasTargets,
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
      aliasTargets: () => {
        throw new Error("Unlisted alias target consulted");
      },
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
    // A stream's own body is read from the database, not through the query.
    expect(f.visited).not.toHaveBeenCalled();
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

  it("serves the local records when an incomplete version follows the retained complete one", async () => {
    const f = await fixture();
    await f.connection();
    await f.head("items", { version: 1 });
    // The log merges per key: the rows of the complete version stay in
    // `records` under the newer, incomplete one, beside the rows it adds.
    const original = { id: "original", value: "retained" };
    const added = { id: "added", value: "partial" };
    await f.db.batch(
      [original, added].map((value, i) => ({
        sql: `INSERT INTO records
        (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
        VALUES ('c1', 'items', ?, ?, ?, 'run', ?, 'body-hash')`,
        params: [`hash-${i}`, value.id, 1000 * (i + 1), JSON.stringify(value)],
      })),
    );
    await f.head("items", { version: 2, complete: false });
    const result = await f.resolver.resolve(input());
    expect(result.kind).toBe("view");
    if (result.kind !== "view") throw new Error("missing retained view");
    // The rows served are the installed version's.
    expect(result.served?.version).toBe(2);
    expect((await drain(result)).data.records).toEqual([original, added]);
    // No complete version above the deletion floor: nothing is served.
    await f.db.batch([
      { sql: "UPDATE stream_state SET last_delete_version = 1" },
    ]);
    expect(verdict(await f.resolver.resolve(input()))).toBe("no_data");
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

/**
 * A read decides its headers while it holds the connection's queue and gives
 * the queue back there. Its body then pages through the stream, each page
 * checking in its own statement that the stream is still the one the read was
 * decided on, so a body nobody finishes reading costs nothing.
 */
describe("a read holds no queue slot while its body is read", () => {
  const PAGE = COMPLETE_PAGE_SIZE;
  const hex = (n: number) => `0x${n.toString(16).padStart(8, "0")}`;

  async function seedRows(
    f: Awaited<ReturnType<typeof fixture>>,
    count: number,
    stream = "items",
    id = "c1",
  ) {
    const statements = Array.from({ length: count }, (_, i) => ({
      sql: `INSERT INTO records
        (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
        VALUES (?, ?, ?, ?, 1000, 'run', ?, 'body-hash')`,
      params: [
        id,
        stream,
        hex((i * 7919) % count),
        `key-${i}`,
        JSON.stringify({ id: `r${(i * 7919) % count}`, value: "v" }),
      ],
    }));
    for (let at = 0; at < statements.length; at += 500)
      await f.db.batch(statements.slice(at, at + 500));
  }

  async function opened(count: number) {
    const f = await fixture();
    await f.connection();
    await f.head();
    await seedRows(f, count);
    const decision = await f.resolver.resolve(input());
    if (decision.kind !== "view") throw new Error("missing view");
    return { f, decision, reader: decision.body.getReader() };
  }
  const within = <T>(work: Promise<T>, ms = 1500) =>
    Promise.race([
      work,
      new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms)),
    ]);
  const decoder = new TextDecoder();
  async function take(
    reader: ReadableStreamDefaultReader<Uint8Array>,
    chunks: number,
  ) {
    let text = "";
    for (let i = 0; i < chunks; i++) {
      const next = await reader.read();
      if (next.done) break;
      text += decoder.decode(next.value);
    }
    return text;
  }
  async function rest(reader: ReadableStreamDefaultReader<Uint8Array>) {
    let text = "";
    for (;;) {
      const next = await reader.read();
      if (next.done) return text;
      text += decoder.decode(next.value);
    }
  }

  it("an abandoned body blocks neither a second whole read nor an apply on its connection", async () => {
    const { f, reader } = await opened(PAGE + 50);
    // The first chunk, and then nothing: no more reads and no cancel, as a
    // consumer that stops pulling leaves a body.
    await reader.read();

    const second = await within(f.resolver.resolve(input()).then(drain));
    expect(second).not.toBe("timeout");
    if (second !== "timeout")
      expect(second.data.records).toHaveLength(PAGE + 50);
    expect(
      await within(f.deps.queue.run("c1", "apply", async () => "ran")),
    ).toBe("ran");
    expect(
      await within(f.deps.queue.run("c1", "purge", async () => "ran")),
    ).toBe("ran");
    await reader.cancel();
  });

  it.each([0, 1, PAGE, PAGE + 1, 2 * PAGE + 7])(
    "a stream of %i records is served byte for byte as the record query yields it",
    async (count) => {
      const f = await fixture();
      await f.connection();
      await f.head();
      await seedRows(f, count);
      const decision = await f.resolver.resolve(input());
      if (decision.kind !== "view") throw new Error("missing view");
      const text = await new Response(decision.body).text();
      const bodies: string[] = [];
      for await (const record of f.query.streamRecords("c1", "items"))
        bodies.push(record.body);
      const at = text.indexOf('"data":') + '"data":'.length;
      expect(text.slice(at)).toBe(`{"records":[${bodies.join(",")}]}}`);
      expect(bodies).toHaveLength(count);
    },
  );

  it("serves the pages of a body in key order when the engine may run an unordered scan backwards", async () => {
    const f = await fixture();
    await f.connection();
    await f.head();
    await seedRows(f, 2 * PAGE + 7);
    // The read connection runs the body's statements, not the writer.
    await readerOf(f.db).query("PRAGMA reverse_unordered_selects = ON");
    const decision = await f.resolver.resolve(input());
    if (decision.kind !== "view") throw new Error("missing view");
    const served = (await drain(decision)).data.records.map((r) => r.id);
    const stored = (
      await f.db.query<{ body: string }>(
        "SELECT body FROM records WHERE stream = 'items' ORDER BY pk_hash",
      )
    ).map((r) => (JSON.parse(r.body) as { id: string }).id);
    expect(served).toEqual(stored);
    expect(served).toHaveLength(2 * PAGE + 7);
  });

  const moves: [string, string, unknown[]][] = [
    [
      "the stream's head moves",
      "UPDATE stream_state SET head_version = 3, head_data_hash = 'h3' WHERE stream = 'items'",
      [],
    ],
    [
      "the connection's generation moves",
      "UPDATE connections SET generation = 3",
      [],
    ],
    [
      "the connection is deleted",
      "UPDATE connections SET control_state = 'deleted', deleted_at = 5",
      [],
    ],
    [
      "a delete intent is saved",
      "INSERT INTO delete_intents(connector, delete_id, intent) VALUES ('fixture-source', 'd', 'x')",
      [],
    ],
    // The commits of an apply write rows of the new head before the commit
    // that moves the head, so the head alone does not say the rows moved.
    [
      "a row changes before the head does (an apply's first commits)",
      "UPDATE records SET body = ?, body_sha256 = 'new', stamp_o = 2000 WHERE stream = 'items' AND pk_hash = ?",
      [JSON.stringify({ id: "r200", value: "w" }), hex(200)],
    ],
    [
      "a row is added",
      "INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES ('c1', 'items', ?, 'added', 1000, 'run', '{\"id\":\"x\"}', 'h')",
      [hex(999)],
    ],
    [
      "a row is removed",
      "DELETE FROM records WHERE stream = 'items' AND pk_hash = ?",
      [hex(230)],
    ],
  ];
  it.each(moves)(
    "the body ends in an error, not a mixed body, when %s",
    async (_name, sql, params) => {
      const { f, reader } = await opened(PAGE + 50);
      // Records of the first page only: the second page is read later.
      const before = await take(reader, 2 + 50);
      await f.db.batch([{ sql, params: params as never }]);
      await expect(rest(reader)).rejects.toBeInstanceOf(PartialViewMoved);
      expect(before).toContain('"records":[');
    },
  );

  it("writes outside the stream do not end the body", async () => {
    const { f, reader } = await opened(PAGE + 50);
    const before = await take(reader, 2 + 50);
    await f.head("other", { version: 5 });
    await seedRows(f, 30, "other");
    await f.connection("active", "c2", "ab");
    await f.head("items", { id: "c2" });
    await seedRows(f, 30, "items", "c2");
    const text = before + (await rest(reader));
    const bodies: string[] = [];
    for await (const record of f.query.streamRecords("c1", "items"))
      bodies.push(record.body);
    expect(text.endsWith(`${bodies.join(",")}]}}`)).toBe(true);
    expect(bodies).toHaveLength(PAGE + 50);
  });
});

describe("local resolve through the host's real legacy alias port", () => {
  const ICLOUD = "icloud-notes";
  const NOTE = {
    id: "n1",
    title: "Grocery list",
    snippet: "milk",
    folder_id: "f1",
    is_pinned: false,
    created_at: "2026-09-01T00:00:00Z",
    modified_at: "2026-09-02T00:00:00Z",
    has_attachments: false,
    text_content: "milk",
  };
  async function icloud(streams: Record<string, Record<string, unknown>>) {
    const f = await fixture();
    await f.db.batch([
      {
        sql: `INSERT INTO connections
        (connection_id, connector, ns, generation, control_state)
        VALUES ('c1', ?, '', 2, 'active')`,
        params: [ICLOUD],
      },
    ]);
    for (const [stream, row] of Object.entries(streams)) {
      await f.head(stream, { profile: ICLOUD });
      await f.db.batch([
        {
          sql: `INSERT OR REPLACE INTO records
          (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
          VALUES ('c1', ?, 'hash', ?, 1000, 'run', ?, 'body-hash')`,
          params: [stream, String(row.id), JSON.stringify(row)],
        },
      ]);
    }
    const resolver = createLocalResolver(f.deps, {
      query: f.query,
      olderVersions: f.olderVersions,
      aliasScopes: () => ["icloud_notes.notes"].values(),
      aliasTargets: legacyAliasScopes,
    });
    return resolver;
  }

  it("serves iCloud Notes from notes and folders when the connector has no profile stream", async () => {
    const resolver = await icloud({
      notes: NOTE,
      folders: { id: "f1", name: "Notes" },
    });
    const read = await resolver.resolve(input("icloud_notes.notes"));
    expect(read.kind).toBe("view");
    if (read.kind !== "view") return;
    const body = JSON.parse(await new Response(read.body).text()) as {
      data: { userName: unknown; notes: { recordName: string }[] };
    };
    expect(body.data.userName).toBeNull();
    expect(body.data.notes.map((n) => n.recordName)).toEqual(["n1"]);
  });

  it("reads an installed profile stream into iCloud Notes", async () => {
    const resolver = await icloud({
      notes: NOTE,
      folders: { id: "f1", name: "Notes" },
      profile: { id: "p1", user_name: "Ada" },
    });
    const read = await resolver.resolve(input("icloud_notes.notes"));
    expect(read.kind).toBe("view");
    if (read.kind !== "view") return;
    const body = JSON.parse(await new Response(read.body).text()) as {
      data: { userName: unknown };
    };
    expect(body.data.userName).toBe("Ada");
  });

  it("serves no iCloud Notes while folders is missing, even with a profile stream", async () => {
    const resolver = await icloud({
      notes: NOTE,
      profile: { id: "p1", user_name: "Ada" },
    });
    expect(verdict(await resolver.resolve(input("icloud_notes.notes")))).toBe(
      "no_data",
    );
  });
});

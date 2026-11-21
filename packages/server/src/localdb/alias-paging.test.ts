import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as v8 from "node:v8";
import * as vm from "node:vm";
import { setTimeout as sleep } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
} from "../../../core/src/legacy-projection/index.js";
import type {
  LegacyScopeBinding,
  PdppRecord,
} from "../../../core/src/legacy-projection/types.js";
import { WINDOW_FIXTURES } from "../../../core/src/legacy-projection/__fixtures__/window-records.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import {
  ARRAY_BUDGET,
  sweepAliasSpool,
} from "../../../core/src/localdb/alias-projection.js";
import { HEAP_PER_STORED_BYTE } from "../../../core/src/localdb/alias-window.js";
import type { SqlDriver, SqlValue } from "../../../core/src/localdb/driver.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import {
  createRecordQuery,
  type RecordQuery,
} from "../../../core/src/localdb/query.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import {
  createLocalResolver,
  type LocalAliasTarget,
} from "../../../core/src/localdb/resolve.js";
import type {
  ReadDecision,
  StreamedReadDecision,
} from "../../../core/src/stream-sync-read/service.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../../../core/src/stream-sync/storage-retry.js";
import type { StreamSyncFiles } from "../../../core/src/stream-sync/ports.js";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { openAliasSpool } from "./alias-spool.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// The resolver applies registry heads before it reads; the rows below are
// already installed, so there is nothing to fetch.
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(async () => []),
}));

/**
 * A legacy alias read pages its projection a window of parents at a time, and
 * takes the memory it holds from the storage governor. Its output is the
 * output of the whole projection, byte for byte; no size refuses it.
 */
/**
 * A governor small enough to cut each fixture into windows of one parent, and
 * large enough to hold the biggest of them: a read that needs more than the
 * governor's limit is refused, so the limit cannot be smaller than a window.
 */
const TIGHT = 8 * 1024;

const NOW_MS = 5000;
const NOW = new Date(NOW_MS).toISOString();
const OBSERVED_MS = 1000;

const drivers: SqlDriver[] = [];
const spoolDirs: string[] = [];
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
  for (const dir of spoolDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

/** A spool on a directory of its own, removed after the test. */
async function newSpool(): Promise<StreamSyncFiles> {
  const dir = await mkdtemp(join(tmpdir(), "alias-spool-test-"));
  spoolDirs.push(dir);
  return createFsStreamSyncFiles(dir);
}

/** One governor of `limit` bytes, as the store's adapter would keep. */
const governorOf = (limit: number) =>
  createStorageAccess({
    ...DEFAULT_STORAGE_ACCESS_POLICY,
    maxBytesInFlight: limit,
  });

/**
 * The governor, and a count of the bytes held from it right now: a reservation
 * counts from its grant to its release, less what `shrink` gave back.
 */
function ledgerOf(real: ReturnType<typeof governorOf>) {
  let held = 0;
  /** Each size a reservation was shrunk to. */
  const kept: number[] = [];
  const governor: ReturnType<typeof governorOf> = {
    ...real,
    async reserve(bytes, objectBytes, signal) {
      const inner = await real.reserve(bytes, objectBytes, signal);
      let mine = Math.max(0, bytes);
      let released = false;
      held += mine;
      return Object.assign(
        () => {
          if (released) return;
          released = true;
          held -= mine;
          inner();
        },
        {
          shrink(keep: number) {
            if (released) return;
            const next = Math.max(0, Math.min(mine, keep));
            held -= mine - next;
            mine = next;
            kept.push(keep);
            inner.shrink(keep);
          },
        },
      );
    },
  };
  return { governor, inUse: () => held, kept };
}

/**
 * `spool`: the file space the resolver writes windowed bodies to, as the
 * server's is. `false` is a host that has none (Lite).
 */
async function fixture(limit: number, spoolOption?: StreamSyncFiles | false) {
  const spool =
    spoolOption === false ? undefined : (spoolOption ?? (await newSpool()));
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "alias-paging",
  });
  drivers.push(db);
  const { governor, inUse, kept } = ledgerOf(governorOf(limit));
  const poison = new Proxy(
    {},
    {
      get() {
        throw new Error("unexpected access");
      },
    },
  );
  const deps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: poison,
    blobs: { governor },
    keys: poison,
    signer: poison,
    logger: { info() {}, warn() {} },
    now: () => NOW_MS,
    newOp: () => "op",
  } as unknown as LocalSyncDeps;
  let hash = 0;
  /** Install `records` as the complete heads of one connection of `target`. */
  async function seed(target: LocalAliasTarget, records: PdppRecord[]) {
    const id = "c1";
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES (?, ?, '', 1, 'active')",
        params: [id, target.connector],
      },
    ]);
    for (const stream of target.streams) {
      await db.batch([
        {
          sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES (?, ?, 1, 1, ?, 3, 1, ?, 1, 'applied')",
          params: [id, stream, `${stream}-1`, OBSERVED_MS],
        },
        {
          sql: `INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, profile_key, profile_version, complete, last_delete_version, head_version, head_generation, head_data_hash, head_blob)
                VALUES (?, ?, '["id"]', 'mutable_state', 0, ?, '1.0.0', 1, 0, 1, 1, ?, ?)`,
          params: [
            id,
            stream,
            target.connector,
            `hash-${stream}`,
            `${stream}-1`,
          ],
        },
      ]);
    }
    const rows = records.map((record) => ({
      sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, ?, ?, ?, 1000, 'run', ?, 'body-hash')",
      params: [
        id,
        record.stream,
        `h${String(++hash).padStart(8, "0")}`,
        `k${hash}`,
        JSON.stringify(record.data),
      ],
    }));
    for (let i = 0; i < rows.length; i += 400) {
      await db.batch(rows.slice(i, i + 400));
    }
  }
  const resolverFor = (
    target: LocalAliasTarget,
    scope: string,
    query: ReturnType<typeof createRecordQuery> = createRecordQuery(db),
  ) =>
    createLocalResolver(deps, {
      query,
      aliasQuery: query,
      aliasScopes: () => [scope],
      aliasTargets: () => [target],
      aliasSpool: spool,
    });
  /**
   * The database as a read sees it, with every result set that carries record
   * bodies checked against the ledger: the heap those bodies take
   * (`HEAP_PER_STORED_BYTE` for each) must be held from the governor at the
   * moment they are read, so no read holds rows the governor does not know.
   */
  function audited() {
    const unheld: string[] = [];
    /** Run once, right after the first statement that sizes records. */
    let afterSizes: (() => Promise<void>) | undefined;
    let sizedStream: string | undefined;
    let readsOfBodies = 0;
    let largest = 0;
    const reader = {
      async query<R extends Record<string, SqlValue>>(
        sql: string,
        params?: readonly SqlValue[],
      ): Promise<R[]> {
        const rows = await db.query<R>(sql, params);
        if (
          afterSizes &&
          /AS bytes FROM records/.test(sql) &&
          (sizedStream === undefined || params?.[1] === sizedStream)
        ) {
          const hook = afterSizes;
          afterSizes = undefined;
          await hook();
        }
        let bytes = 0;
        for (const row of rows) {
          const body = (row as Record<string, SqlValue>).body;
          if (typeof body === "string") bytes += body.length;
        }
        if (bytes > 0) {
          readsOfBodies++;
          largest = Math.max(largest, bytes);
          // A read built whole is charged its heap up to its share of the
          // budget (`wholeReadCharge`); a window, its heap in full.
          if (Math.min(bytes * HEAP_PER_STORED_BYTE, limit / 2) > inUse()) {
            unheld.push(
              `${bytes} stored bytes of bodies read while ${inUse()} bytes were held`,
            );
          }
        }
        return rows;
      },
    };
    return {
      query: createRecordQuery(reader),
      reader,
      /** Run `hook` right after the first sizing of `stream` (any stream: the first). */
      onceSized(hook: () => Promise<void>, stream?: string) {
        afterSizes = hook;
        sizedStream = stream;
      },
      unheld,
      reads: () => ({ readsOfBodies, largest }),
    };
  }
  return { db, deps, governor, inUse, kept, seed, resolverFor, audited, spool };
}

const readInput = (scope: string, signal?: AbortSignal) => ({
  scope,
  connection: null,
  cursor: null,
  legacyFile: false,
  isOwnerView: true,
  ...(signal ? { signal } : {}),
});

/** A read as the one consumer that streams the body to a client makes it. */
const read = (
  resolver: ReturnType<typeof createLocalResolver>,
  scope: string,
  signal?: AbortSignal,
): Promise<StreamedReadDecision> =>
  resolver.resolveStreaming(readInput(scope, signal));

/** A read as a consumer that reads the body whole makes it (an MCP block read). */
const readWhole = (
  resolver: ReturnType<typeof createLocalResolver>,
  scope: string,
  signal?: AbortSignal,
): Promise<ReadDecision> => resolver.resolve(readInput(scope, signal));

/** The envelope a read writes around `payload`. */
const envelopeOf = (scope: string, payload: unknown) =>
  `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(new Date(OBSERVED_MS).toISOString())},"data":${JSON.stringify(payload)}}`;

/** Every windowed binding a caller can select, with its alias target. */
function windowedTargets(): {
  scope: string;
  label: string;
  binding: LegacyScopeBinding;
  target: LocalAliasTarget;
}[] {
  const out: ReturnType<typeof windowedTargets> = [];
  for (const scope of Object.keys(WINDOW_FIXTURES)) {
    const alternates = alternateLegacyBindingsForScope(scope);
    for (const target of legacyAliasScopes(scope)) {
      const binding =
        alternates.get(target.connector) ?? LEGACY_SCOPE_BINDINGS.get(scope)!;
      if (!binding.window) continue;
      out.push({
        scope,
        label: `${scope} (${target.connector})`,
        binding,
        target: target as LocalAliasTarget,
      });
    }
  }
  return out;
}

/**
 * The fixtures keep one conversation whose message count the source does not
 * know, which a read refuses as partial (see the diagnostics tests). Give it
 * a count, so the whole fixture serves.
 */
const completeRows = (records: PdppRecord[]): PdppRecord[] =>
  records.map((r) =>
    r.stream === "conversations" && r.data.message_count === null
      ? { ...r, data: { ...r.data, message_count: 1 } }
      : r,
  );

/**
 * The smallest governor (a power of two from 4 KiB) that holds the largest
 * window of `records` and still windows the read: below it the read is not
 * windowed (it is built whole, in one projection), and the fixture would not
 * be cut into the smallest windows the limit allows.
 */
async function tightBudget(
  target: LocalAliasTarget,
  scope: string,
  records: PdppRecord[],
): Promise<number> {
  for (let limit = 4 * 1024; limit <= 64 * 1024 * 1024; limit *= 2) {
    const f = await fixture(limit);
    const { wrapped, calls } = counting(target);
    await f.seed(target, records);
    const decision = await read(f.resolverFor(wrapped, scope), scope);
    if (decision.kind === "view") await decision.body.cancel();
    // A windowed read projects once per window; a whole read, once.
    if (calls.filter((n) => n > 0).length > 1) return limit;
  }
  throw new Error("no budget windows the fixture");
}

/** The target, counting every projection it is asked for. */
function counting(target: LocalAliasTarget) {
  const calls: number[] = [];
  const wrapped: LocalAliasTarget = {
    ...target,
    project: (records, now, fetched) => {
      calls.push(records.length);
      return target.project(records, now, fetched);
    },
  };
  return { wrapped, calls };
}

describe("a paged alias read equals the whole projection, byte for byte", () => {
  const cases = windowedTargets();
  it("covers every windowed binding", () => {
    expect(cases.length).toBeGreaterThanOrEqual(6);
  });

  for (const { scope, label, binding, target } of cases) {
    it(`${label}`, async () => {
      const records = completeRows(WINDOW_FIXTURES[scope]!(binding));
      const parents = records.filter(
        (r) => r.stream === binding.window!.parentStream,
      ).length;
      // The whole projection, from the same rows in one call.
      const whole = target.project(records, NOW, binding.pdppStreams);
      expect(whole.ok).toBe(true);
      if (!whole.ok) throw new Error("whole projection failed");
      // The fixtures drop and mark no rows: the read serves.
      expect(
        (whole.diagnostics ?? []).filter(
          (d) => d.kind === "records_dropped" || d.kind === "records_partial",
        ),
      ).toEqual([]);
      // A governor of 2 KiB forces a window of one parent.
      const f = await fixture(await tightBudget(target, scope, records));
      const { wrapped, calls } = counting(target);
      await f.seed(target, records);
      const decision = await read(f.resolverFor(wrapped, scope), scope);
      expect(decision.kind).toBe("view");
      if (decision.kind !== "view") return;
      const text = await new Response(decision.body).text();
      expect(text).toBe(envelopeOf(scope, whole.payload));
      // Several windows: the read projects over each of the parents' windows
      // once (the probe counts too), because the body is written to the spool
      // as it is projected, not projected again to be served.
      expect(parents).toBeGreaterThan(5);
      expect(calls.length).toBeGreaterThanOrEqual(parents);
      expect(calls.length).toBeLessThan(2 * parents);
      expect(Math.max(...calls)).toBeLessThan(records.length);
    });
  }
});

/**
 * One chatgpt conversation of `messages` messages that each hold `messageBytes`
 * of text, as the rows of its two streams.
 */
function chatgptConversation(
  c: number,
  messages: number,
  messageBytes: number,
): PdppRecord[] {
  const id = `c${String(c).padStart(3, "0")}`;
  const filler = "x".repeat(messageBytes);
  const records: PdppRecord[] = [];
  let parent: string | null = null;
  for (let m = 0; m < messages; m++) {
    const node = `n${m}`;
    records.push({
      stream: "messages",
      data: {
        id: `${id}:${node}`,
        conversation_id: id,
        parent_id: parent ? `${id}:${parent}` : null,
        role: m % 2 ? "assistant" : "user",
        content: `${m}:${id}:${filler}`,
        content_type: "text",
        model_slug: null,
        create_time: "2026-01-01T00:00:00.000Z",
        on_current_branch: true,
      },
    });
    parent = node;
  }
  records.push({
    stream: "conversations",
    data: {
      id,
      title: `conversation ${id}`,
      create_time: "2026-01-01T00:00:00.000Z",
      update_time: `2026-01-${String(1 + (c % 28)).padStart(2, "0")}T00:00:${String(c % 60).padStart(2, "0")}.000Z`,
      current_node: parent,
      message_count_on_current_branch: messages,
    },
  });
  return records;
}

describe("a read above the old 64 MiB budget", () => {
  /** One chatgpt account whose messages total more than 64 MiB. */
  function bigAccount() {
    const messageBytes = 100 * 1024;
    const conversations = 12;
    const perConversation = 60;
    const records = Array.from({ length: conversations }, (_, c) =>
      chatgptConversation(c, perConversation, messageBytes),
    ).flat();
    return { records, conversations, perConversation, messageBytes };
  }

  it("serves a complete 200 under a governor far below its size", async () => {
    const scope = "chatgpt.conversations";
    const target = legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
    const big = bigAccount();
    const payloadBytes =
      big.conversations * big.perConversation * big.messageBytes;
    expect(payloadBytes).toBeGreaterThan(64 * 1024 * 1024);
    const limit = 24 * 1024 * 1024;
    const f = await fixture(limit);
    await f.seed(target, big.records);
    const window = f.governor.window();
    const audit = f.audited();
    const decision = await read(
      f.resolverFor(target, scope, audit.query),
      scope,
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    // Read the body as a client would, a chunk at a time, and keep only what
    // it counts, so the test holds no more than a client would.
    const reader = decision.body.getReader();
    const decoder = new TextDecoder();
    let tail = "";
    let bytes = 0;
    let chunks = 0;
    (globalThis as { gc?: () => void }).gc?.();
    const heapBefore = process.memoryUsage().heapUsed;
    let heapPeak = heapBefore;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      // With --expose-gc, the live heap at each chunk: what the read holds.
      (globalThis as { gc?: () => void }).gc?.();
      heapPeak = Math.max(heapPeak, process.memoryUsage().heapUsed);
      bytes += next.value.byteLength;
      chunks++;
      tail = (tail + decoder.decode(next.value, { stream: true })).slice(-200);
    }
    const stats = window.end();
    expect(bytes).toBeGreaterThan(64 * 1024 * 1024);
    expect(chunks).toBeGreaterThan(10);
    // The array ends with the conversations' own totals, the body is whole.
    expect(tail.endsWith(`"total":${big.conversations}}}`)).toBe(true);
    expect(stats.peakBytesInFlight).toBeGreaterThan(0);
    expect(stats.peakBytesInFlight).toBeLessThanOrEqual(limit);
    // Every row the read took from the database was held from the governor.
    expect(audit.unheld).toEqual([]);
    console.log(
      `large read: ${bytes} bytes in ${chunks} chunks; governor limit ${limit}; peak held ${stats.peakBytesInFlight}; heap grew ${heapPeak - heapBefore} bytes over the read (live, when run with --expose-gc)`,
    );
  }, 120_000);
});

/**
 * A windowed read is written to the spool before its first byte goes out, so a
 * failure of the projection fails the read, and a failure of the file ends the
 * body in an error. Either way nothing is left behind.
 */
describe("an alias body written to the spool", () => {
  const scope = "instagram.posts";
  const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
  const records = WINDOW_FIXTURES[scope]!(LEGACY_SCOPE_BINDINGS.get(scope)!);

  /** A spool whose file reads fail after the first bytes of the first chunk. */
  async function failingSpool() {
    const real = await newSpool();
    const failing: StreamSyncFiles = {
      ...real,
      async *readChunks(path) {
        for await (const chunk of real.readChunks(path)) {
          yield chunk.slice(0, 16);
          throw new Error("injected failure");
        }
      },
    };
    return { real, failing };
  }

  async function failingRead() {
    const { real, failing } = await failingSpool();
    const f = await fixture(TIGHT, failing);
    await f.seed(target, records);
    const decision = await read(f.resolverFor(target, scope), scope);
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") throw new Error("not a view");
    return { decision, real, f };
  }

  it("ends its body in an error, never a short valid body", async () => {
    const { decision, real } = await failingRead();
    const reader = decision.body.getReader();
    let text = "";
    let failure: unknown;
    const decoder = new TextDecoder();
    for (;;) {
      try {
        const next = await reader.read();
        if (next.done) break;
        text += decoder.decode(next.value, { stream: true });
      } catch (error) {
        failure = error;
        break;
      }
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe("injected failure");
    // Some bytes went out, and what went out is not a whole JSON document.
    expect(text.length).toBeGreaterThan(0);
    expect(() => JSON.parse(text)).toThrow();
    // The body failed, and its file is gone.
    expect(await real.list("")).toEqual([]);
  });

  it("rejects the response a client reads, so it sees a failed request", async () => {
    const { decision } = await failingRead();
    await expect(new Response(decision.body).text()).rejects.toThrow(
      "injected failure",
    );
  });

  it("fails the read, and leaves no file and no memory held, when its projection fails", async () => {
    const real = await newSpool();
    const f = await fixture(TIGHT, real);
    await f.seed(target, records);
    // The projection fails in its third window, after a file has been begun.
    let calls = 0;
    const failing: LocalAliasTarget = {
      ...target,
      project: (rs, now, fetched) => {
        if (++calls === 4) throw new Error("injected failure");
        return target.project(rs, now, fetched);
      },
    };
    await expect(read(f.resolverFor(failing, scope), scope)).rejects.toThrow(
      "injected failure",
    );
    expect(await real.list("")).toEqual([]);
    expect(f.inUse()).toBe(0);
  });

  it("ends busy, with no file left, when a write commits during the last append", async () => {
    const real = await newSpool();
    let landed = false;
    const later: { f?: Awaited<ReturnType<typeof fixture>> } = {};
    // The fixture is small: its one append is the last. A write commits
    // while that append is in flight.
    const delaying: StreamSyncFiles = {
      ...real,
      async appendMany(entries) {
        if (!landed) {
          landed = true;
          await later.f!.db.batch([
            {
              sql: "UPDATE records SET stamp_o = 9 WHERE connection_id = 'c1' AND pk_hash = (SELECT MIN(pk_hash) FROM records WHERE connection_id = 'c1')",
            },
          ]);
        }
        return real.appendMany(entries);
      },
    };
    const f = await fixture(TIGHT, delaying);
    later.f = f;
    await f.seed(target, records);
    const decision = await read(f.resolverFor(target, scope), scope);
    expect(landed).toBe(true);
    expect(decision).toMatchObject({ kind: "busy" });
    expect(await real.list("")).toEqual([]);
    expect(f.inUse()).toBe(0);
  });

  it("ends aborted, with no file left, when the request ends during the last append", async () => {
    const real = await newSpool();
    const stop = new AbortController();
    // The fixture is small: its one append is the last, and the request ends
    // while it is in flight, after every check inside the windows.
    const delaying: StreamSyncFiles = {
      ...real,
      async appendMany(entries) {
        await real.appendMany(entries);
        stop.abort();
      },
    };
    const f = await fixture(TIGHT, delaying);
    await f.seed(target, records);
    const decision = await read(
      f.resolverFor(target, scope),
      scope,
      stop.signal,
    );
    expect(decision).toEqual({ kind: "read_aborted" });
    expect(await real.list("")).toEqual([]);
    expect(f.inUse()).toBe(0);
  });

  it("ends its body in an error when its file is gone, never a complete body with no elements", async () => {
    const real = await newSpool();
    const f = await fixture(TIGHT, real);
    await f.seed(target, records);
    const decision = await read(f.resolverFor(target, scope), scope);
    if (decision.kind !== "view") throw new Error("not a view");
    const reader = decision.body.getReader();
    // The head is out; the file has not been opened yet. It disappears.
    const head = new TextDecoder().decode((await reader.read()).value);
    const [file] = await real.list("");
    expect(file).toBeDefined();
    await real.remove(file!);
    let failure: unknown;
    let rest = "";
    for (;;) {
      try {
        const next = await reader.read();
        if (next.done) break;
        rest += new TextDecoder().decode(next.value);
      } catch (error) {
        failure = error;
        break;
      }
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toMatch(
      /spool file holds 0 of \d+ bytes/,
    );
    // The tail was never sent: what went out is not a whole document.
    expect(() => JSON.parse(head + rest)).toThrow();
    expect(await real.list("")).toEqual([]);
  });

  it("does not leave the governor's memory held", async () => {
    const f = await fixture(TIGHT);
    await f.seed(target, records);
    const window = f.governor.window();
    const decision = await read(f.resolverFor(target, scope), scope);
    if (decision.kind !== "view") throw new Error("not a view");
    const reader = decision.body.getReader();
    await reader.read();
    await reader.cancel();
    // A later reservation of the whole budget is not kept waiting.
    const release = await f.governor.reserve(f.governor.limitBytes);
    release();
    window.end();
  });

  describe("removes its file when the body ends", () => {
    const opened = async () => {
      const f = await fixture(TIGHT);
      await f.seed(target, records);
      const decision = await read(f.resolverFor(target, scope), scope);
      if (decision.kind !== "view") throw new Error("not a view");
      // The projection is done and written: the response is a file.
      expect(await f.spool!.list("")).toHaveLength(1);
      return { f, decision };
    };

    it("when it is read to the end", async () => {
      const { f, decision } = await opened();
      await new Response(decision.body).text();
      expect(await f.spool!.list("")).toEqual([]);
    });

    it("when it is cancelled after some bytes", async () => {
      const { f, decision } = await opened();
      const reader = decision.body.getReader();
      await reader.read();
      await reader.read();
      expect(await f.spool!.list("")).toHaveLength(1);
      await reader.cancel();
      expect(await f.spool!.list("")).toEqual([]);
    });

    it("when it is cancelled before any byte is read", async () => {
      const { f, decision } = await opened();
      await decision.body.cancel();
      expect(await f.spool!.list("")).toEqual([]);
    });

    it("when its projection is refused as incomplete", async () => {
      const f = await fixture(TIGHT);
      const refusing: LocalAliasTarget = {
        ...target,
        project: (rs, now, fetched) => {
          const projected = target.project(rs, now, fetched);
          return projected.ok
            ? {
                ...projected,
                diagnostics: [
                  {
                    kind: "records_dropped",
                    stream: "posts",
                    count: 1,
                    reasons: ["x"],
                  },
                ],
              }
            : projected;
        },
      };
      await f.seed(target, records);
      const decision = await read(f.resolverFor(refusing, scope), scope);
      expect(decision.kind).toBe("incomplete");
      expect(await f.spool!.list("")).toEqual([]);
      expect(f.inUse()).toBe(0);
    });
  });
});

describe("an alias read's diagnostics, over windows", () => {
  it("refuses with the rows named, counted over every window", async () => {
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const posts = records.filter((r) => r.stream === "posts");
    // A liker with no username, on each of three posts: three windows.
    const bad: PdppRecord[] = posts.slice(0, 3).map((post, i) => ({
      stream: "post_likes",
      data: { post_id: post.data.id, user_id: `u${i}`, liker_ordinal: 9 },
    }));
    const all = [...records, ...bad];
    const whole = target.project(all, NOW, binding.pdppStreams);
    expect(whole.ok).toBe(true);
    if (!whole.ok) return;
    const dropped = (whole.diagnostics ?? []).find(
      (d) => d.kind === "records_dropped",
    );
    expect(dropped?.count).toBe(3);
    const f = await fixture(await tightBudget(target, scope, all));
    await f.seed(target, all);
    const decision = await read(f.resolverFor(target, scope), scope);
    expect(decision).toEqual({
      kind: "incomplete",
      diagnostics: [
        {
          stream: "post_likes",
          kind: "dropped",
          detail: "3 rows: Liker lacks post_id, user_id, or username",
        },
      ],
    });
  });

  it("refuses a partial row in a window, as the whole projection does", async () => {
    const { scope, binding, target } = windowedTargets().find(
      (c) => c.label === "claude.conversations (anthropic)",
    )!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const f = await fixture(await tightBudget(target, scope, records));
    await f.seed(target, records);
    expect(await read(f.resolverFor(target, scope), scope)).toEqual({
      kind: "incomplete",
      diagnostics: [
        {
          stream: "conversations",
          kind: "partial",
          detail: "1 rows: message_count_unknown",
        },
      ],
    });
  });

  it("refuses a child that names no parent, as the whole projection reports it", async () => {
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const orphan: PdppRecord = {
      stream: "post_likes",
      data: {
        post_id: "no-such-post",
        user_id: "u",
        username: "n",
        liker_ordinal: 1,
      },
    };
    const f = await fixture(TIGHT);
    await f.seed(target, [...records, orphan]);
    const decision = await read(f.resolverFor(target, scope), scope);
    // The orphan is a dropped row: the read is refused as incomplete, as the
    // whole projection reports it, not served short.
    expect(decision).toMatchObject({
      kind: "incomplete",
      diagnostics: [{ stream: "post_likes", kind: "dropped" }],
    });
  });
});

describe("a read that is not windowed", () => {
  it("takes its memory from the governor and refuses no size", async () => {
    const target: LocalAliasTarget = {
      connector: "plain",
      streams: ["items"],
      project: (records) => ({
        ok: true as const,
        payload: { count: records.length },
      }),
    };
    const f = await fixture(TIGHT);
    // 40 KiB of rows under a 4 KiB governor: the read waits to run alone.
    await f.seed(
      target,
      Array.from({ length: 40 }, (_, i) => ({
        stream: "items",
        data: { id: `i${i}`, pad: "y".repeat(1000) },
      })),
    );
    const window = f.governor.window();
    const decision = await read(
      f.resolverFor(target, "plain.items"),
      "plain.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf("plain.items", { count: 40 }),
    );
    expect(window.end().peakBytesInFlight).toBeGreaterThan(0);
  });
});

/**
 * The three places a read could hold bytes the governor does not know, each
 * in the scenario that shows it. `audited()` counts the heap of every body a
 * statement returns against what the read holds at that moment.
 */
describe("a windowed read holds nothing the governor does not count", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  const whole = (target: LocalAliasTarget, records: PdppRecord[]) => {
    const projected = target.project(
      records,
      NOW,
      LEGACY_SCOPE_BINDINGS.get(scope)!.pdppStreams,
    );
    if (!projected.ok) throw new Error("whole projection failed");
    return envelopeOf(scope, projected.payload);
  };

  it("indexes children a bounded batch at a time, never a page of whole bodies", async () => {
    // 120 conversations, each with one 64 KiB message: a page of 100 bodies
    // is 6.4 MB of stored text, 25 MB of heap, under a 2 MiB read share.
    const records = Array.from({ length: 120 }, (_, c) =>
      chatgptConversation(c, 1, 64 * 1024),
    ).flat();
    const target = chatgpt();
    const f = await fixture(4 * 1024 * 1024);
    await f.seed(target, records);
    const audit = f.audited();
    const decision = await read(
      f.resolverFor(target, scope, audit.query),
      scope,
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    // Byte-identical to the whole projection, as before.
    expect(await new Response(decision.body).text()).toBe(
      whole(target, records),
    );
    expect(audit.reads().readsOfBodies).toBeGreaterThan(10);
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("holds no index while it waits for a larger reservation", async () => {
    // One conversation of three 500 KiB messages is a window of its own, and
    // needs more than the 4 MiB the read first holds (but fits the 8 MiB
    // budget): its read asks again for what it needs. Another holder keeps
    // the budget busy, so the wait is real.
    const records = [
      ...chatgptConversation(0, 3, 500 * 1024),
      ...chatgptConversation(1, 1, 100),
      ...chatgptConversation(2, 1, 100),
    ];
    const real = chatgpt();
    const f = await fixture(8 * 1024 * 1024);
    await f.seed(real, records);
    const gc = collector();
    const seen: WeakRef<object>[] = [];
    let phase: "first" | "later" | undefined;
    let blocker: (() => void) | undefined;
    const target: LocalAliasTarget = {
      ...real,
      window: {
        ...real.window!,
        // The parents are sorted once the index is built, before the read
        // asks for its larger reservation: watch the parsed parents there,
        // and take the budget's last bytes so that the ask must wait.
        parentOrder: (a, b) => {
          if (phase === undefined) {
            phase = "first";
            queueMicrotask(() => (phase = "later"));
            void f.governor.reserve(3 * 1024 * 1024).then((release) => {
              blocker = release;
            });
          }
          if (phase === "first") seen.push(new WeakRef(a), new WeakRef(b));
          return real.window!.parentOrder(a, b);
        },
      },
    };
    const pending = read(f.resolverFor(target, scope), scope);
    const state = await Promise.race([
      pending.then(() => "served"),
      sleep(300).then(() => "waiting"),
    ]);
    expect(state).toBe("waiting");
    expect(seen.length).toBeGreaterThan(0);
    // While it waits it holds no reservation of its own, so it must hold none
    // of the rows the reservation was for.
    expect(f.inUse()).toBe(3 * 1024 * 1024);
    gc();
    await sleep(10);
    gc();
    expect(seen.filter((ref) => ref.deref() !== undefined)).toHaveLength(0);
    blocker!();
    const decision = await pending;
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(whole(real, records));
    expect(f.inUse()).toBe(0);
  }, 60_000);
});

describe("a read that is not windowed holds its payload as main does", () => {
  const plain: LocalAliasTarget = {
    connector: "plain",
    streams: ["items"],
    project: (records) => ({
      ok: true as const,
      payload: { items: records.map((r) => r.data) },
    }),
  };
  const rows = Array.from({ length: 40 }, (_, i) => ({
    stream: "items",
    data: { id: `i${i}`, pad: "y".repeat(10_000) },
  }));
  const expected = envelopeOf("plain.items", {
    items: rows.map((r) => r.data),
  });
  const items = (f: Awaited<ReturnType<typeof fixture>>) =>
    f.resolverFor(plain, "plain.items");

  it("holds the projection's memory only while it builds the text, never for a paused reader", async () => {
    // 400 KB of rows under a 1 MiB governor: the projection takes 1.6 MB, more
    // than the budget, so it runs alone, and ends before the body is served.
    const f = await fixture(1024 * 1024);
    await f.seed(plain, rows);
    const first = await read(items(f), "plain.items");
    expect(first.kind).toBe("view");
    if (first.kind !== "view") return;
    expect(f.inUse()).toBe(0);
    const reader = first.body.getReader();
    await reader.read();
    await reader.read();
    // Paused with the rest of the text unread: the governor holds nothing, so
    // a second such read is served.
    expect(f.inUse()).toBe(0);
    const second = await read(items(f), "plain.items");
    expect(second.kind).toBe("view");
    if (second.kind !== "view") return;
    expect(await new Response(second.body).text()).toBe(expected);
    await reader.cancel();
    expect(f.inUse()).toBe(0);
  });
});

/**
 * A read sizes the rows it is about to read, takes that much memory (waiting
 * for it, if the budget is busy), and then reads the bodies. A write that
 * lands between the two must not give the read a body larger than the memory
 * it holds: the read's statements carry the pinned view as a condition, so
 * they return rows of the state that was sized, or none.
 */
describe("a row that grows after it was sized is not read past what is held", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  const conversations = () =>
    [0, 1, 2].flatMap((c) => chatgptConversation(c, 3, 10_000));
  const plain: LocalAliasTarget = {
    connector: "plain",
    streams: ["items"],
    project: (records) => ({
      ok: true as const,
      payload: { items: records.map((r) => r.data) },
    }),
  };
  const items = Array.from({ length: 10 }, (_, i) => ({
    stream: "items",
    data: { id: `i${i}`, pad: "y".repeat(1000) },
  }));
  /** A write to the first row of a stream that makes its body `bytes` larger. */
  const grow = (
    f: Awaited<ReturnType<typeof fixture>>,
    stream: string,
    bytes: number,
  ) =>
    f.db.batch([
      {
        // A write of a body writes its hash, which is what logs the change.
        sql: `UPDATE records SET body = substr(body, 1, length(body) - 1) || ',"pad":"' || ? || '"}',
                body_sha256 = 'grown'
              WHERE connection_id = 'c1' AND stream = ?
                AND pk_hash = (SELECT MIN(pk_hash) FROM records WHERE connection_id = 'c1' AND stream = ?)`,
        params: ["z".repeat(bytes), stream, stream],
      },
    ]);
  const waiting = (pending: Promise<unknown>) =>
    Promise.race([
      pending.then(() => "served"),
      sleep(200).then(() => "waiting"),
    ]);

  it("windowed: a parent grown while the read waits for its memory", async () => {
    const target = chatgpt();
    const f = await fixture(2 * 1024 * 1024);
    await f.seed(target, conversations());
    const audit = f.audited();
    const blocker = await f.governor.reserve(f.governor.limitBytes);
    const pending = read(f.resolverFor(target, scope, audit.query), scope);
    expect(await waiting(pending)).toBe("waiting");
    await grow(f, "conversations", 1024 * 1024);
    blocker();
    // The rows it sized are gone: it asks the caller to try again.
    expect(await pending).toMatchObject({ kind: "busy" });
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("windowed: a child grown between its size and its body", async () => {
    const target = chatgpt();
    const f = await fixture(2 * 1024 * 1024);
    await f.seed(target, conversations());
    const audit = f.audited();
    audit.onceSized(async () => {
      await grow(f, "messages", 1024 * 1024);
    }, "messages");
    const decision = await read(
      f.resolverFor(target, scope, audit.query),
      scope,
    );
    expect(decision).toMatchObject({ kind: "busy" });
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("not windowed: a row grown while the read waits for its memory", async () => {
    const f = await fixture(1024 * 1024);
    await f.seed(plain, items);
    const audit = f.audited();
    const blocker = await f.governor.reserve(f.governor.limitBytes);
    const pending = read(
      f.resolverFor(plain, "plain.items", audit.query),
      "plain.items",
    );
    expect(await waiting(pending)).toBe("waiting");
    await grow(f, "items", 2 * 1024 * 1024);
    blocker();
    expect(await pending).toMatchObject({ kind: "busy" });
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("still serves a view that no write touched", async () => {
    const target = chatgpt();
    const f = await fixture(2 * 1024 * 1024);
    await f.seed(target, conversations());
    const audit = f.audited();
    const decision = await read(
      f.resolverFor(target, scope, audit.query),
      scope,
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    await new Response(decision.body).text();
    expect(audit.unheld).toEqual([]);
  }, 60_000);
});

/**
 * A row can change under a view that the change mark cannot see move: a mark
 * whose flag is already set does not move its epoch for a later change. Each
 * body statement must then prove for itself that it reads what was sized
 * (the row's hash and a size no larger), so these tests put the mark back as
 * it was read after each write: the epoch is blind, and only the statement is
 * left to catch the change.
 */
describe("a body statement proves it reads what was sized, whatever the change mark says", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  const conversations = () =>
    [0, 1, 2].flatMap((c) => chatgptConversation(c, 3, 10_000));
  const plain: LocalAliasTarget = {
    connector: "plain",
    streams: ["items"],
    project: (records) => ({
      ok: true as const,
      payload: { items: records.map((r) => r.data) },
    }),
  };
  const items = Array.from({ length: 10 }, (_, i) => ({
    stream: "items",
    data: { id: `i${i}`, pad: "y".repeat(1000) },
  }));
  const firstOf = (stream: string) =>
    `connection_id = 'c1' AND stream = '${stream}'
     AND pk_hash = (SELECT MIN(pk_hash) FROM records WHERE connection_id = 'c1' AND stream = '${stream}')`;
  /** Make the first row of `stream` `bytes` larger, as a write of a new body does. */
  const grow = (stream: string, bytes: number) => ({
    sql: `UPDATE records SET body = substr(body, 1, length(body) - 1) || ',"pad":"' || ? || '"}',
            body_sha256 = 'grown' WHERE ${firstOf(stream)}`,
    params: ["z".repeat(bytes)],
  });
  const remove = (stream: string) => ({
    sql: `DELETE FROM records WHERE ${firstOf(stream)}`,
    params: [],
  });
  /** A write the epoch cannot see: the stream's mark is put back as it was. */
  async function unseen(
    f: Awaited<ReturnType<typeof fixture>>,
    stream: string,
    write: ReturnType<typeof grow>,
  ) {
    const [mark] = await f.db.query<{ epoch: number }>(
      "SELECT epoch FROM stream_change_marks WHERE connection_id = 'c1' AND stream = ?",
      [stream],
    );
    await f.db.batch([
      write,
      {
        sql: "UPDATE stream_change_marks SET epoch = ?, dirty = 1 WHERE connection_id = 'c1' AND stream = ?",
        params: [mark!.epoch, stream],
      },
    ]);
  }

  const cases = [
    {
      label: "windowed: a child replaced by a larger body",
      stream: "messages",
      change: () => grow("messages", 1024 * 1024),
    },
    {
      label: "windowed: a child deleted",
      stream: "messages",
      change: () => remove("messages"),
    },
    {
      label: "windowed: a parent replaced by a larger body",
      stream: "conversations",
      change: () => grow("conversations", 1024 * 1024),
    },
  ];
  for (const c of cases) {
    it(`${c.label}: the read ends busy and holds what it reserved`, async () => {
      const target = chatgpt();
      const f = await fixture(2 * 1024 * 1024);
      await f.seed(target, conversations());
      const audit = f.audited();
      audit.onceSized(() => unseen(f, c.stream, c.change()), c.stream);
      const decision = await read(
        f.resolverFor(target, scope, audit.query),
        scope,
      );
      expect(decision).toMatchObject({ kind: "busy" });
      expect(audit.unheld).toEqual([]);
      expect(f.inUse()).toBe(0);
    }, 60_000);
  }

  it("not windowed: a row replaced by a larger body", async () => {
    const f = await fixture(1024 * 1024);
    await f.seed(plain, items);
    const audit = f.audited();
    audit.onceSized(() => unseen(f, "items", grow("items", 2 * 1024 * 1024)));
    const decision = await read(
      f.resolverFor(plain, "plain.items", audit.query),
      "plain.items",
    );
    expect(decision).toMatchObject({ kind: "busy" });
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("not windowed: a row deleted", async () => {
    const f = await fixture(1024 * 1024);
    await f.seed(plain, items);
    const audit = f.audited();
    audit.onceSized(() => unseen(f, "items", remove("items")));
    const decision = await read(
      f.resolverFor(plain, "plain.items", audit.query),
      "plain.items",
    );
    expect(decision).toMatchObject({ kind: "busy" });
    expect(f.inUse()).toBe(0);
  }, 60_000);

  /** A listing over `f`, whose reads go through `audit` and whose writer is `f.db`. */
  function listingOf(
    f: Awaited<ReturnType<typeof fixture>>,
    audit: ReturnType<Awaited<ReturnType<typeof fixture>>["audited"]>,
    target: LocalAliasTarget,
    aliasScope: string,
  ) {
    const db: SqlDriver = {
      info: f.db.info,
      query: (sql, params) => f.db.query(sql, params),
      batch: (statements) => f.db.batch(statements),
      close: () => f.db.close(),
      reads: audit.reader,
    };
    return createLocalListing({
      ...f.deps,
      db,
      aliasScopes: () => [aliasScope],
      aliasTargets: () => [target],
    });
  }

  it("listing: a child replaced by a larger body, under the mark a write left set", async () => {
    const target = chatgpt();
    const f = await fixture(2 * 1024 * 1024);
    await f.seed(target, conversations());
    // Seeding left every stream's mark set, as a first change does: a change
    // from here moves no epoch.
    const marks = await f.db.query<{ dirty: number }>(
      "SELECT dirty FROM stream_change_marks",
    );
    expect(marks.every((m) => m.dirty === 1)).toBe(true);
    const audit = f.audited();
    audit.onceSized(async () => {
      await f.db.batch([grow("messages", 1024 * 1024)]);
    }, "messages");
    const listed = await listingOf(f, audit, target, scope).listScopes({
      canRead: () => true,
    });
    // The read saw the change and asked again: the alias is listed.
    expect(listed.map((s) => s.scope)).toContain(scope);
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);

  it("listing: a child deleted between its size and its body does not throw", async () => {
    // A windowed alias that serves whatever children are there, so a deleted
    // child leaves it complete.
    const tree: LocalAliasTarget = {
      connector: "tree",
      streams: ["parents", "kids"],
      window: {
        parentStream: "parents",
        parentKey: "id",
        childStream: "kids",
        childKey: "parent",
        arrayKey: "items",
        sumKeys: ["kids"],
        parentOrder: (a, b) => String(a.id).localeCompare(String(b.id)),
      },
      project: (records) => {
        const parents = records.filter((r) => r.stream === "parents");
        return {
          ok: true as const,
          payload: {
            items: parents.map((p) => p.data),
            kids: records.length - parents.length,
          },
        };
      },
    };
    const rows = Array.from({ length: 5 }, (_, p) => [
      { stream: "parents", data: { id: `p${p}` } },
      ...[0, 1, 2].map((k) => ({
        stream: "kids",
        data: { id: `p${p}:k${k}`, parent: `p${p}`, pad: "y".repeat(2000) },
      })),
    ]).flat();
    const f = await fixture(2 * 1024 * 1024);
    await f.seed(tree, rows);
    const audit = f.audited();
    audit.onceSized(async () => {
      await f.db.batch([remove("kids")]);
    }, "kids");
    const listed = await listingOf(f, audit, tree, "tree.items").listScopes({
      canRead: () => true,
    });
    // The read saw the change and asked again: the alias is listed.
    expect(listed.map((s) => s.scope)).toContain("tree.items");
    expect(f.inUse()).toBe(0);
  }, 60_000);
});

describe("a resolver called the way main calls it", () => {
  it("serves an alias from a query that already has the alias methods", async () => {
    const plain: LocalAliasTarget = {
      connector: "plain",
      streams: ["items"],
      project: (records) => ({
        ok: true as const,
        payload: { items: records.map((r) => r.data) },
      }),
    };
    const f = await fixture(1024 * 1024);
    await f.seed(plain, [
      { stream: "items", data: { id: "a" } },
      { stream: "items", data: { id: "b" } },
    ]);
    // `{ query: createRecordQuery(db), aliasScopes, aliasTargets }`, with no
    // `aliasQuery`: the shape every caller had on main.
    const resolver = createLocalResolver(f.deps, {
      query: createRecordQuery(f.db),
      aliasScopes: () => ["plain.items"],
      aliasTargets: () => [plain],
    });
    const decision = await read(resolver, "plain.items");
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf("plain.items", { items: [{ id: "a" }, { id: "b" }] }),
    );
  }, 60_000);
});

/**
 * A windowed alias whose parents are `parents` and whose children are `kids`,
 * with a `profile` object in its payload beside the array.
 */
function treeTarget(profileName: string): LocalAliasTarget {
  return {
    connector: "tree",
    streams: ["parents", "kids"],
    window: {
      parentStream: "parents",
      parentKey: "id",
      childStream: "kids",
      childKey: "parent",
      arrayKey: "items",
      sumKeys: ["kids"],
      parentOrder: (a, b) => String(a.id).localeCompare(String(b.id)),
    },
    project: (records) => {
      const parents = records.filter((r) => r.stream === "parents");
      return {
        ok: true as const,
        payload: {
          profile: { name: profileName },
          items: parents.map((p) => p.data),
          kids: records.length - parents.length,
        },
      };
    },
  };
}

describe("the envelope of a paged body is built from its fields", () => {
  it("serves a profile whose name is the text the old placeholder used", async () => {
    const marker = "\u0000alias-window-array\u0000";
    const tree = treeTarget(marker);
    const rows = Array.from({ length: 5 }, (_, p) => [
      { stream: "parents", data: { id: `p${p}` } },
      ...[0, 1].map((k) => ({
        stream: "kids",
        data: { id: `p${p}:k${k}`, parent: `p${p}`, pad: "y".repeat(500) },
      })),
    ]).flat();
    // A governor of 2 KiB forces a window of one parent.
    const f = await fixture(TIGHT);
    await f.seed(tree, rows);
    const decision = await read(
      f.resolverFor(tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf("tree.items", {
        profile: { name: marker },
        items: [0, 1, 2, 3, 4].map((p) => ({ id: `p${p}` })),
        kids: 10,
      }),
    );
  }, 60_000);
});

describe("the window index is charged for the objects it keeps", () => {
  it("holds, for many small parents, at least the heap they take", async () => {
    // Measured: 100,000 parents of body {"id":"c0000000"} (17 stored bytes)
    // grew the live heap by 173 bytes each after a full collection, over the
    // parsed body, the Parent, its Map slot and its group. 4x the stored JSON
    // is 68.
    const heapPerParent = 173;
    const parentCount = 2000;
    const tree = treeTarget("p");
    const rows = Array.from({ length: parentCount }, (_, p) => ({
      stream: "parents",
      data: { id: `p${String(p).padStart(7, "0")}` },
    }));
    const f = await fixture(8 * 1024 * 1024);
    await f.seed(tree, rows);
    const decision = await read(
      f.resolverFor(tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    await new Response(decision.body).text();
    // The read held its index while it projected: the reservation it kept
    // after sizing its largest window is what the index and that window need.
    expect(Math.max(...f.kept)).toBeGreaterThanOrEqual(
      parentCount * heapPerParent,
    );
    expect(f.inUse()).toBe(0);
  }, 60_000);
});

describe("a payload that is cut into pieces keeps every character whole", () => {
  it("does not split a surrogate pair at a piece boundary", async () => {
    // The payload's JSON is `{"pad":"` (8 characters), the padding, then an
    // emoji: with 65 527 characters of padding its high surrogate is the 65 536th
    // character, the last of the first piece, and its low surrogate the first
    // of the second.
    const payload = { pad: `${"x".repeat(65_527)}\u{1F600}tail` };
    const text = JSON.stringify(payload);
    expect(text.charCodeAt(65_535)).toBeGreaterThanOrEqual(0xd800);
    expect(text.charCodeAt(65_535)).toBeLessThanOrEqual(0xdbff);
    const target: LocalAliasTarget = {
      connector: "plain",
      streams: ["items"],
      project: () => ({ ok: true as const, payload }),
    };
    const f = await fixture(1024 * 1024);
    await f.seed(target, [{ stream: "items", data: { id: "i0" } }]);
    const decision = await read(
      f.resolverFor(target, "plain.items"),
      "plain.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    const bytes = Buffer.from(await new Response(decision.body).arrayBuffer());
    const expected = Buffer.from(envelopeOf("plain.items", payload), "utf8");
    expect(bytes.equals(expected)).toBe(true);
    expect(bytes.toString("utf8")).not.toContain("\uFFFD");
  });
});

/**
 * A read waits in the governor's line for its memory. A request that ends
 * stops waiting: it leaves the line and the connection's queue, and is never
 * granted memory it would not release.
 */
describe("a read that is cancelled stops waiting for memory", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  const plain: LocalAliasTarget = {
    connector: "plain",
    streams: ["items"],
    project: (records) => ({
      ok: true as const,
      payload: { items: records.map((r) => r.data) },
    }),
  };
  const cases = [
    {
      label: "windowed",
      scope,
      target: chatgpt(),
      rows: () => [0, 1, 2].flatMap((c) => chatgptConversation(c, 2, 1000)),
    },
    {
      label: "not windowed",
      scope: "plain.items",
      target: plain,
      rows: () =>
        Array.from({ length: 5 }, (_, i) => ({
          stream: "items",
          data: { id: `i${i}`, pad: "y".repeat(1000) },
        })),
    },
  ];
  const settles = <T>(promise: Promise<T>) =>
    Promise.race([promise, sleep(1000).then(() => "still waiting" as const)]);

  for (const c of cases) {
    it(`${c.label}: the check gives up its place, and the next read is served`, async () => {
      const f = await fixture(1024 * 1024);
      await f.seed(c.target, c.rows());
      const blocker = await f.governor.reserve(f.governor.limitBytes);
      const resolver = f.resolverFor(c.target, c.scope);
      const stop = new AbortController();
      const first = read(resolver, c.scope, stop.signal);
      // The same connection: this read waits in the queue behind the first.
      const second = read(resolver, c.scope);
      await sleep(100);
      stop.abort();
      expect(await settles(first)).toEqual({ kind: "read_aborted" });
      // The first read's place in the line is gone: only the blocker holds.
      expect(f.inUse()).toBe(f.governor.limitBytes);
      blocker();
      const decision = await second;
      expect(decision.kind).toBe("view");
      if (decision.kind !== "view") return;
      await new Response(decision.body).text();
      expect(f.inUse()).toBe(0);
    }, 30_000);
  }
});

describe("a read that waits for memory does not hold its connection's queue", () => {
  const plain: LocalAliasTarget = {
    connector: "plain",
    streams: ["items"],
    project: (records) => ({
      ok: true as const,
      payload: { items: records.map((r) => r.data) },
    }),
  };
  const rows = Array.from({ length: 40 }, (_, i) => ({
    stream: "items",
    data: { id: `i${i}`, pad: "y".repeat(10_000) },
  }));

  it("lets an apply finish behind a waiting read, and ends the read busy if a write lands meanwhile", async () => {
    const f = await fixture(1024 * 1024);
    await f.seed(plain, rows);
    // Another holder has the whole budget, so the read waits for memory.
    const blocker = await f.governor.reserve(f.governor.limitBytes);
    const waiting = read(f.resolverFor(plain, "plain.items"), "plain.items");
    expect(
      await Promise.race([
        waiting.then(() => "served"),
        sleep(200).then(() => "waiting"),
      ]),
    ).toBe("waiting");
    // An apply of the same connection is not held up by it.
    const applied = await Promise.race([
      f.deps.queue.run("c1", "apply", async () => "applied"),
      sleep(1000).then(() => "stalled"),
    ]);
    expect(applied).toBe("applied");
    // A write lands while the read still waits.
    await f.db.batch([
      {
        sql: "UPDATE records SET stamp_o = 9 WHERE connection_id = 'c1' AND stream = 'items' AND pk_hash = (SELECT MIN(pk_hash) FROM records WHERE connection_id = 'c1')",
      },
    ]);
    blocker();
    // The view it was decided on is gone: it asks the caller to try again.
    expect(await waiting).toMatchObject({ kind: "busy" });
    expect(f.inUse()).toBe(0);
  }, 30_000);
});

/**
 * What a client that stops reading holds. The invariant: no client's pace can
 * hold memory from the shared budget that an upload or a listing needs. A
 * windowed read is written to the spool before its first byte goes out, so a
 * paused body is a file and a handle.
 */
describe("a client that never reads holds no shared memory budget", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  // 60 conversations of three 10 KB messages: 1.8 MB, above a 1 MiB budget.
  const rows = () =>
    Array.from({ length: 60 }, (_, c) =>
      chatgptConversation(c, 3, 10_000),
    ).flat();
  const wholeBody = (records: PdppRecord[]) => {
    const projected = chatgpt().project(
      records,
      NOW,
      LEGACY_SCOPE_BINDINGS.get(scope)!.pdppStreams,
    );
    if (!projected.ok) throw new Error("whole projection failed");
    return envelopeOf(scope, projected.payload);
  };
  const within = <T>(promise: Promise<T>, ms: number) =>
    Promise.race([promise, sleep(ms).then(() => "waiting" as const)]);

  it("lets an unrelated upload and an alias listing finish while its body is paused", async () => {
    const target = chatgpt();
    const records = rows();
    const f = await fixture(1024 * 1024);
    await f.seed(target, records);
    const decision = await read(f.resolverFor(target, scope), scope);
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    const reader = decision.body.getReader();
    const decoder = new TextDecoder();
    // The envelope's head and the array's opening: the client pauses here.
    let text = "";
    for (let i = 0; i < 2; i++) {
      text += decoder.decode((await reader.read()).value, { stream: true });
    }
    expect(f.inUse()).toBe(0);
    // An unrelated upload asks for 768 KiB of the 1 MiB budget.
    const upload = await within(
      f.governor.reserve(768 * 1024).then((release) => {
        release();
        return "served" as const;
      }),
      1000,
    );
    expect(upload).toBe("served");
    // So does a scope listing of the alias, on another connection of the db.
    const listing = createLocalListing({
      ...f.deps,
      aliasScopes: () => [scope],
      aliasTargets: () => [target],
    });
    const listed = await within(
      listing.listScopes({ canRead: () => true }),
      3000,
    );
    expect(listed).not.toBe("waiting");
    expect(
      (listed as readonly { scope: string }[]).map((s) => s.scope),
    ).toContain(scope);
    // The paused body is a file. Its size is the response's own: the text of
    // the array's elements, a little less than the whole body.
    const [file] = await f.spool!.list("");
    const expected = wholeBody(records);
    const total = Buffer.byteLength(expected);
    expect(file).toBeDefined();
    expect(await f.spool!.size(file!)).toBeLessThanOrEqual(total);
    expect(await f.spool!.size(file!)).toBeGreaterThan(total - 1024);
    // And the client that resumes reads the whole body.
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      text += decoder.decode(next.value, { stream: true });
    }
    expect(text).toBe(expected);
    expect(await f.spool!.list("")).toEqual([]);
    expect(f.inUse()).toBe(0);
  }, 60_000);
});

describe("the spool is swept when the server starts", () => {
  it("removes what a stopped server left, and nothing outside its directory", async () => {
    const parent = await mkdtemp(join(tmpdir(), "alias-spool-sweep-"));
    spoolDirs.push(parent);
    const dir = join(parent, "alias-spool");
    await mkdir(join(dir, "nested"), { recursive: true });
    await writeFile(join(dir, "alias-leftover"), "half a body");
    await writeFile(join(dir, "nested", "alias-deeper"), "more");
    await writeFile(join(parent, "keep.txt"), "not the spool's");
    await mkdir(join(parent, "alias-spool-neighbour"));
    await writeFile(join(parent, "alias-spool-neighbour", "keep"), "nor this");
    const spool = createFsStreamSyncFiles(dir);
    expect((await spool.list("")).sort()).toEqual([
      "alias-leftover",
      "nested/alias-deeper",
    ]);
    await sweepAliasSpool(spool);
    expect(await spool.list("")).toEqual([]);
    expect(await readFile(join(parent, "keep.txt"), "utf8")).toBe(
      "not the spool's",
    );
    expect(
      await readFile(join(parent, "alias-spool-neighbour", "keep"), "utf8"),
    ).toBe("nor this");
  });
});

describe("a spool whose startup sweep fails", () => {
  it("is not opened, and an alias read is served on the capped in-memory path", async () => {
    const parent = await mkdtemp(join(tmpdir(), "alias-spool-sweepfail-"));
    // A root that is a symbolic link is refused by the sweep: it throws.
    await mkdir(join(parent, "elsewhere"));
    await symlink(join(parent, "elsewhere"), join(parent, "alias-spool"));
    const warnings: unknown[][] = [];
    const spool = await openAliasSpool(parent, {
      warn: (...args) => void warnings.push(args),
    });
    expect(spool).toBeUndefined();
    expect(warnings).toHaveLength(1);
    // As the host composes it: no spool, so main's capped in-memory read.
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const whole = target.project(records, NOW, binding.pdppStreams);
    if (!whole.ok) throw new Error("whole projection failed");
    const f = await fixture(24 * 1024 * 1024, spool ?? false);
    await f.seed(target, records);
    const decision = await read(f.resolverFor(target, scope), scope);
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf(scope, whole.payload),
    );
    expect(f.inUse()).toBe(0);
    await rm(parent, { recursive: true, force: true });
  });
});

describe("a host without a spool refuses a large alias read, as main does", () => {
  const tree = treeTarget("p");
  /** `bytes` of stored child text under one parent. */
  const sized = (bytes: number) => [
    { stream: "parents", data: { id: "p0" } },
    ...Array.from({ length: Math.ceil(bytes / (1024 * 1024)) }, (_, k) => ({
      stream: "kids",
      data: { id: `k${k}`, parent: "p0", pad: "y".repeat(1024 * 1024) },
    })),
  ];

  it("answers too_large above the 64 MiB budget, and holds nothing", async () => {
    const f = await fixture(24 * 1024 * 1024, false);
    await f.seed(tree, sized(65 * 1024 * 1024));
    const decision = await read(
      f.resolverFor(tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("too_large");
    if (decision.kind !== "too_large") return;
    expect(decision.bytes).toBeGreaterThan(ARRAY_BUDGET);
    expect(f.inUse()).toBe(0);
  }, 120_000);

  it("serves a read below the budget in memory, and a paused reader holds no budget", async () => {
    const f = await fixture(24 * 1024 * 1024, false);
    await f.seed(tree, sized(3 * 1024 * 1024));
    const decision = await read(
      f.resolverFor(tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    const reader = decision.body.getReader();
    await reader.read();
    await reader.read();
    expect(f.inUse()).toBe(0);
    await reader.cancel();
  }, 60_000);

  /**
   * What main's resolver took: a `RecordQuery` with none of the alias
   * methods. It is served on the capped in-memory path, as a host with no
   * spool is.
   */
  const plainQuery = (f: Awaited<ReturnType<typeof fixture>>): RecordQuery => {
    const full = createRecordQuery(f.db);
    return {
      listRecords: (input) => full.listRecords(input),
      getRecord: (input) => full.getRecord(input),
      changesSince: (input) => full.changesSince(input),
      streamRecords: (connectionId, stream) =>
        full.streamRecords(connectionId, stream),
    };
  };
  const resolverOver = (
    f: Awaited<ReturnType<typeof fixture>>,
    target: LocalAliasTarget,
    scope: string,
  ) =>
    createLocalResolver(f.deps, {
      query: plainQuery(f),
      aliasScopes: () => [scope],
      aliasTargets: () => [target],
    });

  it("keeps a plain RecordQuery working: the body is the whole projection", async () => {
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const whole = target.project(records, NOW, binding.pdppStreams);
    if (!whole.ok) throw new Error("whole projection failed");
    const f = await fixture(24 * 1024 * 1024);
    await f.seed(target, records);
    const decision = await read(resolverOver(f, target, scope), scope);
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf(scope, whole.payload),
    );
    // No spool was asked for: nothing was written.
    expect(await f.spool!.list("")).toEqual([]);
  });

  it("refuses a plain RecordQuery's read above the budget, as main does", async () => {
    const f = await fixture(24 * 1024 * 1024);
    await f.seed(tree, sized(65 * 1024 * 1024));
    const decision = await read(
      resolverOver(f, tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("too_large");
  }, 120_000);
});

const MiB = 1024 * 1024;

/**
 * Rule 1: no read holds more than a fixed ceiling, whatever the data. A parent
 * and its children are one window, so a conversation larger than the governor
 * allows is not windowed. It is read whole, as main reads it: served when main
 * served it (below `ARRAY_BUDGET`), refused when main refused it.
 */
describe("a windowed read never asks the governor for more than its limit", () => {
  const scope = "chatgpt.conversations";
  const chatgpt = () =>
    legacyAliasScopes(scope).find(
      (t) => t.connector === "chatgpt",
    ) as LocalAliasTarget;
  const limit = 24 * MiB;

  /** What main served for these rows: the whole projection, in one call. */
  const mainBody = (records: PdppRecord[]) => {
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const projected = chatgpt().project(records, NOW, binding.pdppStreams);
    if (!projected.ok) throw new Error("whole projection failed");
    return envelopeOf(scope, projected.payload);
  };

  it("one 74 MB conversation: refused as main refuses it, within the ceiling, with an upload served", async () => {
    const f = await fixture(limit);
    await f.seed(chatgpt(), chatgptConversation(0, 740, 100 * 1024));
    const window = f.governor.window();
    const audit = f.audited();
    const decision = await read(
      f.resolverFor(chatgpt(), scope, audit.query),
      scope,
    );
    expect(decision.kind).toBe("too_large");
    if (decision.kind === "too_large") {
      expect(decision.bytes).toBeGreaterThan(ARRAY_BUDGET);
    }
    // The governor never saw a request above its limit, so it never granted
    // one: nothing else was kept from an upload while it built.
    expect(window.end().peakBytesInFlight).toBeLessThanOrEqual(limit);
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
    expect(await f.spool!.list("")).toEqual([]);
    const upload = await f.governor.reserve(16 * MiB);
    upload();
  }, 120_000);

  it("one 20 MB conversation: served, byte for byte what main serves, within the ceiling", async () => {
    // Its group needs about 80 MB of heap, above the 24 MiB budget, but the
    // read is below `ARRAY_BUDGET`: main served it, so the read is built whole
    // in memory, as main built it.
    const records = chatgptConversation(0, 200, 100 * 1024);
    const f = await fixture(limit);
    await f.seed(chatgpt(), records);
    const window = f.governor.window();
    const audit = f.audited();
    const decision = await read(
      f.resolverFor(chatgpt(), scope, audit.query),
      scope,
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(mainBody(records));
    expect(window.end().peakBytesInFlight).toBeLessThanOrEqual(limit);
    expect(audit.unheld).toEqual([]);
    expect(f.inUse()).toBe(0);
    // Built in memory: no file was written.
    expect(await f.spool!.list("")).toEqual([]);
  }, 120_000);

  it("a child too large for a scan batch is served whole, as main serves it, before any index is built", async () => {
    const tree = treeTarget("p");
    const f = await fixture(limit);
    // One 8 MiB child: its scan batch alone is 32 MiB of heap, above 24 MiB.
    const records = [
      { stream: "parents", data: { id: "p0" } },
      {
        stream: "kids",
        data: { id: "k0", parent: "p0", pad: "y".repeat(8 * MiB) },
      },
    ];
    await f.seed(tree, records);
    const window = f.governor.window();
    const decision = await read(
      f.resolverFor(tree, "tree.items"),
      "tree.items",
    );
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    const projected = tree.project(records, NOW, tree.streams);
    if (!projected.ok) throw new Error("whole projection failed");
    expect(await new Response(decision.body).text()).toBe(
      envelopeOf("tree.items", projected.payload),
    );
    expect(window.end().peakBytesInFlight).toBeLessThanOrEqual(limit);
    expect(f.inUse()).toBe(0);
    expect(await f.spool!.list("")).toEqual([]);
  }, 60_000);

  it("still serves a group that fits, byte for byte what the in-memory read serves", async () => {
    const f = await fixture(limit);
    await f.seed(chatgpt(), chatgptConversation(0, 30, 100 * 1024));
    const resolver = f.resolverFor(chatgpt(), scope);
    const streamed = await read(resolver, scope);
    const whole = await readWhole(resolver, scope);
    expect(streamed.kind).toBe("view");
    expect(whole.kind).toBe("view");
    if (streamed.kind !== "view" || whole.kind !== "view") return;
    expect(await new Response(streamed.body).text()).toBe(
      await new Response(whole.body).text(),
    );
    expect(f.inUse()).toBe(0);
  }, 60_000);
});

/**
 * Rule 2: only a consumer that streams the body to a client gets the spooled,
 * unbounded path. `resolve` is what every consumer that materializes a body
 * calls (an MCP block read, a block check): it takes main's capped path.
 */
describe("a consumer that reads the body whole is never given the spool", () => {
  const tree = treeTarget("p");
  /** 65 parents, each with one child of 1 MiB: 65 MiB, above `ARRAY_BUDGET`. */
  const account = () =>
    Array.from({ length: 65 }, (_, i) => [
      { stream: "parents", data: { id: `p${String(i).padStart(3, "0")}` } },
      {
        stream: "kids",
        data: {
          id: `k${i}`,
          parent: `p${String(i).padStart(3, "0")}`,
          pad: "y".repeat(MiB),
        },
      },
    ]).flat();

  it("resolve answers too_large above the budget, as main does, and writes no file", async () => {
    const f = await fixture(24 * MiB);
    await f.seed(tree, account());
    const resolver = f.resolverFor(tree, "tree.items");
    const decision = await readWhole(resolver, "tree.items");
    expect(decision.kind).toBe("too_large");
    expect(await f.spool!.list("")).toEqual([]);
    expect(f.inUse()).toBe(0);
    // The same read, asked for by a consumer that streams it, is served.
    const streamed = await read(resolver, "tree.items");
    expect(streamed.kind).toBe("view");
    if (streamed.kind === "view") {
      expect(streamed.spooled).toBe(true);
      await streamed.body.cancel();
    }
  }, 120_000);

  it("answers a read of a small alias in memory, with no spool brand", async () => {
    const f = await fixture(24 * MiB);
    await f.seed(tree, [
      { stream: "parents", data: { id: "p0" } },
      { stream: "kids", data: { id: "k0", parent: "p0", pad: "y" } },
    ]);
    const resolver = f.resolverFor(tree, "tree.items");
    const whole = await readWhole(resolver, "tree.items");
    expect(whole.kind).toBe("view");
    if (whole.kind === "view") {
      expect(whole.spooled).toBeUndefined();
      await whole.body.cancel();
    }
  });
});

/** A read nobody waits for stops its scan, not only its wait for memory. */
describe("a read that is cancelled while it indexes stops", () => {
  it("stops reading rows, and holds nothing", async () => {
    const tree = treeTarget("p");
    const f = await fixture(24 * MiB);
    await f.seed(
      tree,
      Array.from({ length: 200 }, (_, i) => [
        { stream: "parents", data: { id: `p${String(i).padStart(3, "0")}` } },
        {
          stream: "kids",
          data: {
            id: `k${i}`,
            parent: `p${String(i).padStart(3, "0")}`,
            pad: "y".repeat(100),
          },
        },
      ]).flat(),
    );
    const real = createRecordQuery(f.db);
    const stop = new AbortController();
    let kidsSized = 0;
    const query: ReturnType<typeof createRecordQuery> = {
      ...real,
      async *recordSizes(connectionId, stream) {
        for await (const size of real.recordSizes(connectionId, stream)) {
          if (stream === "kids") {
            kidsSized += 1;
            if (kidsSized === 3) stop.abort();
          }
          yield size;
        }
      },
    };
    const decision = await read(
      f.resolverFor(tree, "tree.items", query),
      "tree.items",
      stop.signal,
    );
    expect(decision).toEqual({ kind: "read_aborted" });
    // The scan stopped at the next row: it did not read the other 197.
    expect(kidsSized).toBe(3);
    expect(f.inUse()).toBe(0);
    expect(await f.spool!.list("")).toEqual([]);
  }, 60_000);
});

/** The engine's collector, switched on at run time when the process has none. */
function collector(): () => void {
  const existing = (globalThis as { gc?: () => void }).gc;
  if (existing) return existing;
  v8.setFlagsFromString("--expose-gc");
  return vm.runInNewContext("gc") as () => void;
}

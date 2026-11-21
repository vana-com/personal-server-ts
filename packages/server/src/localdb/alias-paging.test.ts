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
import { HEAP_PER_STORED_BYTE } from "../../../core/src/localdb/alias-window.js";
import type { SqlDriver, SqlValue } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import {
  createLocalResolver,
  type LocalAliasTarget,
} from "../../../core/src/localdb/resolve.js";
import type { ReadDecision } from "../../../core/src/stream-sync-read/service.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../../../core/src/stream-sync/storage-retry.js";
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
const NOW_MS = 5000;
const NOW = new Date(NOW_MS).toISOString();
const OBSERVED_MS = 1000;

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
});

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
  const governor: ReturnType<typeof governorOf> = {
    ...real,
    async reserve(bytes, objectBytes) {
      const inner = await real.reserve(bytes, objectBytes);
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
            inner.shrink(keep);
          },
        },
      );
    },
  };
  return { governor, inUse: () => held };
}

async function fixture(limit: number) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "alias-paging",
  });
  drivers.push(db);
  const { governor, inUse } = ledgerOf(governorOf(limit));
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
      aliasScopes: () => [scope],
      aliasTargets: () => [target],
    });
  /**
   * The database as a read sees it, with every result set that carries record
   * bodies checked against the ledger: the heap those bodies take
   * (`HEAP_PER_STORED_BYTE` for each) must be held from the governor at the
   * moment they are read, so no read holds rows the governor does not know.
   */
  function audited() {
    const unheld: string[] = [];
    let readsOfBodies = 0;
    let largest = 0;
    const reader = {
      async query<R extends Record<string, SqlValue>>(
        sql: string,
        params?: readonly SqlValue[],
      ): Promise<R[]> {
        const rows = await db.query<R>(sql, params);
        let bytes = 0;
        for (const row of rows) {
          const body = (row as Record<string, SqlValue>).body;
          if (typeof body === "string") bytes += body.length;
        }
        if (bytes > 0) {
          readsOfBodies++;
          largest = Math.max(largest, bytes);
          if (bytes * HEAP_PER_STORED_BYTE > inUse()) {
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
      unheld,
      reads: () => ({ readsOfBodies, largest }),
    };
  }
  return { db, deps, governor, inUse, seed, resolverFor, audited };
}

const read = (
  resolver: ReturnType<typeof createLocalResolver>,
  scope: string,
): Promise<ReadDecision> =>
  resolver.resolve({
    scope,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });

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
      const f = await fixture(2 * 1024);
      const { wrapped, calls } = counting(target);
      await f.seed(target, records);
      const decision = await read(f.resolverFor(wrapped, scope), scope);
      expect(decision.kind).toBe("view");
      if (decision.kind !== "view") return;
      const text = await new Response(decision.body).text();
      expect(text).toBe(envelopeOf(scope, whole.payload));
      // Several windows: the paged read projects more than once, over each of
      // the parents' windows, twice (the check, then the body).
      expect(parents).toBeGreaterThan(5);
      expect(calls.length).toBeGreaterThanOrEqual(2 * parents);
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

describe("an alias read that fails after its first byte", () => {
  async function failingRead() {
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const records = WINDOW_FIXTURES[scope]!(binding);
    const f = await fixture(2 * 1024);
    await f.seed(target, records);
    const { wrapped, calls } = counting(target);
    // The read's check passes over every window; the body fails in its third.
    let failAt = Infinity;
    const failing: LocalAliasTarget = {
      ...wrapped,
      project: (rs, now, fetched) => {
        if (calls.length + 1 >= failAt) throw new Error("injected failure");
        return wrapped.project(rs, now, fetched);
      },
    };
    const resolver = f.resolverFor(failing, scope);
    // First learn how many projections the check takes.
    const probe = await read(f.resolverFor(wrapped, scope), scope);
    expect(probe.kind).toBe("view");
    if (probe.kind === "view") await probe.body.cancel();
    // The second read's check projects as often as the probe did; its body
    // then fails on its third window.
    failAt = calls.length * 2 + 3;
    const decision = await read(resolver, scope);
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") throw new Error("not a view");
    return decision;
  }

  it("ends its body in an error, never a short valid body", async () => {
    const decision = await failingRead();
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
  });

  it("rejects the response a client reads, so it sees a failed request", async () => {
    const decision = await failingRead();
    await expect(new Response(decision.body).text()).rejects.toThrow(
      "injected failure",
    );
  });

  it("does not leave the governor's memory held", async () => {
    const scope = "instagram.posts";
    const target = legacyAliasScopes(scope)[0] as LocalAliasTarget;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const f = await fixture(2 * 1024);
    await f.seed(target, WINDOW_FIXTURES[scope]!(binding));
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
    const f = await fixture(2 * 1024);
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
    const f = await fixture(2 * 1024);
    await f.seed(target, WINDOW_FIXTURES[scope]!(binding));
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
    const f = await fixture(2 * 1024);
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
    const f = await fixture(4 * 1024);
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
    // One conversation of three 300 KiB messages is a window of its own, and
    // needs more than the whole 2 MiB budget: its read must wait to run alone.
    // Another holder keeps the budget busy, so the wait is real.
    const records = [
      ...chatgptConversation(0, 3, 300 * 1024),
      ...chatgptConversation(1, 1, 100),
      ...chatgptConversation(2, 1, 100),
    ];
    const real = chatgpt();
    const f = await fixture(2 * 1024 * 1024);
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
            void f.governor.reserve(1024).then((release) => {
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
    expect(f.inUse()).toBe(1024);
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

describe("a read that is not windowed holds its payload from the governor", () => {
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

  it("keeps the payload's memory held until the body is delivered or cancelled", async () => {
    // 400 KB of rows under a 1 MiB governor: the payload takes 1.6 MB, more
    // than the budget, so a second such read must wait for the first to end.
    const f = await fixture(1024 * 1024);
    await f.seed(plain, rows);
    const first = await read(items(f), "plain.items");
    expect(first.kind).toBe("view");
    if (first.kind !== "view") return;
    // A body nobody has begun to read holds nothing.
    expect(f.inUse()).toBe(0);
    const reader = first.body.getReader();
    // The envelope's head, then the first piece of the payload; the consumer
    // pauses with the rest of the payload built and waiting to be written.
    await reader.read();
    await reader.read();
    expect(f.inUse()).toBeGreaterThan(0);
    const second = read(items(f), "plain.items");
    const state = await Promise.race([
      second.then(() => "served"),
      sleep(200).then(() => "waiting"),
    ]);
    expect(state).toBe("waiting");
    // Cancelling the body gives its memory back: the waiting read now runs.
    await reader.cancel();
    const decision = await second;
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view") return;
    expect(await new Response(decision.body).text()).toBe(expected);
    expect(f.inUse()).toBe(0);
  });
});

/** The engine's collector, switched on at run time when the process has none. */
function collector(): () => void {
  const existing = (globalThis as { gc?: () => void }).gc;
  if (existing) return existing;
  v8.setFlagsFromString("--expose-gc");
  return vm.runInNewContext("gc") as () => void;
}

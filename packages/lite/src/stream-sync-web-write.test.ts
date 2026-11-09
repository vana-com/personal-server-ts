/**
 * Real-runtime oracles for the Lite browser stream-sync writer.
 *
 * The file imports the real browser composition, state, IndexedDB files,
 * writer and reader. Only network endpoints are faked (fetch is replaced with
 * a stateful gateway and blob store). Nothing else is stubbed.
 *
 * Known fixture limits are listed in the PR body under "Not proven".
 */
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createStreamSyncKeyPorts,
  type StreamSyncFiles,
  type IntakeDeclarations,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { StreamSyncReadService } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import {
  decodeHead,
  parseScope,
  partBlobName,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";

const GATEWAY = "https://gateway.local";
const ACCOUNT = privateKeyToAccount(`0x${"13".repeat(32)}`);
const CONNECTOR = "u3oracle";
const ARTIFACT = "u3-oracle-artifact";
const STREAMS = ["alpha", "beta", "gamma"] as const;
const CHECKPOINT = { alpha: "a1", beta: "b1", gamma: "c1" };
const ROWS = Object.fromEntries(
  STREAMS.map((s) => [
    s,
    [
      { id: `${s}-1`, value: 1 },
      { id: `${s}-2`, value: 2 },
    ],
  ]),
) as Record<(typeof STREAMS)[number], { id: string; value: number }[]>;
const DECLARATIONS: IntakeDeclarations = {
  connector: CONNECTOR,
  version: "1.0.0",
  streams: STREAMS.map((name) => ({
    name,
    semantics: "mutable_state",
    primaryKey: ["id"],
    incremental: true,
  })),
};
type Built = Awaited<ReturnType<typeof createIndexedDbPsLiteRuntime>>;
interface RegistryRow {
  scope: string;
  dataHash: string;
  metadataHash: string;
  expectedVersion: string;
  addedAt: string;
  deletedAt: string | null;
}
const decode = new TextDecoder();
const ownerHeaders = { Authorization: "Bearer owner-token" };
const logical = (stream: string) => `pdpp.${CONNECTOR}.${stream}`;

/** Stateful exclusive-version gateway and ciphertext blob store; no real fetch. */
async function network() {
  // The owner master-key signature, the same one every runtime takes (#577).
  const signature = await signOwnerMasterKey(ACCOUNT);
  const keys = createStreamSyncKeyPorts(signature);
  const rows = new Map<string, RegistryRow>();
  const blobs = new Map<string, Uint8Array>();
  const commits: RegistryRow[] = [];
  const uploads: string[] = [];
  const orderViolations: string[] = [];
  let cutBeforeHead: (() => void) | null = null;
  const fetchImpl = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request =
        input instanceof Request ? input : new Request(String(input), init);
      const url = new URL(request.url);
      const method = init?.method ?? request.method;
      const path = decodeURIComponent(url.pathname);
      const object = path.match(/(pdpp\.[^/]+)\/([^/]+)$/);
      if (method === "PUT" && object) {
        const [, scope, name] = object;
        const bytes = new Uint8Array(await request.arrayBuffer());
        if (name!.startsWith("h-")) {
          const head = decodeHead(await keys.decrypt(scope!, bytes));
          expect(
            head.kind,
            "the oracle must recognize a real encrypted head",
          ).toBe("ok");
          if (head.kind !== "ok") throw new Error("invalid fixture head");
          for (const part of head.head.parts) {
            const suffix = `${scope}/${partBlobName(head.head.generation, part.hash)}`;
            if (![...blobs.keys()].some((key) => key.endsWith(suffix))) {
              orderViolations.push(suffix);
            }
          }
          // Observe the actual upload order, rather than accepting a final read
          // that could hide a transient head-before-parts publication window.
          if (cutBeforeHead) {
            const cut = cutBeforeHead;
            cutBeforeHead = null;
            cut();
          }
        }
        blobs.set(path, bytes);
        uploads.push(path);
        return Response.json({
          url: url.pathname,
          key: url.pathname,
          etag: `"${bytes.length}"`,
          size: bytes.length,
        });
      }
      if (method === "POST" && url.origin === GATEWAY && path === "/v1/data") {
        const body = JSON.parse(
          init?.body ? String(init.body) : await request.text(),
        );
        const current = Number(rows.get(body.scope)?.expectedVersion ?? 0);
        if (Number(body.expectedVersion) !== current + 1) {
          return Response.json(
            { latestVersion: String(current) },
            { status: 409 },
          );
        }
        const row: RegistryRow = {
          scope: body.scope,
          dataHash: body.dataHash,
          metadataHash: body.metadataHash,
          expectedVersion: String(current + 1),
          addedAt: new Date(1_800_000_000_000 + commits.length).toISOString(),
          deletedAt: null,
        };
        rows.set(row.scope, row);
        commits.push(row);
        return new Response(null, { status: 201 });
      }
      if (method === "GET" && url.origin === GATEWAY && path === "/v1/data") {
        return Response.json({
          data: { dataPoints: [...rows.values()] },
          pagination: { hasMore: false, nextCursor: null },
        });
      }
      const single = path.match(/^\/v1\/data\/([^/]+)$/);
      if (method === "GET" && url.origin === GATEWAY && single) {
        const row = [...rows.values()].find(
          (r) => computeDataPointId(ACCOUNT.address, r.scope) === single[1],
        );
        return row
          ? Response.json({ data: row })
          : new Response(null, { status: 404 });
      }
      if ((method === "GET" || method === "HEAD") && object) {
        const bytes = blobs.get(path);
        return new Response(
          method === "HEAD" || !bytes ? null : new Uint8Array(bytes),
          { status: bytes ? 200 : 404 },
        );
      }
      throw new Error(
        `Unexpected network request (network disabled): ${method} ${url.origin}${path}`,
      );
    },
  );
  return {
    signature,
    rows,
    blobs,
    commits,
    uploads,
    orderViolations,
    fetchImpl,
    cutHead(cut: () => void) {
      cutBeforeHead = cut;
    },
  };
}
type Network = Awaited<ReturnType<typeof network>>;

/** Same browser means the SAME factory and DB names, not a copied JSON state. */
function browser(name: string) {
  return { name, factory: new IDBFactory(), checkpointAdvances: 0 };
}
type Browser = ReturnType<typeof browser>;

async function boot(net: Network, browser: Browser, write?: boolean) {
  vi.stubGlobal("indexedDB", browser.factory);
  vi.stubGlobal("IDBKeyRange", IDBKeyRange);
  vi.stubGlobal("navigator", {}); // Exercise IndexedDB fallback, not OPFS.
  vi.stubGlobal("fetch", net.fetchImpl);
  let dead = false;
  const homeFiles: StreamSyncFiles[] = [];
  const assertAlive = () => {
    if (dead) throw new Error("page terminated");
  };
  // Passthrough spy only: capture the real service the browser factory wires.
  const opened = vi.spyOn(StreamSyncReadService, "open");
  const before = opened.mock.results.length;
  const built = await createIndexedDbPsLiteRuntime({
    ownerAddress: ACCOUNT.address,
    ownerSignature: net.signature,
    ownerSyncSigner: {
      address: ACCOUNT.address,
      signMessage: (message: string) => ACCOUNT.signMessage({ message }),
      signAddData: async () => `0x${"22".repeat(65)}`,
      signLineageAttestation: vi.fn(),
    },
    dbName: browser.name,
    storageDbName: `${browser.name}-storage`,
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    derivatives: null,
    // Partial at runtime; the cast covers the sections this test leaves to defaults.
    configDefaults: {
      gateway: { url: GATEWAY },
      sync: { enabled: true },
      streamSync: { read: true, ...(write === undefined ? {} : { write }) },
    } as Partial<ServerConfig>,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    streamSyncDeclarations: (digest) =>
      digest === ARTIFACT ? DECLARATIONS : null,
    streamSyncFiles: (home) => {
      const files = createIndexedDbStreamSyncFiles({
        dbName: `${browser.name}-outbox-${home}`,
        factory: browser.factory,
        keyRange: IDBKeyRange,
      });
      homeFiles.push(files);
      return {
        async write(path, bytes) {
          assertAlive();
          let previous: string | undefined;
          if (path === "state.json") {
            const old = await files.read(path);
            previous = old
              ? JSON.stringify(
                  JSON.parse(decode.decode(old)).checkpoints?.[CONNECTOR],
                )
              : undefined;
          }
          await files.write(path, bytes);
          if (path === "state.json") {
            const current = JSON.parse(decode.decode(bytes)).checkpoints?.[
              CONNECTOR
            ];
            if (current && JSON.stringify(current) !== previous)
              browser.checkpointAdvances++;
          }
        },
        read: async (path) => {
          assertAlive();
          return files.read(path);
        },
        appendMany: async (entries) => {
          assertAlive();
          return files.appendMany(entries);
        },
        sync: async (prefix) => {
          assertAlive();
          return files.sync(prefix);
        },
        size: async (path) => {
          assertAlive();
          return files.size(path);
        },
        list: async (prefix) => {
          assertAlive();
          return files.list(prefix);
        },
        remove: async (path) => {
          assertAlive();
          return files.remove(path);
        },
        async *readChunks(path) {
          assertAlive();
          yield* files.readChunks(path);
        },
      };
    },
  });
  // Pause the background scheduler at bootstrap, before ingestion. This is
  // NOT the simulated page-close operation. Publisher calls below are real.
  expect(built.syncManager?.stop).toBeTypeOf("function");
  await built.syncManager!.stop?.();
  const reader = (await opened.mock.results[before]!
    .value) as StreamSyncReadService;
  return {
    built,
    reader,
    homeFiles,
    crash() {
      dead = true;
    }, // no close, stop, flush, end or reader acknowledgment
  };
}

async function collect(built: Built, runId: string, complete = true) {
  const intake = built.streamSyncIntake!;
  expect(intake).not.toBeNull();
  await intake.begin(runId, {
    connector: CONNECTOR,
    artifactDigest: ARTIFACT,
    owner: { address: ACCOUNT.address, leaseId: null },
    wantFull: true,
    observedAt: 1_800_000_000_000,
  });
  await intake.batch(runId, {
    batch: 0,
    records: STREAMS.flatMap((stream) =>
      ROWS[stream].map((data) => ({ stream, data })),
    ),
  });
  if (complete)
    await intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: [...STREAMS],
      checkpointCandidate: CHECKPOINT,
      lastBatch: 0,
    });
}
async function imported(net: Network, reader: StreamSyncReadService) {
  await reader.observe([...net.rows.values()], {
    fromStart: true,
    lastPage: true,
  });
  await reader.importPending();
}
async function exactRows(net: Network) {
  const fresh = await boot(net, browser(`fresh-${crypto.randomUUID()}`), false);
  expect(fresh.built.streamSyncWriter).toBeNull();
  await imported(net, fresh.reader);
  for (const stream of STREAMS) {
    const decision = await fresh.reader.resolve({
      scope: logical(stream),
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    expect(decision.kind).toBe("view");
    if (decision.kind !== "view")
      throw new Error(`logical read was ${decision.kind}`);
    const envelope = await new Response(decision.body).json();
    expect(
      envelope.data.records.sort((a: { id: string }, b: { id: string }) =>
        a.id.localeCompare(b.id),
      ),
    ).toEqual(ROWS[stream]);
    const response = await fresh.built.runtime.fetch(
      new Request(`https://ps.local/v1/data/${logical(stream)}`, {
        headers: ownerHeaders,
      }),
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(
      body.data.records.sort((a: { id: string }, b: { id: string }) =>
        a.id.localeCompare(b.id),
      ),
    ).toEqual(ROWS[stream]);
  }
}
function exactlyOneHead(net: Network) {
  const heads = net.commits.filter(
    (r) => parseScope(r.scope)?.kind === "stream",
  );
  expect(heads).toHaveLength(STREAMS.length);
  expect(heads.map((r) => r.expectedVersion)).toEqual(["1", "1", "1"]);
  expect(new Set(heads.map((r) => r.scope)).size).toBe(STREAMS.length);
  expect(net.orderViolations).toEqual([]);
}
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("U3 real browser write path (host verification required)", () => {
  // Mutant a: writer runs when streamSync.write is off (sync.ts guard removed).
  it.each([undefined, false])(
    "default/explicit write=%s leaves legacy writes intact",
    async (write) => {
      const net = await network();
      const { built } = await boot(
        net,
        browser(`gate-${String(write)}`),
        write,
      );
      expect(built.streamSyncWriter).toBeNull();
      expect(built.streamSyncIntake).toBeNull();
      const response = await built.runtime.fetch(
        new Request("https://ps.local/v1/data/legacy.items", {
          method: "POST",
          headers: { ...ownerHeaders, "Content-Type": "application/json" },
          body: JSON.stringify({ items: ROWS.alpha }),
        }),
      );
      expect(response.status).toBe(201);
      const read = await built.runtime.fetch(
        new Request("https://ps.local/v1/data/legacy.items", {
          headers: ownerHeaders,
        }),
      );
      expect(read.status).toBe(200);
      // Exact data payload, not a substring: a dropped row or changed value must fail.
      // collectedAt is a wall-clock stamp, so the envelope is checked by fields.
      const body = await read.json();
      expect(body.scope).toBe("legacy.items");
      expect(body.data).toEqual({ items: ROWS.alpha });
      expect(net.uploads).toEqual([]);
      expect(net.commits).toEqual([]);
    },
  );

  // Mutant b: head uploaded before its parts (writer.ts publish order).
  // Upload-time orderViolations must fail even if the eventual read passes.
  it("publishes three streams and serves exact rows from empty IndexedDB", async () => {
    const net = await network();
    const first = await boot(net, browser("fresh-source"), true);
    await collect(first.built, "fresh-run");
    await first.built.streamSyncWriter!.publishPending();
    exactlyOneHead(net);
    await exactRows(net);
  });

  // Mutant c: a pending spool is not replayed on restart.
  // Versions, exact logical rows, checkpoint transitions and third boot must
  // all remain unchanged. IDB names/factory survive; runtime objects do not.
  it.each(["ready-entry", "parts-before-head"] as const)(
    "resumes once after %s without close",
    async (point) => {
      const net = await network();
      const sameBrowser = browser(`resume-${point}`);
      let first: Awaited<ReturnType<typeof boot>> | null = await boot(
        net,
        sameBrowser,
        true,
      );
      await collect(first.built, "resumable-run");
      expect((await first.built.streamSyncWriter!.status()).pending).toEqual([
        expect.objectContaining({ runId: "resumable-run", phase: "ready" }),
      ]);
      if (point === "parts-before-head") {
        const dying = first;
        net.cutHead(() => {
          dying.crash();
          throw new Error("page terminated before head");
        });
        // Real catch/finally may run in this JS process but all old outbox access
        // fails after the cut. This is an I/O crash model, not a browser kill test.
        await dying.built.streamSyncWriter!.publishPending().catch(() => {});
        expect(net.uploads.some((path) => /\/g[1-9][0-9]*-p-/.test(path))).toBe(
          true,
        );
        expect(net.uploads.some((path) => path.includes("/h-"))).toBe(false);
      } else first.crash();
      first = null;
      expect(
        net.commits.filter((r) => parseScope(r.scope)?.kind === "stream"),
      ).toEqual([]);
      const next = await boot(net, sameBrowser, true);
      await next.built.streamSyncWriter!.publishPending();
      exactlyOneHead(net);
      expect(sameBrowser.checkpointAdvances).toBe(1);
      expect(
        (await next.built.streamSyncWriter!.status()).checkpoints[CONNECTOR]
          ?.value,
      ).toEqual(CHECKPOINT);
      next.crash();
      const again = await boot(net, sameBrowser, true);
      await again.built.streamSyncWriter!.publishPending();
      exactlyOneHead(net);
      expect(sameBrowser.checkpointAdvances).toBe(1);
      await exactRows(net);
    },
  );

  // Mutant d: recover() admits a collecting spool as complete.
  // Persisted partial bytes must not produce any registry row, and a later
  // complete run must still succeed; mere append success is not completion.
  it("discards an interrupted collecting spool and admits the later run", async () => {
    const net = await network();
    const sameBrowser = browser("partial");
    let first: Awaited<ReturnType<typeof boot>> | null = await boot(
      net,
      sameBrowser,
      true,
    );
    await collect(first.built, "partial-run", false);
    await first.built.streamSyncIntake!.batch("partial-run", {
      batch: 1,
      // FLUSH_BYTES is 8 MiB: this batch must cross it so spool lines are durable.
      records: Array.from({ length: 200 }, (_, i) => ({
        stream: "alpha",
        data: { id: `partial-${i}`, value: "x".repeat(48_000) },
      })),
    });
    const paths = (
      await Promise.all(first.homeFiles.map((f) => f.list("runs/partial-run")))
    )
      .flat()
      .filter((p) => !p.endsWith("entry.json"));
    expect(
      paths.length,
      "must cut after actual spool writes, before end/ready",
    ).toBeGreaterThan(0);
    expect(
      (await first.built.streamSyncWriter!.status()).pending[0]?.phase,
    ).toBe("collecting");
    first.crash();
    first = null;
    const next = await boot(net, sameBrowser, true);
    await next.built.streamSyncWriter!.publishPending();
    expect(net.commits).toEqual([]);
    expect(net.uploads).toEqual([]);
    expect(
      (await next.built.streamSyncWriter!.status()).checkpoints[CONNECTOR],
    ).toBeUndefined();
    await collect(next.built, "later-complete-run");
    await next.built.streamSyncWriter!.publishPending();
    exactlyOneHead(net);
    await exactRows(net);
  });

  // Mutant e: a stream reads as ready from a legacy file when its remote
  // control row is deleted or its blobs are missing. Fixture changes only
  // remote observations; it never invokes delete, tombstone or reconnect code.
  // A named connection has no legacy fallback. The unnamed listing is not
  // asserted: a local legacy write legitimately reports that scope as ready.
  it.each(["deleted", "missing-blobs"] as const)(
    "never reports ready for %s despite a legacy file",
    async (kind) => {
      const net = await network();
      const writer = await boot(net, browser(`seed-${kind}`), true);
      await collect(writer.built, "readiness-seed");
      await writer.built.streamSyncWriter!.publishPending();
      const control = [...net.rows.values()].find(
        (r) => parseScope(r.scope)?.kind === "control",
      )!;
      const ns = parseScope(control.scope)!.ns;
      if (kind === "deleted")
        net.rows.set(control.scope, {
          ...control,
          deletedAt: new Date(1_800_000_001_000).toISOString(),
          expectedVersion: "2",
        });
      else net.blobs.clear();
      const fresh = await boot(net, browser(`unavailable-${kind}`), false);
      const write = await fresh.built.runtime.fetch(
        new Request(`https://ps.local/v1/data/${logical("alpha")}`, {
          method: "POST",
          headers: { ...ownerHeaders, "Content-Type": "application/json" },
          body: JSON.stringify({ stale: true }),
        }),
      );
      expect(write.status).toBe(201);
      await imported(net, fresh.reader);
      const decision = await fresh.reader.resolve({
        scope: logical("alpha"),
        connection: ns,
        cursor: null,
        legacyFile: true,
        isOwnerView: true,
      });
      expect(decision).toEqual({
        kind: "unavailable",
        reason: kind === "deleted" ? "deleted" : "connection_not_found",
      });
      const response = await fresh.built.runtime.fetch(
        new Request(
          `https://ps.local/v1/data/${logical("alpha")}?connection=${ns}`,
          { headers: ownerHeaders },
        ),
      );
      // Exact refusal: deletion is 410 DATA_DELETED; a vanished connection is 404.
      expect(response.status).toBe(kind === "deleted" ? 410 : 404);
    },
  );

  // Mutant f2: a named view already served by this reader is replayed from a
  // cache after its control is deleted, without rechecking the control. The
  // same reader must see the deletion, refuse, and return no old row bodies.
  it("stops serving an already-imported named view when its control is deleted", async () => {
    const net = await network();
    const writer = await boot(net, browser("warm-seed"), true);
    await collect(writer.built, "warm-seed-run");
    await writer.built.streamSyncWriter!.publishPending();
    const control = [...net.rows.values()].find(
      (r) => parseScope(r.scope)?.kind === "control",
    )!;
    const ns = parseScope(control.scope)!.ns;
    const query = {
      scope: logical("alpha"),
      connection: ns,
      cursor: null,
      legacyFile: true,
      isOwnerView: true,
    };
    const reader = await boot(net, browser("warm-reader"), false);
    const legacy = await reader.built.runtime.fetch(
      new Request(`https://ps.local/v1/data/${logical("alpha")}`, {
        method: "POST",
        headers: { ...ownerHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ stale: true }),
      }),
    );
    expect(legacy.status).toBe(201);
    await imported(net, reader.reader);

    // Serve the live rows on this reader first, so a cached view can exist.
    const live = await reader.reader.resolve(query);
    expect(live.kind).toBe("view");
    if (live.kind !== "view") throw new Error(`live read was ${live.kind}`);
    const envelope = await new Response(live.body).json();
    expect(
      envelope.data.records.sort((a: { id: string }, b: { id: string }) =>
        a.id.localeCompare(b.id),
      ),
    ).toEqual(ROWS.alpha);

    // The deletion reaches the SAME reader that already served those rows.
    net.rows.set(control.scope, {
      ...control,
      deletedAt: new Date(1_800_000_001_000).toISOString(),
      expectedVersion: "2",
    });
    await imported(net, reader.reader);
    expect(await reader.reader.resolve(query)).toEqual({
      kind: "unavailable",
      reason: "deleted",
    });
    const response = await reader.built.runtime.fetch(
      new Request(
        `https://ps.local/v1/data/${logical("alpha")}?connection=${ns}`,
        { headers: ownerHeaders },
      ),
    );
    expect(response.status).toBe(410);
    const text = await response.text();
    expect(text).toContain("DATA_DELETED");
    expect(text).not.toContain("alpha-1");
    expect(text).not.toContain("alpha-2");
  });
});

/**
 * Step 1 of the stream-sync memory plan: measurement and red acceptance gates
 * for the read side. Counters come from budget.ts (`estimateReadMemory: true`).
 *
 * Conventions:
 * - Plain `it` tests are green on the current code and must stay green.
 * - `it.fails` marks a gate that needs a later step (step 2+). It passes while
 *   the gate fails, and must be flipped to `it` when that step lands. Each one
 *   names the step and the reason in its title.
 * - Fixtures use identity encryption. The real publisher, codec and hashes are
 *   kept. Encryption is not what these tests measure.
 */

import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import v8 from "node:v8";
import vm from "node:vm";
import type {
  JsonObject,
  Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { LEGACY_SCOPE_BINDINGS } from "../legacy-projection/index.js";
import {
  READ_THRESHOLDS,
  ReadMemoryEstimator,
  type ReadMemoryEstimate,
} from "./budget.js";
import { streamSyncReadHashes } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import type { StreamSyncOverlayEntry, StreamSyncReadFiles } from "./ports.js";
import { planProjection, type ProjectionInput } from "./projection.js";
import {
  StreamSyncReadService,
  type ReadDecision,
  type StreamSyncReadOptions,
} from "./service.js";
import { buildTestHead, testOwnerKey, type TestOwnerKey } from "./testing.js";

const KiB = 1024;
const MiB = 1024 * KiB;
/** Fixture bound on one clear part. A fixture constant, not a production limit (production target is 4 MiB). */
const FIXTURE_PART_BYTES = 128 * KiB;
const META = `0x${"ab".repeat(32)}`;
/** Overlay stamps sit above any imported `observedAt`, as in service.test.ts, so local rows win. */
const OVERLAY_STAMP = 5_000_000_000_000;
const silent = { info() {}, warn() {}, error() {} };
const CONNECTOR = "acme";
const ask = (scope: string) => ({
  scope,
  connection: null,
  cursor: null,
  legacyFile: false,
});

function masterKey(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (seed * 31 + i) & 0xff);
}

/** Bit prefixes of length `bits`: every head part is one of these, so parts stay small. */
function prefixesFor(bits: number): string[] {
  return Array.from({ length: 2 ** bits }, (_, i) =>
    i.toString(2).padStart(bits, "0"),
  );
}

/** Prefix length that keeps parts near FIXTURE_PART_BYTES for `n` records. */
function bitsFor(n: number): number {
  return Math.log2(n / 128);
}

/** Fixed-width IDs and a padded value: encoded lines of 384 to 768 bytes. */
function recordsOf(n: number): JsonObject[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `r${String(i).padStart(8, "0")}`,
    seq: i,
    body: "x".repeat(300 + (i % 300)),
  }));
}

class Fixture {
  readonly blobs = new Map<string, Uint8Array>();
  readonly rows = new Map<string, MirrorFeedRow>();
  readonly files = createMemoryStreamSyncReadFiles();
  overlay: StreamSyncOverlayEntry[] = [];
  private clock = Date.parse("2026-11-01T00:00:00Z");
  /** Publishes with identity encryption. */
  readonly identity: TestOwnerKey;

  constructor(readonly owner: TestOwnerKey) {
    this.identity = {
      ...owner,
      encrypt: async (_scope, clear) => clear.slice(),
    };
  }

  private row(scope: string, dataHash: string, metadataHash: string) {
    const previous = this.rows.get(scope);
    const version = previous ? Number(previous.expectedVersion) + 1 : 1;
    this.clock += 1000;
    this.rows.set(scope, {
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      addedAt: new Date(this.clock).toISOString(),
      deletedAt: null,
    });
    return version;
  }

  async activate(connector: string, ns: string): Promise<void> {
    const { active } = await this.owner.control();
    this.row(controlScope(connector, ns), active.dataHash, active.metadataHash);
  }

  async publish(input: {
    connector: string;
    ns: string;
    stream: string;
    generation: number;
    records: JsonObject[];
    prefixes?: string[];
    observedAt?: number;
  }): Promise<void> {
    const built = await buildTestHead({
      key: this.identity,
      connector: input.connector,
      ns: input.ns,
      stream: input.stream,
      generation: input.generation,
      primaryKey: ["id"],
      records: input.records,
      observedAt: input.observedAt ?? this.clock,
      prefixes: input.prefixes,
    });
    for (const [k, v] of built.blobs) this.blobs.set(k, v);
    this.row(built.scope, built.dataHash, META);
  }

  options(
    overrides: Partial<StreamSyncReadOptions> = {},
  ): Partial<StreamSyncReadOptions> {
    return {
      files: this.files,
      blobs: {
        get: async (k) => this.blobs.get(k)?.slice() ?? null,
      },
      // Identity decryption, matching the identity publisher above.
      keys: {
        hashes: streamSyncReadHashes,
        keyCheck: this.owner.keyCheck,
        decrypt: async (_scope, cipher) => cipher.slice(),
      },
      logger: silent,
      overlay: { entries: async () => this.overlay },
      now: () => new Date("2026-11-02T00:00:00Z"),
      ...overrides,
    };
  }

  async service(
    overrides: Partial<StreamSyncReadOptions> = {},
  ): Promise<StreamSyncReadService> {
    return StreamSyncReadService.open(
      this.options(overrides) as StreamSyncReadOptions,
    );
  }

  async sync(service: StreamSyncReadService): Promise<void> {
    await service.observe([...this.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    await service.importPending();
  }
}

/** Drain a view body chunk by chunk: a digest, a byte count, and the records' count. */
async function drain(
  decision: ReadDecision,
): Promise<{ digest: string; bytes: number; records: number }> {
  if (decision.kind !== "view")
    throw new Error(`expected view: ${decision.kind}`);
  const reader = decision.body.getReader();
  const hash = sha256.create();
  const decoder = new TextDecoder();
  const idToken = '"id":"';
  let carry = "";
  let bytes = 0;
  let records = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    hash.update(next.value);
    bytes += next.value.byteLength;
    // Count `"id":"` across chunk boundaries: keep the last token-1 characters.
    const text = carry + decoder.decode(next.value, { stream: true });
    records += text.split(idToken).length - 1;
    carry = text.slice(-(idToken.length - 1));
  }
  return {
    digest: Array.from(hash.digest(), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join(""),
    bytes,
    records,
  };
}

function expectQuiet(s: ReadMemoryEstimate): void {
  for (const [name, c] of Object.entries(s.categories)) {
    expect(c.estimatedCurrent, name).toBe(0);
    expect(c.thresholdExceedances, name).toBe(0);
  }
  expect(s.estimatedBytesCurrent).toBe(0);
  expect(s.oversizeRecordCount).toBe(0);
}

async function plainRead(n: number, measure: boolean) {
  const owner = await testOwnerKey(masterKey(41));
  const f = new Fixture(owner);
  const ns = await owner.ns(CONNECTOR, "account-1");
  await f.activate(CONNECTOR, ns);
  await f.publish({
    connector: CONNECTOR,
    ns,
    stream: "items",
    generation: 1,
    records: recordsOf(n),
    prefixes: prefixesFor(bitsFor(n)),
  });
  const service = await f.service({ estimateReadMemory: measure });
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items"));
  const result = await drain(decision);
  const budget = decision.kind === "view" ? decision.budget : undefined;
  return { result, budget: budget?.snapshot() };
}

describe("stream-sync read memory: step 1 measurement", () => {
  describe("plain large stream: fixed live part, growing part count", () => {
    it("plain_many_part_read_has_fixed_live_payload_peak", async () => {
      const small = await plainRead(8_192, true);
      const large = await plainRead(32_768, true);

      for (const [label, run, n] of [
        ["N", small, 8_192],
        ["4N", large, 32_768],
      ] as const) {
        expect(run.result.records, label).toBe(n);
        const s = run.budget!;
        expect(
          s.categories.importedPart.estimatedPeak,
          label,
        ).toBeLessThanOrEqual(FIXTURE_PART_BYTES);
        expect(
          s.categories.decodedPart.estimatedPeak,
          label,
        ).toBeLessThanOrEqual(2 * FIXTURE_PART_BYTES);
        expect(s.estimatedBytesPeak, label).toBeLessThanOrEqual(2 * MiB);
        // No overlay, no projection: those peaks are zero for a plain read.
        expect(s.categories.overlayWinners.estimatedPeak, label).toBe(0);
        expect(s.categories.overlayPayload.estimatedPeak, label).toBe(0);
        expect(s.categories.spoolBuffer.estimatedPeak, label).toBe(0);
        expect(s.categories.shardPayload.estimatedPeak, label).toBe(0);
        expect(s.categories.otherRows.estimatedPeak, label).toBe(0);
        expectQuiet(s);
      }
      // The workload really grows: the part count rises fourfold.
      expect(
        large.budget!.categories.importedPart.acquisitions,
      ).toBeGreaterThan(
        3.9 * small.budget!.categories.importedPart.acquisitions,
      );
      // Each read holds one part at a time, not the stream.
      expect(large.budget!.estimatedBytesPeak).toBeLessThan(
        large.result.bytes / 4,
      );
    }, 120_000);

    it("stats on and stats off produce the same output", async () => {
      const off = await plainRead(8_192, false);
      const on = await plainRead(8_192, true);
      expect(on.result).toEqual(off.result);
      expect(off.budget).toBeUndefined();
    });
  });

  describe("overlay log with a bounded distinct-key working set", () => {
    it("repeated_overlay_rows_do_not_accumulate_losing_versions", async () => {
      const results: ReadMemoryEstimate[] = [];
      for (const n of [8_192, 32_768]) {
        const owner = await testOwnerKey(masterKey(42));
        const f = new Fixture(owner);
        const ns = await owner.ns(CONNECTOR, "account-1");
        await f.activate(CONNECTOR, ns);
        const base = Array.from({ length: 64 }, (_, k) => ({
          id: `k${String(k).padStart(2, "0")}`,
          seq: -1,
        }));
        await f.publish({
          connector: CONNECTOR,
          ns,
          stream: "items",
          generation: 1,
          records: base,
        });
        const local = (i: number): Line => ({
          o: OVERLAY_STAMP + i,
          r: "local",
          v: { id: `k${String(i % 64).padStart(2, "0")}`, seq: i },
        });
        f.overlay = [
          {
            runId: "local",
            ns,
            state: "pending",
            streams: ["items"],
            async *lines(): AsyncGenerator<Line> {
              for (let i = 0; i < n; i++) {
                yield i % 1000 === 999
                  ? // A row without the primary key: skipped, never a winner.
                    { o: 1, r: "local", v: { seq: i } }
                  : local(i);
              }
            },
          },
          // Unattributed, wrong namespace, and wrong stream: never overlaid.
          {
            runId: "unattributed",
            ns: null,
            state: "pending",
            streams: ["items"],
            async *lines(): AsyncGenerator<Line> {
              yield { o: 9_999_999_999, r: "x", v: { id: "k00", seq: -2 } };
            },
          },
          {
            runId: "other-ns",
            ns: "0000000000000000",
            state: "pending",
            streams: ["items"],
            async *lines(): AsyncGenerator<Line> {
              yield { o: 9_999_999_999, r: "x", v: { id: "k01", seq: -3 } };
            },
          },
          {
            runId: "other-stream",
            ns,
            state: "pending",
            streams: ["other"],
            async *lines(): AsyncGenerator<Line> {
              yield { o: 9_999_999_999, r: "x", v: { id: "k02", seq: -4 } };
            },
          },
        ];
        const service = await f.service({ estimateReadMemory: true });
        await f.sync(service);
        const decision = await service.resolve(ask("pdpp.acme.items"));
        if (decision.kind !== "view") throw new Error(decision.kind);
        const text = await new Response(decision.body).text();
        const data = JSON.parse(text).data.records as {
          id: string;
          seq: number;
        }[];
        // Each of the 64 IDs is returned once, with its last local value.
        expect(data).toHaveLength(64);
        const lastSeq = new Map<string, number>();
        for (let i = 0; i < n; i++) {
          if (i % 1000 === 999) continue;
          lastSeq.set(`k${String(i % 64).padStart(2, "0")}`, i);
        }
        for (const row of data) expect(row.seq).toBe(lastSeq.get(row.id));
        results.push(decision.budget!.snapshot());
      }
      const [small, large] = results as [
        ReadMemoryEstimate,
        ReadMemoryEstimate,
      ];
      expect(small.categories.overlayWinners.estimatedPeak).toBe(64);
      expect(small.categories.overlayPendingKeys.estimatedPeak).toBe(64);
      expect(large.categories.overlayWinners.estimatedPeak).toBe(64);
      expect(large.categories.overlayPendingKeys.estimatedPeak).toBe(64);
      expect(small.categories.overlayPayload.estimatedPeak).toBeLessThanOrEqual(
        128 * KiB,
      );
      expect(large.categories.overlayPayload.estimatedPeak).toBeLessThanOrEqual(
        small.categories.overlayPayload.estimatedPeak + KiB,
      );
      expectQuiet(small);
      expectQuiet(large);
    });
  });

  describe("distinct overlay keys: characterization and the step-2+ gate", () => {
    async function distinct(n: number) {
      const owner = await testOwnerKey(masterKey(43));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      const half = n / 2;
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: Array.from({ length: half }, (_, i) => ({
          id: `x${i}`,
          base: true,
        })),
      });
      f.overlay = [
        {
          runId: "local",
          ns,
          state: "pending",
          streams: ["items"],
          async *lines(): AsyncGenerator<Line> {
            for (let i = 0; i < n; i++) {
              // Half replace imported rows, half are local only.
              const id = i < half ? `x${i}` : `local${i}`;
              yield { o: OVERLAY_STAMP + i, r: "local", v: { id, seq: i } };
            }
          },
        },
      ];
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      const decision = await service.resolve(ask("pdpp.acme.items"));
      const drained = await drain(decision);
      return { decision, drained, n };
    }

    it("characterizes today's linear overlay: winners and pending keys equal N and 4N", async () => {
      for (const n of [2_048, 8_192]) {
        const { decision, drained } = await distinct(n);
        expect(drained.records).toBe(n);
        const snap =
          decision.kind === "view" ? decision.budget!.snapshot() : null;
        // Current code retains every distinct winner. This pins that, so the
        // counters are shown to be honest before any reader change.
        expect(snap!.categories.overlayWinners.estimatedPeak).toBe(n);
        expect(snap!.categories.overlayPendingKeys.estimatedPeak).toBe(n);
      }
    });

    it.fails(
      "step 2+: distinct_overlay_winners_are_bounded_not_all_retained (red until the indexed overlay lands)",
      async () => {
        for (const n of [2_048, 8_192]) {
          const { decision } = await distinct(n);
          const snap =
            decision.kind === "view" ? decision.budget!.snapshot() : null;
          expect(
            snap!.categories.overlayWinners.estimatedPeak,
          ).toBeLessThanOrEqual(1024);
          expect(
            snap!.categories.overlayPendingKeys.estimatedPeak,
          ).toBeLessThanOrEqual(1024);
        }
      },
    );
  });

  describe("windowed projection: phases, skew, and the shard gate", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("chatgpt.conversations")!;

    function chatgpt(n: number) {
      const conversations: JsonObject[] = [];
      const messages: JsonObject[] = [];
      for (let c = 0; c < n; c++) {
        const id = `conv-${String(c).padStart(6, "0")}`;
        conversations.push({
          id,
          title: `t${c}`,
          create_time: "2026-01-01T00:00:00.000Z",
          update_time: `2026-01-${String((c % 28) + 1).padStart(2, "0")}T00:00:00.000Z`,
          current_node: `${id}:n1`,
          message_count_on_current_branch: 2,
        });
        for (let m = 0; m < 2; m++) {
          messages.push({
            id: `${id}:n${m}`,
            conversation_id: id,
            parent_id: m ? `${id}:n0` : null,
            role: m ? "assistant" : "user",
            content: "m".repeat(200),
            content_type: "text",
            model_slug: null,
            create_time: "2026-01-01T00:00:00.000Z",
            on_current_branch: true,
          });
        }
      }
      return { conversations, messages };
    }

    /** Run planProjection on the chatgpt binding; `skewed` puts every join key in one shard. */
    async function project(n: number, skewed: boolean) {
      const { conversations, messages } = chatgpt(n);
      const budget = new ReadMemoryEstimator();
      const hashes = streamSyncReadHashes.sha256;
      const input: ProjectionInput = {
        scope: "chatgpt.conversations",
        binding,
        profileKey: "chatgpt",
        lines: (stream) => {
          const rows = stream === "conversations" ? conversations : messages;
          return (async function* (): AsyncGenerator<Line> {
            for (const v of rows) yield { o: 1, r: "t", v };
          })();
        },
        streamBytes: () => 1,
        sha256: skewed
          ? async (data: Uint8Array) => {
              const h = await hashes(data);
              h[0] = 0;
              return h;
            }
          : hashes,
        spool: createMemoryStreamSyncReadFiles(),
        spoolId: `s${n}${skewed ? "k" : ""}`,
        budgetBytes: 1 << 30,
        now: "2026-11-02T00:00:00.000Z",
        budget,
      };
      const plan = await planProjection(input);
      if (plan.kind !== "ok") throw new Error("too large");
      let text = "";
      for await (const part of plan.payload) text += part;
      return { text, snap: budget.snapshot(), total: n + 2 * n };
    }

    it("skew and the normal hash give the same projected bytes", async () => {
      const normal = await project(256, false);
      const skewed = await project(256, true);
      expect(skewed.text).toBe(normal.text);
      expectQuiet(normal.snap);
      expectQuiet(skewed.snap);
    });

    it("phase bounds hold: spool buffer, merge width and merge chunks", async () => {
      for (const n of [256, 1_024]) {
        for (const skewed of [false, true]) {
          const { snap } = await project(n, skewed);
          expect(snap.categories.spoolBuffer.estimatedPeak).toBeLessThanOrEqual(
            READ_THRESHOLDS.spoolBufferBytes,
          );
          expect(
            snap.categories.mergeCursors.estimatedPeak,
          ).toBeLessThanOrEqual(256);
          expect(snap.categories.mergeChunk.estimatedPeak).toBeLessThanOrEqual(
            READ_THRESHOLDS.mergeChunkBytes,
          );
          expectQuiet(snap);
        }
      }
    });

    it("characterizes the skew: one hot shard holds every row, a normal hash spreads them", async () => {
      const normal = await project(256, false);
      const skewed = await project(256, true);
      const rows = 256 + 512;
      expect(skewed.snap.categories.shardRows.estimatedPeak).toBe(rows);
      expect(normal.snap.categories.shardRows.estimatedPeak).toBeLessThan(rows);
    });

    it.fails(
      "step 4+: windowed_projection_shard_payload_flat_under_skew (red until shard reads are bounded)",
      async () => {
        const small = await project(256, true);
        const large = await project(1_024, true);
        // A flat bound: the hot shard does not grow fourfold with the input.
        expect(
          large.snap.categories.shardPayload.estimatedPeak,
        ).toBeLessThanOrEqual(
          1.25 * small.snap.categories.shardPayload.estimatedPeak + 64 * KiB,
        );
      },
    );
  });

  describe("durable read store: the step-2 requirement, against the store production selects", () => {
    // The store production selects for the stream-sync read side. Lite
    // (packages/lite/src/sync.ts) uses `createMemoryStreamSyncReadFiles()`
    // unless a host injects its own `StreamSyncReadFiles`. A reopen is a new
    // call with the same root: a durable store reads back what the last
    // instance wrote. Step 2 changes this selector to the durable store. The
    // predicates below are about that store, not about the memory adapter.
    const openProductionReadFiles = (_root: string): StreamSyncReadFiles =>
      createMemoryStreamSyncReadFiles();

    const PAYLOAD_FILES = 8;
    const payloadPath = (i: number) => `views/a/_/s/parts/p${i}`;
    const payloadBytes = (i: number) => new Uint8Array(MiB).fill(i + 1);

    it("green setup: the selected store writes, reads and lists one file", async () => {
      const store = openProductionReadFiles("setup-root");
      await store.write("views/a/_/s/parts/one", new Uint8Array([1, 2, 3]));
      expect(await store.read("views/a/_/s/parts/one")).toEqual(
        new Uint8Array([1, 2, 3]),
      );
      expect(await store.list("views/a/_/s")).toEqual([
        "views/a/_/s/parts/one",
      ]);
    });

    it.fails(
      "step 2: the read store is durable and keeps payload out of process memory: after 8 MiB is written, resident payload grows by under 1 MiB, and a reopen reads the same bytes (red: the production selector is memory)",
      async () => {
        const root = "durable-root";
        const forceGc = (): void => {
          const g = (globalThis as { gc?: () => void }).gc;
          if (g) {
            g();
            g();
            return;
          }
          // Runtime fallback for `--expose-gc`, which vitest does not pass.
          v8.setFlagsFromString("--expose-gc");
          (vm.runInNewContext("gc") as () => void)();
          (vm.runInNewContext("gc") as () => void)();
        };
        const residentPayload = (): number => {
          forceGc();
          const m = process.memoryUsage();
          return m.heapUsed + m.arrayBuffers;
        };

        const store = openProductionReadFiles(root);
        const before = residentPayload();
        for (let i = 0; i < PAYLOAD_FILES; i++) {
          await store.write(payloadPath(i), payloadBytes(i));
        }
        const growth = residentPayload() - before;
        expect(growth).toBeLessThan(MiB);

        const reopened = openProductionReadFiles(root);
        for (let i = 0; i < PAYLOAD_FILES; i++) {
          const got = await reopened.read(payloadPath(i));
          expect(got, payloadPath(i)).not.toBeNull();
          expect(got!.byteLength).toBe(MiB);
        }
      },
    );
  });

  describe("retained parsed lines: a reader that keeps every line", () => {
    // Gate, not yet runnable. The estimator counts bookkeeping calls, so a
    // reader that collects every parsed line into an array (viewLines, no
    // overlay) keeps the whole stream while the estimate reports one part.
    // The independent instrument is the shared child-process high-water
    // helper in PS #565 (test/stream-sync-p1-bounded). It is not yet
    // importable, so this body throws. Replace it with the helper's
    // assertion when the helper lands; do not copy the helper's sampler here.
    it.fails(
      "step 2+: a reader that retains every parsed line across a read is caught by the shared high-water helper (gate: PS #565, not yet shared)",
      () => {
        throw new Error(
          "gate: needs the shared child-process high-water helper from PS #565 (test/stream-sync-p1-bounded); not yet importable",
        );
      },
    );
  });

  describe("import and restart", () => {
    it("a fresh service over the same files serves the same bytes with no blob or feed calls", async () => {
      const owner = await testOwnerKey(masterKey(44));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: recordsOf(2_048),
        prefixes: prefixesFor(bitsFor(2_048)),
      });
      const first = await f.service({ estimateReadMemory: true });
      await f.sync(first);
      const before = await drain(await first.resolve(ask("pdpp.acme.items")));

      let gets = 0;
      const restarted = await StreamSyncReadService.open(
        f.options({
          estimateReadMemory: true,
          blobs: {
            get: async () => {
              gets++;
              throw new Error("blob read on restart");
            },
          },
        }) as StreamSyncReadOptions,
      );
      expect(restarted.wantsListingFromStart()).toBe(false);
      const after = await drain(
        await restarted.resolve(ask("pdpp.acme.items")),
      );
      expect(after).toEqual(before);
      expect(gets).toBe(0);
      expect(restarted.importEstimator()!.snapshot().estimatedBytesPeak).toBe(
        0,
      );
    });

    it("import charges one part at a time and releases every charge", async () => {
      const owner = await testOwnerKey(masterKey(45));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: recordsOf(8_192),
        prefixes: prefixesFor(bitsFor(8_192)),
      });
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      const snap = service.importEstimator()!.snapshot();
      expect(snap.categories.importPart.acquisitions).toBe(64);
      expect(snap.categories.importPart.estimatedPeak).toBeLessThanOrEqual(
        2 * FIXTURE_PART_BYTES,
      );
      expect(snap.categories.importPart.thresholdExceedances).toBe(0);
      expect(snap.estimatedBytesCurrent).toBe(0);
    });
  });

  describe("ordinary-record budget vs the 8 MiB record limit", () => {
    it("a 200 KiB ASCII record is not counted oversize: its canonical UTF-8 size is under the threshold, though its UTF-16 memory charge is over it", async () => {
      const owner = await testOwnerKey(masterKey(50));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: [{ id: "medium", body: "x".repeat(200 * KiB) }],
      });
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      const decision = await service.resolve(ask("pdpp.acme.items"));
      const result = await drain(decision);
      expect(result.records).toBe(1);
      const snap =
        decision.kind === "view" ? decision.budget!.snapshot() : null;
      expect(snap!.oversizeRecordCount).toBe(0);
    });

    it.fails(
      "step 2 must not enforce budgets until the ordinary-record budget agrees with the 8 MiB record limit: a legal 1 MiB record is not counted as oversize or as an exceedance (red today: the 256 KiB budget counts it)",
      async () => {
        const owner = await testOwnerKey(masterKey(49));
        const f = new Fixture(owner);
        const ns = await owner.ns(CONNECTOR, "account-1");
        await f.activate(CONNECTOR, ns);
        await f.publish({
          connector: CONNECTOR,
          ns,
          stream: "items",
          generation: 1,
          records: [{ id: "big", body: "x".repeat(MiB) }],
        });
        const service = await f.service({ estimateReadMemory: true });
        await f.sync(service);
        const decision = await service.resolve(ask("pdpp.acme.items"));
        const result = await drain(decision);
        expect(result.records).toBe(1);
        const snap =
          decision.kind === "view" ? decision.budget!.snapshot() : null;
        expect(snap!.oversizeRecordCount).toBe(0);
        for (const [name, c] of Object.entries(snap!.categories)) {
          expect(c.thresholdExceedances, name).toBe(0);
        }
      },
    );
  });

  describe("cancel, error and repeat: every charge is released", () => {
    it("a body cancelled after its first chunk releases every charge", async () => {
      const owner = await testOwnerKey(masterKey(46));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: recordsOf(2_048),
        prefixes: prefixesFor(bitsFor(2_048)),
      });
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      const decision = await service.resolve(ask("pdpp.acme.items"));
      if (decision.kind !== "view") throw new Error(decision.kind);
      const reader = decision.body.getReader();
      await reader.read();
      await reader.cancel();
      expectQuiet(decision.budget!.snapshot());
    });

    it("a part that goes missing mid-read errors the body and releases every charge", async () => {
      const owner = await testOwnerKey(masterKey(47));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: recordsOf(2_048),
        prefixes: prefixesFor(bitsFor(2_048)),
      });
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      // Remove one imported part: the read reaches it after bytes were sent.
      const parts = [...f.files.files.keys()].filter((p) =>
        p.includes("/parts/"),
      );
      f.files.files.delete(parts[parts.length - 1]!);
      const decision = await service.resolve(ask("pdpp.acme.items"));
      if (decision.kind !== "view") throw new Error(decision.kind);
      await expect(new Response(decision.body).text()).rejects.toThrow();
      expectQuiet(decision.budget!.snapshot());
    });

    it("twenty sequential reads keep the same peak: nothing leaks across attempts", async () => {
      const owner = await testOwnerKey(masterKey(48));
      const f = new Fixture(owner);
      const ns = await owner.ns(CONNECTOR, "account-1");
      await f.activate(CONNECTOR, ns);
      await f.publish({
        connector: CONNECTOR,
        ns,
        stream: "items",
        generation: 1,
        records: recordsOf(2_048),
        prefixes: prefixesFor(bitsFor(2_048)),
      });
      const service = await f.service({ estimateReadMemory: true });
      await f.sync(service);
      const peaks: number[] = [];
      for (let attempt = 0; attempt < 20; attempt++) {
        const decision = await service.resolve(ask("pdpp.acme.items"));
        await drain(decision);
        const snap =
          decision.kind === "view" ? decision.budget!.snapshot() : null;
        expectQuiet(snap!);
        peaks.push(snap!.estimatedBytesPeak);
      }
      expect(peaks[19]!).toBeLessThanOrEqual(peaks[0]! + 64 * KiB);
    });
  });
});

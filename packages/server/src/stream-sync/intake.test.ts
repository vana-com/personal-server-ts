/**
 * Run intake (run-intake contract v2, rulings R17-R19 and R23): the real adapter over
 * the real writer, the production storage adapter against a local blob store
 * and the in-memory exclusive-version registry.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { StreamSyncWriter } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  RunIntakeError,
  createStreamSyncIntake,
  type BeginRequest,
  type IntakeDeclarations,
  type StreamSyncBlobs,
  type StreamSyncIntake,
  type StreamSyncRegistry,
  type StreamSyncWriterOptions,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  OWNER,
  createOracleEnv,
  artifactFor,
  finishedOutcome,
  fixedSeed,
  freshConnector,
  oldDelete,
  readStream,
  resolveTestArtifact,
  startLocalStorage,
  type OracleEnv,
} from "./oracle.test-utils.js";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";

const T0 = Date.UTC(2026, 10, 1);
const DECLARATIONS: Omit<IntakeDeclarations, "connector"> = {
  version: "1.2.0",
  streams: [
    { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
    { name: "events", semantics: "append_only", primaryKey: ["id"] },
    {
      name: "snapshot",
      semantics: "mutable_state",
      primaryKey: ["id"],
      incremental: false,
    },
    { name: "profile", semantics: "mutable_state", primaryKey: ["id"] },
    { name: "export", semantics: "mutable_state", primaryKey: ["id"] },
  ],
};

let storage: Awaited<ReturnType<typeof startLocalStorage>>;
let env: OracleEnv;
let device = 0;

beforeAll(async () => {
  storage = await startLocalStorage();
  env = await createOracleEnv({
    surface: "full",
    backend: "fake",
    storageUrl: storage.url,
  });
});
afterAll(async () => {
  await env.cleanup();
  await storage.close();
});

interface Host {
  readonly name: string;
  readonly writer: StreamSyncWriter;
  readonly intake: StreamSyncIntake;
}

async function host(
  extra: Partial<StreamSyncWriterOptions> & { files?: StreamFiles } = {},
  intakeOptions: Partial<Parameters<typeof createStreamSyncIntake>[0]> = {},
  name = `intake-${(device += 1)}`,
): Promise<Host> {
  const writer = await env.writer(name, extra);
  const intake = createStreamSyncIntake({
    writer,
    resolveArtifact: resolveTestArtifact,
    ...intakeOptions,
  });
  return { name, writer, intake };
}

const begin = (connector: string, extra: Partial<BeginRequest> = {}) => ({
  connector,
  artifactDigest: artifactFor(connector, DECLARATIONS),
  owner: { address: OWNER, leaseId: null },
  observedAt: T0,
  ...extra,
});

const row = (id: string) => ({ id, n: id });

async function fails(promise: Promise<unknown>): Promise<RunIntakeError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(RunIntakeError);
    return error as RunIntakeError;
  }
  throw new Error("expected a RunIntakeError");
}

type RunInput = {
  records: { stream: string; op?: string; data: unknown }[];
  covered: string[];
  candidate?: Record<string, string> | null;
  outcome?: "succeeded" | "partial" | "retry_pending";
  begin?: Partial<BeginRequest>;
};

/** Batch and end of a run whose begin the caller already issued. */
async function finish(h: Host, runId: string, input: RunInput) {
  const batch = await h.intake.batch(runId, {
    batch: 0,
    records: input.records,
  });
  const ended = await h.intake.end(runId, {
    outcome: input.outcome ?? "succeeded",
    coveredStreams: input.covered,
    checkpointCandidate: input.candidate ?? null,
    lastBatch: 0,
  });
  return { batch, ended };
}

/** A whole run: begin, one batch, end. */
async function run(h: Host, runId: string, connector: string, input: RunInput) {
  const started = await h.intake.begin(
    runId,
    begin(connector, input.begin ?? {}),
  );
  return { started, ...(await finish(h, runId, input)) };
}

async function publish(h: Host, runId: string) {
  await h.writer.cycle();
  const status = await h.writer.status();
  return { status, finished: finishedOutcome(status, runId) };
}

describe("run intake", { timeout: 30_000 }, () => {
  it("publishes a run and issues START from the saved checkpoint", async () => {
    const c = freshConnector("start");
    const h = await host();
    const first = await run(h, "r1", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: ["items"],
      candidate: { items: "c1" },
    });
    expect(first.started.start).toEqual({
      collection_mode: "full_refresh",
      state: null,
    });
    expect(first.started.status).toBe("collecting");
    expect(first.ended.result).toBe("queued");
    const { finished } = await publish(h, "r1");
    expect(finished?.outcome?.kind).toBe("checkpointed");

    const second = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    expect(second.start).toEqual({
      collection_mode: "incremental",
      state: { items: "c1" },
    });
    // R24: a full run's START carries no cursor, yet the stored one stays.
    await h.intake.abort("r2", "cancelled");
    const third = await h.intake.begin(
      "r3",
      begin(c, { wantFull: true, observedAt: T0 + 2 }),
    );
    expect(third.start).toEqual({
      collection_mode: "full_refresh",
      state: null,
    });
    await h.intake.abort("r3", "cancelled");

    // A writer-forced full run (needsFull) gets no state.
    const files = await env.files(h.name);
    const state = JSON.parse(
      new TextDecoder().decode((await files.read("state.json"))!),
    );
    state.needsFull = [{ connector: c, ns: "", stream: "items" }];
    await files.write(
      "state.json",
      new TextEncoder().encode(JSON.stringify(state)),
    );
    const forced = await h.intake.begin("r4", begin(c, { observedAt: T0 + 3 }));
    expect(forced.start).toEqual({
      collection_mode: "full_refresh",
      state: null,
    });
  });

  it("sends no cursor for a full_refresh stream; its incremental sibling keeps its cursor (R24)", async () => {
    const c = freshConnector("r24");
    const h = await host();
    await run(h, "r1", c, {
      records: [
        { stream: "items", data: row("a") },
        { stream: "snapshot", data: row("s") },
      ],
      covered: ["items", "snapshot"],
      candidate: { items: "i1", snapshot: "s1" },
    });
    await publish(h, "r1");
    const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    // Incremental run: `snapshot` is declared incremental:false.
    expect(next.start.collection_mode).toBe("incremental");
    expect(next.start.state).toEqual({ items: "i1" });
    expect(next.streams.map((s) => [s.name, s.mode])).toEqual(
      expect.arrayContaining([
        ["items", "incremental"],
        ["snapshot", "full_refresh"],
      ]),
    );
  });

  it("skips and counts deletes, never storing a stub row (R17)", async () => {
    const c = freshConnector("delete");
    const h = await host();
    const { batch } = await run(h, "r1", c, {
      records: [
        { stream: "items", data: row("keep") },
        { stream: "items", op: "delete", data: { id: "gone" } },
        { stream: "items", op: "delete", data: {} },
        { stream: "events", op: "delete", data: { id: "e1" } },
      ],
      covered: ["items", "events"],
    });
    expect(batch).toMatchObject({ accepted: 1, deletesSkipped: 3 });
    await publish(h, "r1");
    const items = await readStream(env.registry, env.blobs, c, "", "items");
    expect(items).not.toBeNull();
    expect([
      ...(items as { records: Map<string, unknown> }).records.keys(),
    ]).toEqual(["keep"]);
  });

  it("refuses a START that limits fields or resources (R17)", async () => {
    const h = await host();
    const c = freshConnector("restricted");
    const refused = await fails(
      h.intake.begin(
        "r1",
        begin(c, { streams: [{ name: "items", fields: ["id"] }] }),
      ),
    );
    expect(refused.code).toBe("restricted_scope_unsupported");
    expect(refused.status).toBe(422);
    expect(
      (
        await fails(
          h.intake.begin(
            "r2",
            begin(c, { streams: [{ name: "items", resources: ["x"] }] }),
          ),
        )
      ).code,
    ).toBe("restricted_scope_unsupported");
    // A time window counts as full: it is accepted.
    const ok = await h.intake.begin(
      "r3",
      begin(c, {
        streams: [{ name: "items", time_range: { since: "2026-01-01" } }],
      }),
    );
    expect(ok.status).toBe("collecting");
  });

  it("counts an incremental:false stream as full inside an incremental run (§3.0)", async () => {
    const c = freshConnector("streamfull");
    const writer = await env.writer(`sf-${(device += 1)}`);
    await writer.refreshControls();
    const shape = (incremental: boolean) => ({
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
      incremental,
    });
    // An incremental run (it names a checkpoint) onto an absent base: only the
    // stream that is read whole each run may publish a complete head.
    await writer.beginRun({
      runId: "r1",
      connector: c,
      userConnect: false,
      observedAt: T0,
      identity: "none",
      checkpointUsed: { ns: "", generation: 1 },
    });
    await writer.declareStream("r1", "snapshot", shape(false));
    await writer.declareStream("r1", "items", shape(true));
    await writer.append("r1", "snapshot", row("a"));
    await writer.append("r1", "items", row("a"));
    await writer.finishRun("r1", { checkpointCandidate: null });
    await writer.publishPending();
    const complete = async (stream: string) =>
      (
        (await readStream(env.registry, env.blobs, c, "", stream)) as {
          head: { complete: boolean };
        }
      ).head.complete;
    expect(await complete("snapshot")).toBe(true);
    expect(await complete("items")).toBe(false);
    // Only the stream that stays incomplete is marked for a full run.
    expect((await writer.status()).needsFull).toEqual([
      { connector: c, ns: "", stream: "items" },
    ]);
  });

  it("publishes covered streams only and keeps the others' head and cursor", async () => {
    const c = freshConnector("covered");
    const h = await host();
    await run(h, "r1", c, {
      records: [
        { stream: "items", data: row("a") },
        { stream: "events", data: row("e1") },
      ],
      covered: ["items", "events"],
      candidate: { items: "i1", events: "v1" },
    });
    await publish(h, "r1");
    const eventsBefore = await readStream(
      env.registry,
      env.blobs,
      c,
      "",
      "events",
    );

    // Run 2 emits events but covers only items.
    await run(h, "r2", c, {
      records: [
        { stream: "items", data: row("b") },
        { stream: "events", data: row("e2") },
      ],
      covered: ["items"],
      candidate: { items: "i2" },
      begin: { observedAt: T0 + 10 },
    });
    const { status } = await publish(h, "r2");
    const eventsAfter = await readStream(
      env.registry,
      env.blobs,
      c,
      "",
      "events",
    );
    expect(eventsAfter).toEqual(eventsBefore);
    // The candidate joins the earlier cursors of the same namespace.
    expect(status.checkpoints[c]?.value).toEqual({ items: "i2", events: "v1" });
    const finished = finishedOutcome(status, "r2");
    expect(Object.keys(finished!.streams)).toEqual(["items"]);

    // A stream no run ever covered gets no empty head.
    const c2 = freshConnector("uncovered");
    await run(h, "r3", c2, {
      records: [
        { stream: "items", data: row("a") },
        { stream: "events", data: row("e1") },
      ],
      covered: ["items"],
      candidate: { items: "i1" },
    });
    await publish(h, "r3");
    expect(
      await readStream(env.registry, env.blobs, c2, "", "events"),
    ).toBeNull();
    expect(
      await readStream(env.registry, env.blobs, c2, "", "items"),
    ).not.toBeNull();
  });

  it("retry_pending saves a cursor and publishes nothing; the next begin issues it", async () => {
    const c = freshConnector("retry");
    const h = await host();
    const { ended } = await run(h, "r1", c, {
      records: [],
      covered: [],
      candidate: { export: "job-token" },
      outcome: "retry_pending",
    });
    expect(ended.result).toBe("checkpoint_only");
    expect(
      await readStream(env.registry, env.blobs, c, "", "export"),
    ).toBeNull();
    const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    expect(next.start).toEqual({
      collection_mode: "incremental",
      state: { export: "job-token" },
    });
  });

  it("a retry_pending run that emitted records publishes them incomplete and keeps its cursors (R28)", async () => {
    const c = freshConnector("r28-records");
    const h = await host();
    const { ended } = await run(h, "r1", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: [],
      candidate: { items: "after-a", export: "tok" },
      outcome: "retry_pending",
    });
    expect(ended.result).toBe("queued");
    await publish(h, "r1");
    expect(await recordKeys(c, "items")).toEqual(["a"]);
    const view = await readStream(env.registry, env.blobs, c, "", "items");
    expect((view as { head: { complete: boolean } }).head.complete).toBe(false);
    const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    expect(next.start.state).toEqual({ items: "after-a", export: "tok" });
    await h.intake.abort("r2", "cancelled");
  });

  it("a retry_pending run with no records takes the cursor path and publishes nothing", async () => {
    const c = freshConnector("r19-cursor-path");
    const h = await host();
    const { ended } = await run(h, "r1", c, {
      records: [],
      covered: [],
      candidate: { items: "c1", export: "tok" },
      outcome: "retry_pending",
    });
    expect(ended.result).toBe("checkpoint_only");
    expect(
      await readStream(env.registry, env.blobs, c, "", "items"),
    ).toBeNull();
    const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    expect(next.start).toEqual({
      collection_mode: "incremental",
      state: { items: "c1", export: "tok" },
    });
    await h.intake.abort("r2", "cancelled");
  });

  it("a retry commit whose candidate omits a sibling keeps the sibling's cursor", async () => {
    const c = freshConnector("r28-sibling");
    const h = await host();
    await run(h, "r1", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: [],
      candidate: { items: "i1", export: "tok1" },
      outcome: "retry_pending",
    });
    await publish(h, "r1");
    await run(h, "r2", c, {
      records: [{ stream: "items", data: row("b") }],
      covered: [],
      candidate: { items: "i2" },
      outcome: "retry_pending",
      begin: { observedAt: T0 + 1 },
    });
    await publish(h, "r2");
    // r2's candidate omits export, so export keeps the cursor saved by r1.
    const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
    expect(next.start).toEqual({
      collection_mode: "incremental",
      state: { items: "i2", export: "tok1" },
    });
    await h.intake.abort("r3", "cancelled");
  });

  it("an oversized-only retry publishes and saves its candidate", async () => {
    const c = freshConnector("r28-oversized-only");
    const h = await host();
    const { ended } = await run(h, "r1", c, {
      records: [
        {
          stream: "items",
          data: { id: "big", n: "x".repeat(8 * 1024 * 1024) },
        },
      ],
      covered: [],
      candidate: { items: "c1" },
      outcome: "retry_pending",
    });
    expect(ended.result).toBe("queued");
    await publish(h, "r1");
    const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    expect(next.start).toEqual({
      collection_mode: "incremental",
      state: { items: "c1" },
    });
    await h.intake.abort("r2", "cancelled");
  });

  it("begin and end of one run finish while another run's publish waits on an upload", async () => {
    const c = freshConnector("queue");
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let blocked = false;
    const slow: StreamSyncBlobs = {
      ...env.blobs,
      async put(key, bytes) {
        blocked = true;
        await gate;
        return env.blobs.put(key, bytes);
      },
    };
    const h = await host({ blobs: slow });
    await run(h, "a", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: ["items"],
    });
    const publishing = h.writer.cycle();
    for (let i = 0; i < 200 && !blocked; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(blocked).toBe(true);
    const other = freshConnector("queue-b");
    const timeout = new Promise<string>((resolve) =>
      setTimeout(() => resolve("stuck"), 5000),
    );
    const second = run(h, "b", other, {
      records: [{ stream: "items", data: row("b") }],
      covered: ["items"],
    }).then(() => "done");
    expect(await Promise.race([second, timeout])).toBe("done");
    release();
    await publishing;
  });

  it("refuses a batch or end when the owner changed after begin (M5)", async () => {
    const c = freshConnector("owner");
    let binding = { owner: OWNER as string, keyCheck: "" };
    const h = await host({}, { currentBinding: async () => binding });
    binding = await h.writer.binding();
    const started = await h.intake.begin("r1", begin(c));
    expect(started.binding.keyCheck).toBe(binding.keyCheck);
    binding = { ...binding, keyCheck: "other-key" };
    expect(
      (await fails(h.intake.batch("r1", { batch: 0, records: [] }))).code,
    ).toBe("owner_mismatch");
    expect(
      (
        await fails(
          h.intake.end("r1", {
            outcome: "succeeded",
            coveredStreams: [],
            lastBatch: -1,
          }),
        )
      ).code,
    ).toBe("owner_mismatch");
    expect(
      (
        await fails(
          h.intake.begin("r9", {
            ...begin(c),
            owner: { address: "0x" + "11".repeat(20), leaseId: null },
          }),
        )
      ).code,
    ).toBe("owner_mismatch");
  });

  it("publishes nothing for a run whose owner changed before the publish (M5)", async () => {
    const c = freshConnector("owner-restart");
    const h = await host();
    await run(h, "r1", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: ["items"],
    });
    const other = "0x" + "22".repeat(20);
    const restarted = await env.writer(h.name, {
      ownerAddress: other as `0x${string}`,
    });
    await restarted.cycle();
    const done = finishedOutcome(await restarted.status(), "r1");
    expect(done?.outcome?.kind).toBe("failed");
    expect(
      await readStream(env.registry, env.blobs, c, "", "items"),
    ).toBeNull();
  });

  it("refuses a begin while the connection is being deleted (M5)", async () => {
    const h = await host(
      {},
      { deleting: (connector) => connector.startsWith("busy") },
    );
    expect((await fails(h.intake.begin("r1", begin("busy-one")))).code).toBe(
      "connection_busy",
    );
    expect(
      (await h.intake.begin("r2", begin(freshConnector("free")))).status,
    ).toBe("collecting");
  });

  it("answers lease_lost when the bound lease is no longer held (M5)", async () => {
    let held: string | null = "write-aaaa";
    const h = await host({}, { currentLease: () => held });
    const c = freshConnector("lease");
    await fails(
      h.intake.begin("r0", {
        ...begin(c),
        owner: { address: OWNER, leaseId: "write-zzzz" },
      }),
    ).then((e) => expect(e.code).toBe("lease_lost"));
    await h.intake.begin("r1", {
      ...begin(c),
      owner: { address: OWNER, leaseId: "write-aaaa" },
    });
    held = "write-bbbb";
    expect(
      (await fails(h.intake.batch("r1", { batch: 0, records: [] }))).code,
    ).toBe("lease_lost");
  });

  it("answers gone for a finished run, a replay after restart and a batch after abort", async () => {
    const c = freshConnector("gone");
    const h = await host();
    await run(h, "r1", c, {
      records: [{ stream: "items", data: row("a") }],
      covered: ["items"],
    });
    expect((await fails(h.intake.begin("r1", begin(c)))).code).toBe("gone");
    await publish(h, "r1");

    // A restarted process: new writer and adapter over the same files.
    const again = await host({}, {}, h.name);
    expect((await fails(again.intake.begin("r1", begin(c)))).code).toBe("gone");
    expect(
      (await fails(again.intake.batch("r1", { batch: 0, records: [] }))).code,
    ).toBe("gone");
    expect(
      (
        await fails(
          again.intake.end("r1", {
            outcome: "succeeded",
            coveredStreams: [],
            lastBatch: -1,
          }),
        )
      ).code,
    ).toBe("gone");

    // Abort: a late batch is refused and writes nothing.
    await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
    await h.intake.batch("r2", {
      batch: 0,
      records: [{ stream: "items", data: row("late") }],
    });
    await h.intake.abort("r2", "failed");
    expect(
      (
        await fails(
          h.intake.batch("r2", {
            batch: 1,
            records: [{ stream: "items", data: row("later") }],
          }),
        )
      ).code,
    ).toBe("gone");
    const files = await env.files(h.name);
    expect(
      (await files.list("runs")).filter((p) => p.includes("/r2/")),
    ).toEqual([]);
  });

  it("clamps observedAt to five minutes ahead of now (m1)", async () => {
    const c = freshConnector("clamp");
    const now = T0;
    const h = await host({ now: () => now });
    await h.intake.begin("r1", begin(c, { observedAt: now + 3_600_000 }));
    const files = await env.files(h.name);
    const entry = JSON.parse(
      new TextDecoder().decode((await files.read("runs/r1/entry.json"))!),
    );
    expect(entry.entry.observedAt).toBe(now + 300_000);
  });

  it("orders batches: a gap is refused, a replay is not appended twice", async () => {
    const c = freshConnector("gap");
    const h = await host();
    await h.intake.begin("r1", begin(c));
    const gap = await fails(
      h.intake.batch("r1", {
        batch: 1,
        records: [{ stream: "items", data: row("x") }],
      }),
    );
    expect(gap.code).toBe("batch_gap");
    expect(gap.nextBatch).toBe(0);
    const records = [{ stream: "items", data: row("a") }];
    expect(await h.intake.batch("r1", { batch: 0, records })).toMatchObject({
      applied: true,
      accepted: 1,
    });
    expect(await h.intake.batch("r1", { batch: 0, records })).toMatchObject({
      applied: false,
    });
    const mismatch = await fails(
      h.intake.end("r1", {
        outcome: "succeeded",
        coveredStreams: ["items"],
        lastBatch: 3,
      }),
    );
    expect(mismatch.code).toBe("batch_gap");
    await h.intake.end("r1", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: 0,
    });
    await publish(h, "r1");
    const items = await readStream(env.registry, env.blobs, c, "", "items");
    expect((items as { head: { recordCount: number } }).head.recordCount).toBe(
      1,
    );
  });

  it("binds the connector to the artifact: a producer cannot publish under another name (B)", async () => {
    const h = await host();
    const bound = freshConnector("bound");
    const other = freshConnector("other");
    const digest = artifactFor(bound, DECLARATIONS);
    const refused = await fails(
      h.intake.begin("r1", { ...begin(other), artifactDigest: digest }),
    );
    expect(refused.code).toBe("invalid_request");
    expect(refused.status).toBe(400);
    // The refusal leaves no run behind, and the bound name still begins.
    const started = await h.intake.begin("r1", {
      ...begin(bound),
      artifactDigest: digest,
    });
    expect(started.status).toBe("collecting");
  });

  it("refuses an unknown artifact, stream, key-less record and replayed begin body", async () => {
    const h = await host();
    const c = freshConnector("invalid");
    const unknown = await fails(
      h.intake.begin("r1", {
        ...begin(c),
        artifactDigest: "sha256:" + "00".repeat(32),
      }),
    );
    expect(unknown.code).toBe("unknown_artifact");
    expect(unknown.status).toBe(422);
    await h.intake.begin("r2", begin(c));
    expect(
      (
        await fails(
          h.intake.batch("r2", {
            batch: 0,
            records: [{ stream: "nope", data: {} }],
          }),
        )
      ).code,
    ).toBe("invalid_request");
    expect(
      (
        await fails(
          h.intake.batch("r2", {
            batch: 0,
            records: [{ stream: "items", data: { n: 1 } }],
          }),
        )
      ).code,
    ).toBe("invalid_request");
    expect(
      (
        await fails(
          h.intake.batch("r2", {
            batch: 0,
            records: [{ stream: "items", op: "merge", data: row("a") }],
          }),
        )
      ).code,
    ).toBe("invalid_request");
    // The same begin again returns the same answer; another body conflicts.
    const first = await h.intake.begin("r3", begin(c, { observedAt: T0 }));
    expect(await h.intake.begin("r3", begin(c, { observedAt: T0 }))).toBe(
      first,
    );
    expect(
      (await fails(h.intake.begin("r3", begin(c, { observedAt: T0 + 1 }))))
        .code,
    ).toBe("run_conflict");
  });

  it("marks a run will_discard when the registry is unreachable and calls a stuck connector", async () => {
    const c = freshConnector("down");
    const down: StreamSyncRegistry = {
      ...env.newRegistry(),
      async listControlRows() {
        throw new Error("registry unreachable");
      },
    };
    const h = await host({ registry: down });
    for (const id of ["d1", "d2", "d3"]) {
      const started = await h.intake.begin(id, begin(c, { observedAt: T0 }));
      expect(started.status).toBe("will_discard");
      expect(started.discardReason).toBe("registry_unreachable");
      expect(started.start.collection_mode).toBe("full_refresh");
      expect(
        await h.intake.batch(id, {
          batch: 0,
          records: [{ stream: "items", data: row("a") }],
        }),
      ).toMatchObject({ applied: true });
      const ended = await h.intake.end(id, {
        outcome: "succeeded",
        coveredStreams: ["items"],
        checkpointCandidate: { items: "c" },
        lastBatch: 0,
      });
      expect(ended.result).toBe("discarded");
    }
    expect(await h.writer.stuck(c)).toBe(true);
    expect((await h.intake.begin("d4", begin(c))).stuck).toBe(true);
    const status = await h.writer.status();
    expect(status.checkpoints[c]).toBeUndefined();
    expect(
      await readStream(env.registry, env.blobs, c, "", "items"),
    ).toBeNull();
  });
});

describe("run intake: no account derivation (R23)", { timeout: 30_000 }, () => {
  it("publishes every connector under the identity-less name", async () => {
    const c = freshConnector("acct-less");
    const h = await host();
    await run(h, "r1", c, {
      records: [
        { stream: "profile", data: { id: "acct-1" } },
        { stream: "items", data: row("a") },
      ],
      covered: ["profile", "items"],
      candidate: { items: "c1" },
    });
    const { finished } = await publish(h, "r1");
    expect(finished?.ns).toBe("");
    expect(finished?.outcome?.kind).toBe("checkpointed");
    // The scope is pdpp.<connector>~.<stream>: nothing is derived from a record.
    expect(
      await readStream(env.registry, env.blobs, c, "", "items"),
    ).not.toBeNull();
  });
});

/**
 * Retry progress: a retry_pending end publishes its records and keeps the
 * provenance of its cursor. Red until that build lands: the current writer
 * saves a retry_pending end as a checkpoint only, so the publication these
 * tests expect does not exist yet. Tests labelled guard, control or twin are
 * green today and must stay green.
 */

type SavedState = {
  checkpoints?: Record<string, unknown>;
  needsFull?: { connector: string; ns: string; stream: string }[];
  receipts?: Record<string, string>;
};

async function savedState(h: Host): Promise<SavedState> {
  const files = await env.files(h.name);
  const raw = await files.read("state.json");
  return raw ? JSON.parse(new TextDecoder().decode(raw)) : {};
}

/** The streams one connector still owes a full read, as saved on disk. */
async function debtOf(h: Host, connector: string): Promise<string[]> {
  return ((await savedState(h)).needsFull ?? [])
    .filter((entry) => entry.connector === connector)
    .map((entry) => entry.stream);
}

/** Sorted record keys of a committed head, or what readStream reports. */
async function recordKeys(connector: string, stream: string) {
  const view = await readStream(env.registry, env.blobs, connector, "", stream);
  if (view === null || view === "tombstoned") return view;
  return [...view.records.keys()].sort();
}

/** Saves a full-read debt for a stream, then reopens the writer on it. */
async function withNeedsFull(
  h: Host,
  connector: string,
  stream: string,
): Promise<Host> {
  const files = await env.files(h.name);
  const state = await savedState(h);
  state.needsFull = [{ connector, ns: "", stream }];
  await files.write(
    "state.json",
    new TextEncoder().encode(JSON.stringify(state)),
  );
  return host({}, {}, h.name);
}

type StreamFiles = Awaited<ReturnType<OracleEnv["files"]>>;

/**
 * Wraps a device's files port and records each appended entry. A finished
 * run removes its run directory, so the evidence is read from the append.
 */
function recordingFiles(
  inner: StreamFiles,
  appends: Map<string, string[]>,
): StreamFiles {
  return new Proxy(inner, {
    get(target, key) {
      if (key === "appendMany") {
        return async (
          entries: readonly { path: string; bytes: Uint8Array }[],
        ) => {
          for (const entry of entries) {
            appends.set(entry.path, [
              ...(appends.get(entry.path) ?? []),
              new TextDecoder().decode(entry.bytes),
            ]);
          }
          return target.appendMany(entries);
        };
      }
      const value = Reflect.get(target, key, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** The stream of each exclusion line the run appended. */
function exclusionStreams(appends: Map<string, string[]>, runId: string) {
  const text = (appends.get(`runs/${runId}/excluded.ndjson`) ?? []).join("");
  return text
    .trim()
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => (JSON.parse(line) as { stream?: string }).stream);
}

/** A record-bearing retry with a candidate; its head must commit the record. */
async function recordRetry(h: Host, connector: string) {
  await run(h, "r1", connector, {
    records: [{ stream: "items", data: row("a") }],
    covered: [],
    candidate: { items: "c1" },
    outcome: "retry_pending",
  });
  await publish(h, "r1");
  expect(await recordKeys(connector, "items")).toEqual(["a"]);
  await expectIncompleteHead(h, connector);
}

/** The committed items head is incomplete, and its items debt is durable. */
async function expectIncompleteHead(h: Host, connector: string) {
  const view = await readStream(
    env.registry,
    env.blobs,
    connector,
    "",
    "items",
  );
  expect(view).not.toBeNull();
  expect(view).not.toBe("tombstoned");
  expect((view as { head: { complete: boolean } }).head.complete).toBe(false);
  expect(await debtOf(h, connector)).toEqual(["items"]);
}

describe(
  "run intake: retry progress provenance (red until the retry build lands)",
  { timeout: 30_000 },
  () => {
    it("a head tombstone during an explicit full run makes the next ordinary begin full/null", async () => {
      const c = freshConnector("r28-m2");
      const h = await host();
      await run(h, "r1", c, {
        records: [],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      // An explicit full run issues no cursor and does not re-save the checkpoint.
      await h.intake.begin(
        "r2",
        begin(c, { wantFull: true, observedAt: T0 + 1 }),
      );
      await oldDelete(env, streamScope(c, "", "items"));
      await h.intake.batch("r2", {
        batch: 0,
        records: [{ stream: "items", data: row("b") }],
      });
      await h.intake.end("r2", {
        outcome: "succeeded",
        coveredStreams: ["items"],
        checkpointCandidate: null,
        lastBatch: 0,
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
      await h.intake.abort("r3", "cancelled");
    });

    // Control: green today and must stay green. Without a tombstone the
    // retry cursor survives an explicit full run.
    it("control: without a tombstone, an explicit full run keeps the retry cursor for the next begin", async () => {
      const c = freshConnector("r28-m2-twin");
      const h = await host();
      await run(h, "r1", c, {
        records: [],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      await run(h, "r2", c, {
        records: [{ stream: "items", data: row("b") }],
        covered: ["items"],
        candidate: null,
        begin: { wantFull: true, observedAt: T0 + 1 },
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await h.intake.abort("r3", "cancelled");
    });

    // Guard: green today, because no whole-read stream keeps a cursor past an
    // uncovered attempt. The build that adds retry provenance must keep it
    // green: once covered, the snapshot restarts full with no cursor.
    it("guard: a whole-read stream covered with a candidate cursor restarts full with no snapshot cursor", async () => {
      const c = freshConnector("r28-m6a-guard");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: [],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      await run(h, "r2", c, {
        records: [{ stream: "snapshot", data: row("t") }],
        covered: ["snapshot"],
        candidate: { items: "i2", snapshot: "s2" },
        outcome: "retry_pending",
        begin: { observedAt: T0 + 1 },
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.streams.find((s) => s.name === "snapshot")?.mode).toBe(
        "full_refresh",
      );
      expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
      await h.intake.abort("r3", "cancelled");
    });

    it("an uncovered whole-read stream resumes with its snapshot cursor, and covering it drops that cursor", async () => {
      const c = freshConnector("r28-m6a-trace");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: [],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      // Prerequisite: the uncovered attempt resumes incrementally with s1.
      const resumed = await h.intake.begin(
        "r2",
        begin(c, { observedAt: T0 + 1 }),
      );
      expect(resumed.start).toEqual({
        collection_mode: "incremental",
        state: { items: "i1", snapshot: "s1" },
      });
      await finish(h, "r2", {
        records: [{ stream: "snapshot", data: row("t") }],
        covered: ["snapshot"],
        candidate: { items: "i2", snapshot: "s2" },
        outcome: "retry_pending",
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.streams.find((s) => s.name === "snapshot")?.mode).toBe(
        "full_refresh",
      );
      expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
      // The items cursor from the same trace survives the covered attempt.
      expect(next.start.state).toEqual({ items: "i2" });
      await h.intake.abort("r3", "cancelled");
    });

    it("an uncovered sibling resumes from its cursor after a mixed retry end", async () => {
      const c = freshConnector("r28-m6a-items");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: ["snapshot"],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      expect(await recordKeys(c, "items")).toEqual(["a"]);
      // Durable: a reopened writer on the same home resumes from the same cursor.
      const reopened = await host({}, {}, h.name);
      const next = await reopened.intake.begin(
        "r2",
        begin(c, { observedAt: T0 + 1 }),
      );
      expect(next.start.state).toEqual({ items: "i1" });
      await reopened.intake.abort("r2", "cancelled");
    });

    // Guard: green today, for the same reason as the guard above.
    it("guard: a whole-read stream omitted from the saved candidate restarts full with no snapshot cursor", async () => {
      const c = freshConnector("r28-m6b-guard");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: [],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      await run(h, "r2", c, {
        records: [{ stream: "snapshot", data: row("t") }],
        covered: ["snapshot"],
        candidate: { items: "i2" },
        outcome: "retry_pending",
        begin: { observedAt: T0 + 1 },
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.streams.find((s) => s.name === "snapshot")?.mode).toBe(
        "full_refresh",
      );
      expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
      await h.intake.abort("r3", "cancelled");
    });

    it("an uncovered whole-read stream resumes with its snapshot cursor; covering it without a snapshot candidate keeps the items cursor", async () => {
      const c = freshConnector("r28-m6b-trace");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: [],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      // Prerequisite: the uncovered attempt resumes incrementally with s1.
      const resumed = await h.intake.begin(
        "r2",
        begin(c, { observedAt: T0 + 1 }),
      );
      expect(resumed.start).toEqual({
        collection_mode: "incremental",
        state: { items: "i1", snapshot: "s1" },
      });
      await finish(h, "r2", {
        records: [{ stream: "snapshot", data: row("t") }],
        covered: ["snapshot"],
        candidate: { items: "i2" },
        outcome: "retry_pending",
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.streams.find((s) => s.name === "snapshot")?.mode).toBe(
        "full_refresh",
      );
      expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
      expect(next.start.state).toEqual({ items: "i2" });
      await h.intake.abort("r3", "cancelled");
    });

    it("an uncovered sibling keeps its cursor when a later retry omits a covered whole-read stream", async () => {
      const c = freshConnector("r28-m6b-items");
      const h = await host();
      await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          { stream: "snapshot", data: row("s") },
        ],
        covered: [],
        candidate: { items: "i1", snapshot: "s1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      await run(h, "r2", c, {
        records: [
          { stream: "items", data: row("b") },
          { stream: "snapshot", data: row("t") },
        ],
        covered: ["snapshot"],
        candidate: { items: "i2" },
        outcome: "retry_pending",
        begin: { observedAt: T0 + 1 },
      });
      await publish(h, "r2");
      // Committed head holds both retries' records, and the head is durable.
      expect(await recordKeys(c, "items")).toEqual(["a", "b"]);
      const reopened = await host({}, {}, h.name);
      const next = await reopened.intake.begin(
        "r3",
        begin(c, { observedAt: T0 + 2 }),
      );
      expect(next.start.state).toEqual({ items: "i2" });
      await reopened.intake.abort("r3", "cancelled");
    });

    it("guard: a retry leaves a seeded stream's receipt retryable, and a later eligible run incorporates its seed rows", async () => {
      const c = freshConnector("r28-m1");
      const h = await host({
        seed: fixedSeed("desktop-install", {
          items: [row("seed-i")],
          events: [{ id: "seed-e", n: "seed" }],
        }),
      });
      await run(h, "r1", c, {
        records: [{ stream: "items", data: row("a") }],
        covered: [],
        candidate: { items: "i1" },
        outcome: "retry_pending",
      });
      const { status } = await publish(h, "r1");
      // The seed-only stream gets no head, and its receipt is not consumed.
      expect(
        await readStream(env.registry, env.blobs, c, "", "events"),
      ).toBeNull();
      expect(status.receipts[`desktop-install|${c}||events`]).toBeUndefined();
      // A later eligible run publishes events, and the seed rows come with it.
      await run(h, "r2", c, {
        records: [{ stream: "events", data: row("e1") }],
        covered: ["events"],
        candidate: null,
        begin: { observedAt: T0 + 1 },
      });
      const { finished } = await publish(h, "r2");
      expect(finished?.outcome?.kind).toBe("checkpointed");
      expect(await recordKeys(c, "events")).toEqual(["e1", "seed-e"]);
    });

    it("a record-bearing retry's head is tombstoned before the next begin: the next begin is full/null", async () => {
      const c = freshConnector("r28-m3-pre");
      const h = await host();
      await recordRetry(h, c);
      await oldDelete(env, streamScope(c, "", "items"));
      const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
      await h.intake.abort("r2", "cancelled");
    });

    it("a record-bearing retry's head is tombstoned after begin and before the retry save: the next begin is full/null", async () => {
      const c = freshConnector("r28-m3-mid");
      const h = await host();
      await recordRetry(h, c);
      const held = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(held.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await oldDelete(env, streamScope(c, "", "items"));
      await finish(h, "r2", {
        records: [{ stream: "items", data: row("b") }],
        covered: [],
        candidate: { items: "c2" },
        outcome: "retry_pending",
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
      await h.intake.abort("r3", "cancelled");
    });

    // Twin: the same record-bearing retry and continuation with no tombstone.
    it("twin: without a tombstone, a record-bearing retry continuation resumes incrementally from c2", async () => {
      const c = freshConnector("r28-m3-twin");
      const h = await host();
      await recordRetry(h, c);
      const held = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(held.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await finish(h, "r2", {
        records: [{ stream: "items", data: row("b") }],
        covered: [],
        candidate: { items: "c2" },
        outcome: "retry_pending",
      });
      await publish(h, "r2");
      await expectIncompleteHead(h, c);
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c2" },
      });
      await h.intake.abort("r3", "cancelled");
    });

    it("a retry cursor saved after a head tombstone lands does not renew the continuation", async () => {
      const c = freshConnector("r28-m3");
      const h = await host();
      await run(h, "r1", c, {
        records: [],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
      });
      await publish(h, "r1");
      // r2 holds the cursor c1 from its begin.
      const held = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(held.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await oldDelete(env, streamScope(c, "", "items"));
      await finish(h, "r2", {
        records: [{ stream: "items", data: row("b") }],
        covered: [],
        candidate: { items: "c2" },
        outcome: "retry_pending",
      });
      await publish(h, "r2");
      const next = await h.intake.begin("r3", begin(c, { observedAt: T0 + 2 }));
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
      await h.intake.abort("r3", "cancelled");
    });

    it("an oversized-only retry follows the ordinary exclusion path and is not an all-empty retry", async () => {
      const c = freshConnector("r28-m4-only");
      const name = `ev-${c}`;
      const appends = new Map<string, string[]>();
      const h = await host(
        { files: recordingFiles(await env.files(name), appends) },
        {},
        name,
      );
      const { batch, ended } = await run(h, "r1", c, {
        records: [
          {
            stream: "items",
            data: { id: "big", n: "x".repeat(8 * 1024 * 1024) },
          },
        ],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
      });
      expect(batch).toMatchObject({ accepted: 0, tooLarge: 1 });
      expect(ended.result).toBe("queued");
      // The candidate is not saved before the run publishes.
      expect(JSON.stringify(await savedState(h))).not.toContain('"c1"');
      await publish(h, "r1");
      // The ordinary path appends the exclusion evidence for the excluded row.
      expect(exclusionStreams(appends, "r1")).toContain("items");
      const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(next.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await h.intake.abort("r2", "cancelled");
    });

    it("an oversized upsert beside an accepted one is not an all-empty retry", async () => {
      const c = freshConnector("r28-m4");
      const name = `ev-${c}`;
      const appends = new Map<string, string[]>();
      const h = await host(
        { files: recordingFiles(await env.files(name), appends) },
        {},
        name,
      );
      const { batch, ended } = await run(h, "r1", c, {
        records: [
          { stream: "items", data: row("a") },
          {
            stream: "items",
            data: { id: "big", n: "x".repeat(8 * 1024 * 1024) },
          },
        ],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
      });
      expect(batch).toMatchObject({ accepted: 1, tooLarge: 1 });
      expect(ended.result).toBe("queued");
      await publish(h, "r1");
      expect(await recordKeys(c, "items")).toEqual(["a"]);
      // The ordinary path appends the exclusion evidence for the excluded row.
      expect(exclusionStreams(appends, "r1")).toContain("items");
      const next = await h.intake.begin("r2", begin(c, { observedAt: T0 + 1 }));
      expect(next.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await h.intake.abort("r2", "cancelled");
    });

    it("a covered incremental tail with no token keeps the items debt until a covered full commit clears it", async () => {
      const c = freshConnector("r28-m5");
      let h = await host();
      await run(h, "r0", c, {
        records: [{ stream: "items", data: row("z") }],
        covered: ["items"],
        candidate: { items: "c0" },
      });
      await publish(h, "r0");
      h = await withNeedsFull(h, c, "items");
      await run(h, "r1", c, {
        records: [],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
        begin: { observedAt: T0 + 1 },
      });
      await publish(h, "r1");
      // The retry continuation resumes incrementally despite the debt.
      const cont = await h.intake.begin("r2", begin(c, { observedAt: T0 + 2 }));
      expect(cont.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await finish(h, "r2", {
        records: [{ stream: "items", data: row("b") }],
        covered: ["items"],
        candidate: null,
      });
      await publish(h, "r2");
      // A covered tail with no token is not a full read: the debt stays durable.
      expect(await debtOf(h, c)).toEqual(["items"]);
      const after = await h.intake.begin(
        "r3",
        begin(c, { observedAt: T0 + 3 }),
      );
      expect(after.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
      await finish(h, "r3", {
        records: [{ stream: "items", data: row("c") }],
        covered: ["items"],
        candidate: { items: "c3" },
      });
      await publish(h, "r3");
      // Only the covered, actually-full commit retires the debt.
      expect(await debtOf(h, c)).toEqual([]);
      const repaired = await h.intake.begin(
        "r4",
        begin(c, { observedAt: T0 + 4 }),
      );
      expect(repaired.start).toEqual({
        collection_mode: "incremental",
        state: { items: "c3" },
      });
      await h.intake.abort("r4", "cancelled");
    });

    it("companion: another stream's valid checkpoint does not mask the items debt", async () => {
      const c = freshConnector("r28-m5-companion");
      let h = await host();
      await run(h, "r0", c, {
        records: [
          { stream: "items", data: row("z") },
          { stream: "events", data: row("x") },
        ],
        covered: ["items", "events"],
        candidate: { items: "c0", events: "e0" },
      });
      await publish(h, "r0");
      h = await withNeedsFull(h, c, "items");
      await run(h, "r1", c, {
        records: [],
        covered: [],
        candidate: { items: "c1" },
        outcome: "retry_pending",
        begin: { observedAt: T0 + 1 },
      });
      await publish(h, "r1");
      const cont = await h.intake.begin("r2", begin(c, { observedAt: T0 + 2 }));
      expect(cont.start).toMatchObject({
        collection_mode: "incremental",
        state: { items: "c1" },
      });
      await finish(h, "r2", {
        records: [{ stream: "items", data: row("b") }],
        covered: ["items"],
        candidate: null,
      });
      await publish(h, "r2");
      expect(await debtOf(h, c)).toEqual(["items"]);
      const after = await h.intake.begin(
        "r3",
        begin(c, { observedAt: T0 + 3 }),
      );
      expect(after.start.collection_mode).toBe("full_refresh");
      await finish(h, "r3", {
        records: [{ stream: "items", data: row("c") }],
        covered: ["items"],
        candidate: { items: "c3" },
      });
      await publish(h, "r3");
      expect(await debtOf(h, c)).toEqual([]);
      const repaired = await h.intake.begin(
        "r4",
        begin(c, { observedAt: T0 + 4 }),
      );
      expect(repaired.start.collection_mode).toBe("incremental");
      expect(repaired.start.state).toMatchObject({ items: "c3" });
      await h.intake.abort("r4", "cancelled");
    });
  },
);

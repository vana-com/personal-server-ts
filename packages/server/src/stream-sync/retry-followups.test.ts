/**
 * Retry follow-ups for PS #566 (dot recheck of ae6734d9): a completed retry
 * continuation is never reissued after an artifact change, a zero-upsert
 * covered retry follows RetryEmpty, and an exclusion count survives a
 * restart. Helpers mirror intake.test.ts; that file is not edited.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { StreamSyncWriter } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createStreamSyncIntake,
  type BeginRequest,
  type IntakeDeclarations,
  type StreamSyncIntake,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  OWNER,
  artifactFor,
  createOracleEnv,
  finishedOutcome,
  freshConnector,
  readStream,
  resolveTestArtifact,
  startLocalStorage,
  type OracleEnv,
} from "./oracle.test-utils.js";

const T0 = Date.UTC(2026, 10, 1);
const DECLARATIONS: Omit<IntakeDeclarations, "connector"> = {
  version: "1.2.0",
  streams: [
    { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
    {
      name: "snapshot",
      semantics: "mutable_state",
      primaryKey: ["id"],
      incremental: false,
    },
  ],
};
/** The same stream, now incremental, from a newer artifact version. */
const CHANGED: Omit<IntakeDeclarations, "connector"> = {
  version: "1.3.0",
  streams: [
    { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
    { name: "snapshot", semantics: "mutable_state", primaryKey: ["id"] },
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

async function host(name = `followup-${(device += 1)}`): Promise<Host> {
  const writer = await env.writer(name);
  const intake = createStreamSyncIntake({
    writer,
    resolveArtifact: resolveTestArtifact,
  });
  return { name, writer, intake };
}

const begin = (
  connector: string,
  extra: Partial<BeginRequest> = {},
  declarations = DECLARATIONS,
) => ({
  connector,
  artifactDigest: artifactFor(connector, declarations),
  owner: { address: OWNER, leaseId: null },
  observedAt: T0,
  ...extra,
});

const row = (id: string) => ({ id, n: id });

type RunInput = {
  records: { stream: string; data: unknown }[];
  covered: string[];
  candidate?: Record<string, string> | null;
  outcome?: "succeeded" | "retry_pending";
  declarations?: Omit<IntakeDeclarations, "connector">;
};

async function run(h: Host, runId: string, connector: string, input: RunInput) {
  const started = await h.intake.begin(
    runId,
    begin(connector, {}, input.declarations ?? DECLARATIONS),
  );
  await h.intake.batch(runId, { batch: 0, records: input.records });
  const ended = await h.intake.end(runId, {
    outcome: input.outcome ?? "succeeded",
    coveredStreams: input.covered,
    checkpointCandidate: input.candidate ?? null,
    lastBatch: 0,
  });
  return { started, ended };
}

async function publish(h: Host, runId: string) {
  await h.writer.cycle();
  return finishedOutcome(await h.writer.status(), runId);
}

/**
 * Run 1 leaves snapshot mid-attempt with token "s-tok" (a retry continuation);
 * run 2 issues it, emits a snapshot row and covers snapshot. Returns the host.
 */
async function snapshotCompleted(
  connector: string,
  run2Candidate: Record<string, string> | null,
) {
  const h = await host();
  await run(h, "r1", connector, {
    records: [{ stream: "items", data: row("a") }],
    covered: [],
    candidate: { items: "i1", snapshot: "s-tok" },
    outcome: "retry_pending",
  });
  await publish(h, "r1");
  const issued = await h.intake.begin(
    "r2",
    begin(connector, { observedAt: T0 + 1 }),
  );
  expect(issued.start.state).toEqual({ items: "i1", snapshot: "s-tok" });
  await h.intake.batch("r2", {
    batch: 0,
    records: [{ stream: "snapshot", data: row("b") }],
  });
  await h.intake.end("r2", {
    outcome: "retry_pending",
    coveredStreams: ["snapshot"],
    checkpointCandidate: run2Candidate,
    lastBatch: 0,
  });
  await publish(h, "r2");
  return h;
}

describe("retry follow-ups", { timeout: 30_000 }, () => {
  it("a completed snapshot continuation is not reissued after the artifact makes it incremental (empty candidate)", async () => {
    const c = freshConnector("f-m7-changed-empty");
    const h = await snapshotCompleted(c, null);
    // r2 was published inside snapshotCompleted.
    const next = await h.intake.begin(
      "r3",
      begin(c, { observedAt: T0 + 2 }, CHANGED),
    );
    expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
    await h.intake.abort("r3", "cancelled");
  });

  it("a completed snapshot continuation is not reissued after the artifact makes it incremental (omitted candidate)", async () => {
    const c = freshConnector("f-m7-changed-omitted");
    const h = await snapshotCompleted(c, { items: "i2" });
    // r2 was published inside snapshotCompleted.
    const next = await h.intake.begin(
      "r3",
      begin(c, { observedAt: T0 + 2 }, CHANGED),
    );
    expect(next.start.state ?? {}).not.toHaveProperty("snapshot");
    await h.intake.abort("r3", "cancelled");
  });

  it("RetryEmpty: a zero-upsert covered retry writes no head, keeps the old token, and a later success retires it", async () => {
    const c = freshConnector("f-retry-empty");
    const h = await host();
    await run(h, "r1", c, {
      records: [],
      covered: [],
      candidate: { snapshot: "t1" },
      outcome: "retry_pending",
    });
    await publish(h, "r1");
    // Zero upserts with coverage: checkpoint-only, nothing published.
    const ended = await run(h, "r2", c, {
      records: [],
      covered: ["snapshot"],
      candidate: null,
      outcome: "retry_pending",
    });
    expect(ended.ended.result).toBe("checkpoint_only");
    await publish(h, "r2");
    expect(
      await readStream(env.registry, env.blobs, c, "", "snapshot"),
    ).toBeNull();
    const resumed = await h.intake.begin(
      "r3",
      begin(c, { observedAt: T0 + 2 }),
    );
    expect(resumed.start.state).toEqual({ snapshot: "t1" });
    await h.intake.abort("r3", "cancelled");
    // A later succeeded run covers and emits snapshot: the continuation ends.
    await run(h, "r4", c, {
      records: [{ stream: "snapshot", data: row("b") }],
      covered: ["snapshot"],
      candidate: null,
      outcome: "succeeded",
    });
    await publish(h, "r4");
    const after = await h.intake.begin("r5", begin(c, { observedAt: T0 + 3 }));
    expect(after.start.state ?? {}).not.toHaveProperty("snapshot");
    await h.intake.abort("r5", "cancelled");
  });

  it("an oversized-only retry's exclusion count is in its durable result and survives a restart", async () => {
    const c = freshConnector("f-oversize-durable");
    const h = await host("f-oversize-durable-device");
    await run(h, "r1", c, {
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
    const finished = await publish(h, "r1");
    expect(finished?.streams.items?.recordTooLarge).toBe(1);
    const restarted = await env.writer("f-oversize-durable-device");
    const after = finishedOutcome(await restarted.status(), "r1");
    expect(after?.streams.items?.recordTooLarge).toBe(1);
  });
});

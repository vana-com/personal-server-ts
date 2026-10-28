/**
 * Contract suite, section C: custody and crash-boundary scenarios (cases 35-46).
 *
 * Every scenario here runs as an exhaustive crash matrix. A recording run
 * enumerates every durable mutation, outermost commit and network effect of the
 * window under test. Then, for each index, the process is lost at that exact
 * point, the same SQLite file is reopened, raw durable state and public reads are
 * checked BEFORE any resume, and two resumes are compared with the no-crash
 * reference.
 *
 * Every index starts from the same pre-window state. The devices run once up to
 * the point where the window opens; each index puts back each device's own file,
 * the in-memory network and the clock (`checkpoint`). A device never receives
 * another device's file. The restore is proven equal to a fresh build in
 * pdpp-replica-contract.custody-restore.test.ts.
 *
 * Tiers: the pull-request run walks the indexes chosen by `pullRequestTier`
 * from the recorded trace. The nightly run walks every index.
 * Full matrix, one command: npm run test:replica-crash-full
 *
 * Fields that do not exist on today's schema (outcome, reason, dependency,
 * integrity epoch) are read through narrow typed accessors, so each case fails at
 * its own assertion and not with a file-level error.
 */
import Database from "better-sqlite3";
import type * as Crypto from "node:crypto";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  replicaFragmentKey,
  replicaScope,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import {
  CrashController,
  appendBinding,
  at,
  binding,
  cleanupHarness,
  clock,
  credential,
  envelope,
  network,
  owner,
  sourceId,
  transportDevice,
  transportInvariantViolations,
  workRecords,
  checkpoint,
  pullRequestTier,
  slotKey,
  type Network,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

// The crash matrix creates hundreds of tiny SQLite files, one per trace index.
// Their fsync cost dominates on a disk-backed directory; keep them on tmpfs.
// (Only kilobytes per file: this is not a build tree.)
process.env.TMPDIR = "/tmp";

/**
 * Off by default. The restore-equivalence test turns it on so two builds draw
 * the same ids and keys and can be compared byte for byte.
 */
const det = vi.hoisted(() => ({ on: false, count: 0 }));
vi.mock("node:crypto", async (original) => {
  const real = await original<typeof Crypto>();
  return {
    ...real,
    randomUUID: () =>
      det.on
        ? `00000000-0000-4000-8000-${(det.count++).toString(16).padStart(12, "0")}`
        : real.randomUUID(),
    randomBytes: (size: number) =>
      det.on ? Buffer.alloc(size, det.count++ & 0xff) : real.randomBytes(size),
  };
});

afterEach(cleanupHarness);

// ------------------------------------------------------------------ helpers

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
/** Await a promise that may reject because the process "died" or a phase failed. */
async function settle(promise: Promise<unknown>) {
  try {
    await promise;
  } catch {
    /* A crashed or failing cycle may reject. Durable state is the oracle. */
  }
}
/** CrashController.disarm() leaves `dead` set; a restarted process is alive. */
function revive(crash: CrashController) {
  crash.arm();
  crash.disarm();
}
const count = (db: Database.Database, sql: string, ...args: unknown[]) =>
  (db.prepare(sql).get(...args) as { n: number }).n;
const sha = (bytes: Uint8Array | undefined) =>
  bytes ? createHash("sha256").update(bytes).digest("hex") : undefined;

/** Resume: clear injected faults, then several cycles with clock advances. */
async function cycleAll(devices: TransportDevice[], n = 6, ms = 10_000) {
  for (let i = 0; i < n; i++) {
    clock.advance(ms);
    for (const d of devices) await settle(d.cycle());
  }
}

interface OutboxRow {
  kind: "fragment" | "manifest";
  batch: string;
  encrypted: string;
  plaintext: string;
  dataHash: string;
  metadataHash: string;
  version?: number;
  state: string;
}
/**
 * Every outbound object of the device, by storage key: content-addressed
 * fragments and the one manifest of each batch at its slot.
 */
function outboxSnapshot(db: Database.Database): Record<string, OutboxRow> {
  const writer = (
    db.prepare("SELECT writer FROM pdpp_transport_state WHERE id=1").get() as
      { writer: string } | undefined
  )?.writer;
  const fragments = db
    .prepare(
      "SELECT batch,digest,hex(encrypted) AS e,state FROM pdpp_transport_fragments_out ORDER BY batch,position",
    )
    .all() as Record<string, string>[];
  const manifests = db
    .prepare(
      "SELECT scope,version,batch,hex(encrypted) AS e,hex(plaintext) AS p,data_hash,metadata_hash,state FROM pdpp_transport_manifests_out ORDER BY version",
    )
    .all() as Record<string, string>[];
  return Object.fromEntries([
    ...fragments.map((r) => [
      replicaFragmentKey(replicaScope(writer!), r.digest!),
      {
        kind: "fragment" as const,
        batch: r.batch!,
        encrypted: r.e!.toLowerCase(),
        plaintext: "",
        dataHash: r.digest!,
        metadataHash: "",
        state: r.state!,
      },
    ]),
    ...manifests.map((r) => [
      slotKey(r.scope!, Number(r.version)),
      {
        kind: "manifest" as const,
        batch: r.batch!,
        encrypted: r.e!.toLowerCase(),
        plaintext: r.p!.toLowerCase(),
        dataHash: r.data_hash!,
        metadataHash: r.metadata_hash!,
        version: Number(r.version),
        state: r.state!,
      },
    ]),
  ]);
}
/** A fragment is done once stored; a manifest once its registration is final. */
const outboundDone = (r: OutboxRow) =>
  r.state === (r.kind === "manifest" ? "published" : "stored");
/** Received manifests and fragments the device holds, by work id and storage key. */
function retainedObjects(db: Database.Database) {
  const manifests = db
    .prepare(
      "SELECT slot FROM pdpp_transport_manifests_in WHERE manifest_json IS NOT NULL",
    )
    .all() as { slot: string }[];
  const fragments = db
    .prepare(
      "SELECT f.slot,f.position,f.digest,m.scope FROM pdpp_transport_fragments_in f JOIN pdpp_transport_manifests_in m USING(slot) WHERE f.fragment_json IS NOT NULL",
    )
    .all() as {
    slot: string;
    position: number;
    digest: string;
    scope: string;
  }[];
  return [
    ...manifests.map((r) => ({ id: r.slot, key: r.slot })),
    ...fragments.map((r) => ({
      id: `${r.slot}#${r.position}`,
      key: replicaFragmentKey(r.scope, r.digest),
    })),
  ];
}
const stableOutbox = (rows: Record<string, OutboxRow>) =>
  Object.fromEntries(
    Object.entries(rows).map(([scope, r]) => [
      scope,
      { ...r, state: undefined },
    ]),
  );
function batchSnapshot(db: Database.Database) {
  return db
    .prepare(
      "SELECT batch,sequence,digest,prepared FROM pdpp_transport_batches ORDER BY sequence",
    )
    .all() as {
    batch: string;
    sequence: number;
    digest: string;
    prepared: number;
  }[];
}
const registrationsPerScope = (net: Network) => {
  const per = new Map<string, number>();
  for (const s of net.calls.registrations) per.set(s, (per.get(s) ?? 0) + 1);
  return per;
};
const putsPerScope = (net: Network) => {
  const per = new Map<string, number>();
  for (const s of net.calls.puts) per.set(s, (per.get(s) ?? 0) + 1);
  return per;
};
const publicList = (d: TransportDevice) =>
  d.store
    .listRecords("messages", {
      instanceIds: [d.instance],
      limit: 100,
      order: "asc",
    })
    .data.map((r) => [r.recordKey, r.data]);

// -------------------------------------------------------------- crash matrix

/** "[category] message": the category lets the report separate causes. */
type Violation = string;
interface Frame {
  index: number;
  label: string;
  before: unknown;
  final: unknown;
}
interface Scenario {
  crash: CrashController;
  restart(): void;
  invariants(): Violation[];
  /** The armed window under test. May reject (crash or injected failure). */
  run(): Promise<void>;
  /** One resume pass: clear faults, advance the clock, cycle. */
  resume(): Promise<void>;
  /** Everything an authorized reader can see right now. */
  reads(): unknown;
  /** Convergence digest: no random identifiers. */
  digest(): unknown;
  /**
   * A read between the pre-step and final values that is still a committed
   * state, such as a batch boundary when one window imports several batches.
   */
  intermediate?(read: unknown, frame: Frame): boolean;
  /** Contract assertions on the no-crash reference run (once). */
  checkReference?(frame: Frame): Violation[];
  /** Durable-state checks right after process loss, before any resume. */
  checkCrashed?(frame: Frame): Violation[];
  /** Checks after two resumes. */
  checkResumed?(frame: Frame): Violation[];
}
/** A scenario whose devices have run up to the point where the window opens. */
interface World {
  crash: CrashController;
  net: Network;
  /** Every device of the scenario, for inspection. */
  devices: TransportDevice[];
  /** The devices `rewind` restores, and so reopens: those the window runs on. */
  windowDevices: TransportDevice[];
  /** Put every device, the network and the clock back to the pre-window state. */
  rewind(): void;
  /** Fresh check state over the same devices. Call after `rewind`. */
  scenario(): Scenario;
}
interface MatrixReport {
  name: string;
  points: number;
  failedIndexes: number;
  categories: Record<string, number>;
  failures: string[];
  summary: string;
}

function safely<T>(
  category: string,
  fn: () => T,
): { value?: T; violation?: Violation } {
  try {
    return { value: fn() };
  } catch (error) {
    return {
      violation: `[${category}] ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
const categoryOf = (v: Violation) => /^\[([^\]]+)\]/.exec(v)?.[1] ?? "state";

/** Nightly: REPLICA_ORACLE_NIGHTLY=1 (the replica oracle's switch) walks every index, by both methods. */
const everyIndex = process.env.REPLICA_ORACLE_NIGHTLY === "1";
/** Pull-request tier: seconds. Nightly: every index twice (restore, then warm). */
const matrixLimit = everyIndex ? 1_800_000 : 60_000;

interface MatrixOptions {
  /**
   * Trace indexes that may be missing from a run, with the reason. Any other
   * index the recording run saw but a crash run did not reach fails the test.
   */
  expectedUnreached?: { indexes: number[]; reason: string };
}

/**
 * - restore: the devices run once up to the window; each index puts them back
 *   and reopens them. Used by the pull-request tier and by the nightly run.
 * - warm: each index builds the devices from scratch and runs the window on the
 *   process that built them, with no reopen, as the matrix did before restore
 *   existed. It covers the warm-worker paths a reopened process skips (e.g. the
 *   dependency-wake UPDATE that a warm process with an unchanged fingerprint
 *   does not repeat). Nightly only.
 */
type Method = "restore" | "warm";

/** Pull-request tier: a derived subset by restore. Nightly: every index by restore, then by warm. */
async function crashMatrix(
  name: string,
  prepare: () => Promise<World>,
  options: MatrixOptions = {},
): Promise<MatrixReport> {
  const restored = await runMatrix(name, prepare, "restore", options);
  if (!everyIndex) return restored;
  const warm = await runMatrix(name, prepare, "warm", options);
  const categories = { ...restored.categories };
  for (const [k, n] of Object.entries(warm.categories))
    categories[k] = (categories[k] ?? 0) + n;
  return {
    name,
    points: Math.min(restored.points, warm.points),
    failedIndexes: restored.failedIndexes + warm.failedIndexes,
    categories,
    failures: [...restored.failures, ...warm.failures].slice(0, 8),
    summary: `${restored.summary}\n${warm.summary}`,
  };
}

async function runMatrix(
  name: string,
  prepare: () => Promise<World>,
  method: Method,
  options: MatrixOptions,
): Promise<MatrixReport> {
  // Seeded randomness: ids and keys come from a counter that restarts at the
  // same value for every run, so the trace, and the tier chosen from it, are
  // the same on every run.
  const wasOn = det.on;
  det.on = true;
  try {
    return await runSeededMatrix(name, prepare, method, options);
  } finally {
    det.on = wasOn;
  }
}

async function runSeededMatrix(
  name: string,
  prepare: () => Promise<World>,
  method: Method,
  options: MatrixOptions,
): Promise<MatrixReport> {
  const all = everyIndex;
  let world: World | undefined;
  let start = 0;
  det.count = 0;
  if (method === "restore") {
    world = await prepare();
    start = det.count;
  }
  /** A scenario at the start of the window. */
  const begin = async (): Promise<Scenario> => {
    if (world) {
      // Every run of the window, the recording run included, starts on devices
      // reopened from the pre-window files. A reopened process rebuilds the
      // derived view (a stamp that counts process starts) and re-initializes
      // its worker once, so a warm process and a reopened one trace slightly
      // different windows; mixing them would misalign trace indexes.
      det.count = start;
      world.rewind();
      return world.scenario();
    }
    det.count = 0;
    return (await prepare()).scenario();
  };
  // 1. Recording run: the trace of the armed window, then the reference outcome.
  const ref = await begin();
  const before = ref.reads();
  ref.crash.arm();
  await settle(ref.run());
  const trace = [...ref.crash.trace];
  ref.crash.disarm();
  const afterRun = ref.reads();
  await ref.resume();
  await ref.resume();
  const final = ref.reads();
  const finalDigest = ref.digest();
  const referenceViolations = [
    ...ref.invariants(),
    ...(ref.checkReference?.({
      index: -1,
      label: "reference",
      before,
      final,
    }) ?? []),
    ...(ref.checkResumed?.({ index: -1, label: "reference", before, final }) ??
      []),
  ];
  void afterRun;
  if (method === "warm") cleanupHarness();

  const failures = new Map<number, Violation[]>();
  if (referenceViolations.length) failures.set(-1, referenceViolations);
  const add = (k: number, violations: Violation[]) => {
    if (violations.length)
      failures.set(k, [...(failures.get(k) ?? []), ...violations]);
  };

  // 2. One run from the pre-window state per walked index, killed exactly there.
  const walked = all ? trace.map((_, k) => k) : pullRequestTier(trace);
  let unreached = 0;
  let allowedMissing = 0;
  const allowed = new Set(options.expectedUnreached?.indexes);
  for (const k of walked) {
    const label = trace[k]!;
    const frame: Frame = { index: k, label, before, final };
    const s = await begin();
    s.crash.arm(k);
    await settle(s.run());
    if (!s.crash.dead) {
      // The randomness is seeded, so the recording run's trace is this run's
      // trace: a missing point is a defect unless the test names it.
      unreached++;
      if (allowed.has(k)) allowedMissing++;
      else
        add(k, [
          `[unreached] crash index ${k} (${label}) was in the recording run's trace but this run did not reach it`,
        ]);
      if (method === "warm") cleanupHarness();
      continue;
    }
    s.restart();
    revive(s.crash);
    const crashed: Violation[] = [];
    const inv = safely("invariant", () => s.invariants());
    if (inv.violation) crashed.push(inv.violation);
    else crashed.push(...inv.value!);
    const read = safely("reads", () => s.reads());
    if (read.violation) crashed.push(read.violation);
    else if (
      !isDeepStrictEqual(read.value, before) &&
      !isDeepStrictEqual(read.value, final) &&
      !s.intermediate?.(read.value, frame)
    )
      crashed.push(
        `[mixed-read] public reads equal neither the pre-step nor the final value: ${JSON.stringify(read.value)}`,
      );
    for (const check of [s.checkCrashed]) {
      if (!check) continue;
      const result = safely("check", () => check.call(s, frame));
      if (result.violation) crashed.push(result.violation);
      else crashed.push(...result.value!);
    }
    add(k, crashed);
    // Resume twice, then compare with the no-crash reference.
    await s.resume();
    await s.resume();
    const resumed: Violation[] = [];
    const inv2 = safely("invariant", () => s.invariants());
    if (inv2.violation) resumed.push(inv2.violation);
    else resumed.push(...inv2.value!.map((v) => `${v} (after resume)`));
    const read2 = safely("reads", () => s.reads());
    if (read2.violation) resumed.push(read2.violation);
    else if (!isDeepStrictEqual(read2.value, final))
      resumed.push(
        `[convergence] reads after resume differ from the reference: ${JSON.stringify(read2.value)} vs ${JSON.stringify(final)}`,
      );
    const dig = safely("digest", () => s.digest());
    if (dig.violation) resumed.push(dig.violation);
    else if (!isDeepStrictEqual(dig.value, finalDigest))
      resumed.push(
        `[convergence] durable digest differs from the reference: ${JSON.stringify(dig.value)} vs ${JSON.stringify(finalDigest)}`,
      );
    if (s.checkResumed) {
      const result = safely("check", () => s.checkResumed!(frame));
      if (result.violation) resumed.push(result.violation);
      else resumed.push(...result.value!);
    }
    add(k, resumed);
    if (method === "warm") cleanupHarness();
  }

  const categories: Record<string, number> = {};
  const lines: string[] = [];
  for (const [k, list] of failures) {
    for (const v of new Set(list.map(categoryOf)))
      categories[v] = (categories[v] ?? 0) + 1;
    lines.push(
      `#${k} ${k >= 0 ? trace[k] : "reference"}: ${[...new Set(list)].slice(0, 3).join(" | ")}`,
    );
  }
  const failedIndexes = [...failures.keys()].filter((k) => k >= 0).length;
  const summary = `${name}: ${method}, ${all ? "every index" : "pull-request tier"}, trace N=${trace.length}, walked ${walked.length}, indexes passed ${walked.length - allowedMissing - failedIndexes}, failed ${failedIndexes}, unreached ${unreached} (${allowedMissing} named as expected), reference ${failures.has(-1) ? "FAILED" : "ok"}, by category ${JSON.stringify(categories)}`;
  console.info(`[crash-matrix] ${summary}`);
  return {
    name,
    points: trace.length,
    failedIndexes,
    categories,
    failures: lines.slice(0, 8),
    summary,
  };
}
/** Fail with the summary and the first failures, never with a full diff. */
function expectMatrix(report: MatrixReport, minimumPoints = 8) {
  expect(
    report.points,
    `${report.summary}: trace too short`,
  ).toBeGreaterThanOrEqual(minimumPoints);
  expect(report.failures, report.summary).toEqual([]);
}

// ------------------------------------------------- source-side scenarios

interface SourceOptions {
  text: string;
  chunk?: number;
  /** retain: crash window is retain+prepare. publish: window is publish. */
  window: "retain" | "publish";
  loseRegistrationResponse?: boolean;
}

/**
 * Source device A (crashable) plus destination device B. The feed and the RPC
 * fail during the window so that the trace stays on the phase under test; the
 * resume clears every fault.
 */
async function sourceWorld(options: SourceOptions): Promise<World> {
  const crash = new CrashController();
  const net = network({ crash });
  const a = transportDevice(net, {
    crash,
    chunk: options.chunk,
    preexisting: options.text,
  });
  const b = transportDevice(net, { chunk: options.chunk });
  const sourceValue = a.get();
  const journalBefore = count(
    b.db,
    "SELECT count(*) AS n FROM pdpp_replica_own_writes",
  );
  net.faults.list = () => new Error("feed down");
  net.faults.evidence = () => new Error("rpc down");
  let prelude:
    { outbox: Record<string, OutboxRow>; encrypts: number } | undefined;
  if (options.window === "publish") {
    await settle(a.cycle()); // retain + prepare; publication fails and backs off
    net.faults.evidence = undefined;
    prelude = { outbox: outboxSnapshot(a.db), encrypts: net.calls.encrypts };
  }
  const rewind = checkpoint(net, [a, b], crash);
  const scenario = (): Scenario => {
    let capturedOutbox: Record<string, OutboxRow> = {};
    let capturedBatches: ReturnType<typeof batchSnapshot> = [];
    let putsAtCrash = new Map<string, number>();

    return {
      crash,
      restart: () => a.crashReopen(),
      invariants: () =>
        transportInvariantViolations(a).map((v) => `[invariant] ${v}`),
      async run() {
        clock.advance(10_000);
        if (options.loseRegistrationResponse)
          net.faults.loseRegistrationResponse = true;
        await a.cycle();
      },
      async resume() {
        net.faults.list = undefined;
        net.faults.evidence = undefined;
        await cycleAll([a, b], 6);
      },
      reads: () => ({
        dest: b.get(),
        destList: publicList(b),
        source: a.get(),
      }),
      digest: () => ({
        batches: batchSnapshot(a.db).length,
        outbox: Object.keys(outboxSnapshot(a.db)).length,
        published: Object.values(outboxSnapshot(a.db)).every(outboundDone),
        registrations: [...registrationsPerScope(net).values()].sort(),
        destChanges: count(
          b.db,
          "SELECT count(*) AS n FROM pdpp_record_changes",
        ),
        destImportedPerBatch: (
          b.db
            .prepare(
              "SELECT count(*) AS n FROM pdpp_transport_imported GROUP BY batch",
            )
            .all() as { n: number }[]
        ).map((r) => r.n),
        destJournal: count(
          b.db,
          "SELECT count(*) AS n FROM pdpp_replica_own_writes",
        ),
      }),
      checkCrashed({ label }) {
        const out: Violation[] = [];
        // The local value is readable at every point.
        if (!isDeepStrictEqual(a.get(), sourceValue))
          out.push(`[local-read] local value changed after ${label}`);
        capturedOutbox = outboxSnapshot(a.db);
        capturedBatches = batchSnapshot(a.db);
        if (process.env.PROF)
          console.error(
            `DBG ${label} batches=${capturedBatches.length} outbox=${Object.values(
              capturedOutbox,
            )
              .map((r) => r.state)
              .join(
                ",",
              )} regs=${net.calls.registrations.length} puts=${net.calls.puts.length} cp=${a.store.replication.getBaselineCheckpoint()}`,
          );
        putsAtCrash = putsPerScope(net);
        // Export cursor and batch row commit together.
        const checkpoint = a.store.replication.getBaselineCheckpoint();
        if (checkpoint > 0 !== capturedBatches.length >= 1)
          out.push(
            `[retain] export cursor ${checkpoint} but ${capturedBatches.length} retained batch rows`,
          );
        // No outbound effect before custody of the immutable bytes.
        for (const scope of net.calls.puts)
          if (!capturedOutbox[scope])
            out.push(
              `[custody] PUT for ${scope} without a persisted outbox row`,
            );
        for (const scope of net.calls.registrations)
          if (!capturedOutbox[scope])
            out.push(
              `[custody] registration for ${scope} without an outbox row`,
            );
        // Bytes in the store are the persisted ciphertext, never a re-encryption.
        for (const [scope, bytes] of net.blobs)
          if (
            capturedOutbox[scope] &&
            Buffer.from(bytes).toString("hex") !==
              capturedOutbox[scope].encrypted
          )
            out.push(
              `[custody] stored bytes of ${scope} differ from the outbox ciphertext`,
            );
        if (
          prelude &&
          !isDeepStrictEqual(
            stableOutbox(capturedOutbox),
            stableOutbox(prelude.outbox),
          )
        )
          out.push(
            "[custody] outbox ciphertext or hashes changed before resume",
          );
        if (prelude && net.calls.encrypts !== prelude.encrypts)
          out.push(
            `[custody] re-encrypted after custody (${net.calls.encrypts - prelude.encrypts} encrypt calls)`,
          );
        return out;
      },
      checkResumed() {
        const out: Violation[] = [];
        const outbox = outboxSnapshot(a.db);
        // No ciphertext that existed before the crash is ever replaced.
        for (const [scope, row] of Object.entries(capturedOutbox))
          if (outbox[scope]?.encrypted !== row.encrypted)
            out.push(`[custody] ciphertext of ${scope} changed after resume`);
        if (prelude) {
          if (
            !isDeepStrictEqual(
              stableOutbox(outbox),
              stableOutbox(prelude.outbox),
            )
          )
            out.push(
              "[custody] outbox set or bytes differ from the pre-window snapshot",
            );
        }
        // No regenerated batch identity.
        const batches = batchSnapshot(a.db);
        for (const old of capturedBatches) {
          const now = batches.find((x) => x.batch === old.batch);
          if (
            !now ||
            now.sequence !== old.sequence ||
            now.digest !== old.digest
          )
            out.push(
              `[identity] batch ${old.batch} was regenerated or re-sequenced`,
            );
        }
        if (batches.length !== 1)
          out.push(
            `[identity] ${batches.length} batches retained for one local commit`,
          );
        // One registration per manifest slot, none per fragment, never a rebase.
        for (const [scope, row] of Object.entries(outbox)) {
          const registrations = registrationsPerScope(net).get(scope) ?? 0;
          if (registrations !== (row.kind === "manifest" ? 1 : 0))
            out.push(
              `[publication] ${registrations} registrations for ${row.kind} ${scope}`,
            );
          const puts = putsPerScope(net).get(scope) ?? 0;
          if (puts < 1 || puts > 2 || puts < (putsAtCrash.get(scope) ?? 0))
            out.push(`[publication] ${puts} PUTs for ${scope}`);
          const head = net.head.get(scope);
          if (
            row.kind === "manifest" &&
            (!head ||
              head.version !== String(row.version) ||
              head.dataHash !== row.dataHash)
          )
            out.push(
              `[publication] head of ${scope} is not its slot with the persisted hash`,
            );
          if (
            net.blobs.has(scope) &&
            Buffer.from(net.blobs.get(scope)!).toString("hex") !==
              outbox[scope]!.encrypted
          )
            out.push(
              `[custody] remote bytes of ${scope} differ from the persisted ciphertext`,
            );
        }
        if (
          count(b.db, "SELECT count(*) AS n FROM pdpp_replica_own_writes") !==
          journalBefore
        )
          out.push("[echo] receiver journal grew after replay");
        return out;
      },
    };
  };
  return {
    crash,
    net,
    devices: [a, b],
    windowDevices: [a, b],
    rewind,
    scenario,
  };
}

describe("section C: custody and crash boundaries", () => {
  it(
    "35 local commit to retain/enqueue: export cursor and batch row commit together, no regenerated identity",
    async () => {
      const report = await crashMatrix("35 retain", () =>
        sourceWorld({ text: "local commit", window: "retain" }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );

  it(
    "36 prepared ciphertext before external PUT: same address, same bytes after every crash point",
    async () => {
      const report = await crashMatrix("36 publish", () =>
        sourceWorld({ text: "prepared ciphertext", window: "publish" }),
      );
      expect(
        report.points,
        "the publication window must contain a PUT and a registration",
      ).toBeGreaterThan(0);
      expectMatrix(report);
    },
    matrixLimit,
  );

  it(
    "37 remote PUT accepted, local acknowledgment lost: multi-fragment batch, no rebase or second ciphertext",
    async () => {
      const report = await crashMatrix("37 multi-fragment publish", () =>
        sourceWorld({
          text: "x".repeat(1500),
          chunk: 600,
          window: "publish",
        }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );

  it(
    "38 registration commits, response lost: one registration per scope, no replacement PUT",
    async () => {
      const report = await crashMatrix("38 lost registration response", () =>
        sourceWorld({
          text: "lost response",
          window: "publish",
          loseRegistrationResponse: true,
        }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );
});

// -------------------------------------------- destination-side scenarios

interface DestinationOptions {
  text?: string;
  chunk?: number;
  /** Publish several local commits as separate batches (discovery pages). */
  batches?: number;
  /** A binary blob of this size travels with the record. */
  blobBytes?: number;
  pageSize?: number;
}

/**
 * Source A publishes and finalizes everything first, outside the window. The
 * window is destination B's cycles: discovery, download, confirmation, staging
 * and import. B's process is lost at every point of that window.
 */
async function destinationWorld(options: DestinationOptions): Promise<World> {
  const crash = new CrashController();
  const net = network({ crash, cap: 64 * 1024 });
  const chunk = options.chunk ?? 600;
  const a = transportDevice(net, { chunk, cap: 64 * 1024 });
  let blobId: string | undefined;
  if (options.blobBytes) {
    const bytes = new Uint8Array(options.blobBytes).fill(7);
    const blob = a.store.storeBlobBytesForInstance({
      instance: "conn",
      method: "export",
      generation: 1,
      bytes,
      mimeType: "application/octet-stream",
    });
    blobId = blob.blobId;
    a.store.ingestBatch(
      [
        {
          instance: "conn",
          stream: "messages",
          key: "a",
          emitted_at: at,
          data: {
            id: "a",
            blob_ref: {
              blob_id: blob.blobId,
              mime_type: blob.mimeType,
              size_bytes: bytes.length,
            },
          },
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
    );
  } else a.put(options.text ?? "destination");
  for (let i = 1; i < (options.batches ?? 1); i++) {
    await cycleAll([a], 2);
    a.put(`later ${i}`, `k${i}`);
  }
  // Two source cycles reach the steady state (every batch published, no new
  // puts); further cycles only repeat no-op phases before the window opens.
  await cycleAll([a], 2);
  if (options.pageSize) net.pageSize(options.pageSize);
  const b = transportDevice(net, { chunk, cap: 64 * 1024, crash });
  const journalBefore = count(
    b.db,
    "SELECT count(*) AS n FROM pdpp_replica_own_writes",
  );
  // Only B runs in the window; A is never touched, and the equivalence test compares it anyway.
  const rewind = checkpoint(net, [b], crash);
  const scenario = (): Scenario => {
    let fetchedAtCrash = new Set<string>();
    let retained: ReturnType<typeof retainedObjects> = [];
    let getsAtCrash = 0;
    return {
      crash,
      restart: () => b.crashReopen(),
      invariants: () =>
        transportInvariantViolations(b).map((v) => `[invariant] ${v}`),
      async run() {
        clock.advance(10_000);
        await b.cycle();
        clock.advance(10_000);
        await b.cycle();
      },
      async resume() {
        await cycleAll([b], 6);
      },
      reads: () => ({
        list: publicList(b),
        blob: blobId ? sha(b.store.getBlobBytes(blobId)) : null,
      }),
      // One writer scope holds every batch, so one window can import several
      // in sequence. Each import is atomic: a crash shows a prefix of batches.
      intermediate: (read, frame) => {
        const now = read as { list: unknown[]; blob: unknown };
        const end = frame.final as { list: unknown[]; blob: unknown };
        return (
          (options.batches ?? 1) > 1 &&
          now.blob === end.blob &&
          isDeepStrictEqual(now.list, end.list.slice(0, now.list.length))
        );
      },
      digest: () => ({
        imported: (
          b.db
            .prepare(
              "SELECT count(*) AS n FROM pdpp_transport_imported GROUP BY batch",
            )
            .all() as { n: number }[]
        ).map((r) => r.n),
        inbox: (
          b.db
            .prepare(
              "SELECT state FROM pdpp_transport_manifests_in ORDER BY slot",
            )
            .all() as { state: string }[]
        ).map((r) => r.state),
        fragments: (
          b.db
            .prepare(
              "SELECT state FROM pdpp_transport_fragments_in ORDER BY slot,position",
            )
            .all() as { state: string }[]
        ).map((r) => r.state),
        changes: count(b.db, "SELECT count(*) AS n FROM pdpp_record_changes"),
        journal: count(
          b.db,
          "SELECT count(*) AS n FROM pdpp_replica_own_writes",
        ),
        staging: count(
          b.db,
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace='staging'",
        ),
      }),
      checkReference() {
        // Every durable work item carries a typed outcome after a clean run.
        const records = workRecords(b.db).filter(
          (r) =>
            r.table !== "pdpp_transport_fragments_out" &&
            r.table !== "pdpp_transport_manifests_out",
        );
        const untyped = records.filter(
          (r) => r.outcome === undefined || r.outcome === null,
        );
        return untyped.length
          ? [`[outcome] ${untyped.length} work records without a typed outcome`]
          : [];
      },
      checkCrashed() {
        const out: Violation[] = [];
        retained = retainedObjects(b.db);
        fetchedAtCrash = new Set(retained.map((r) => r.key));
        getsAtCrash = net.calls.gets.length;
        // Discovery: an admitted scope is never lost behind an advanced cursor.
        const cursor = (
          b.db.prepare("SELECT scan_cursor FROM pdpp_transport_state").get() as
            { scan_cursor: string | null } | undefined
        )?.scan_cursor;
        if (cursor) {
          const admitted = count(
            b.db,
            "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE scope<=?",
            cursor,
          );
          // Discovery admits every version of a listed scope.
          const listed = [...net.head.keys()].filter(
            (k) => k.slice(0, k.lastIndexOf("/")) <= cursor,
          ).length;
          if (admitted !== listed)
            out.push(
              `[discovery] cursor ${cursor} advanced past ${listed - admitted} unadmitted scopes`,
            );
        }
        // No receipt/progress without the evidence it claims.
        const imports = workRecords(b.db).filter(
          (r) =>
            r.table === "pdpp_transport_import_work" &&
            r.outcome === "progress",
        );
        for (const r of imports)
          if (
            count(
              b.db,
              "SELECT count(*) AS n FROM pdpp_transport_imported WHERE writer||':'||batch=?",
              r.id,
            ) === 0 &&
            count(
              b.db,
              "SELECT count(*) AS n FROM pdpp_transport_imported WHERE batch=?",
              r.id,
            ) === 0
          )
            out.push(`[outcome] import ${r.id} progress without a receipt`);
        const downloads = workRecords(b.db).filter(
          (r) =>
            (r.table === "pdpp_transport_manifests_in" ||
              r.table === "pdpp_transport_fragments_in") &&
            r.outcome === "progress",
        );
        const retainedIds = new Set(retained.map((r) => r.id));
        for (const r of downloads)
          if (!retainedIds.has(r.id))
            out.push(
              `[outcome] download ${r.id} progress without a retained object`,
            );
        return out;
      },
      checkResumed() {
        const out: Violation[] = [];
        // Retry needs only missing objects: retained ones are not fetched again.
        const after = net.calls.gets.slice(getsAtCrash);
        for (const key of after)
          if (fetchedAtCrash.has(key))
            out.push(`[download] re-fetched retained object ${key}`);
        if (
          count(b.db, "SELECT count(*) AS n FROM pdpp_replica_own_writes") !==
          journalBefore
        )
          out.push("[echo] receiver journal grew after replay");
        return out;
      },
    };
  };
  return { crash, net, devices: [a, b], windowDevices: [b], rewind, scenario };
}

describe("section C: destination custody and crash boundaries", () => {
  it(
    "39 discovery pages: replay dedupes admissions and never skips a scope behind the cursor",
    async () => {
      const report = await crashMatrix("39 discovery", () =>
        destinationWorld({ batches: 3, pageSize: 1 }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );
  it(
    "40 partial download: an incomplete batch never imports; resume fetches only missing fragments",
    async () => {
      const report = await crashMatrix("40 partial download", () =>
        destinationWorld({ text: "f".repeat(2000), chunk: 600 }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );
  it(
    "41/42 verified staging and import receipt: no public blob or record without the committed receipt; no orphan staging",
    async () => {
      const report = await crashMatrix("41 staged blob import", () =>
        destinationWorld({ blobBytes: 3000, chunk: 1500 }),
      );
      expectMatrix(report);
    },
    matrixLimit,
  );
});

// ------------------------------------------------- restore equivalence

/** Every table row of a device, ordered, with bytes as hex: journal, epochs, checkpoints, writer id. */
function dumpDevice(d: TransportDevice) {
  const names = (
    d.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all() as { name: string }[]
  ).map((t) => t.name);
  return Object.fromEntries(
    names.map((name) => [
      name,
      (d.db.prepare(`SELECT * FROM "${name}"`).all() as object[])
        .map((row) =>
          JSON.stringify(row, (k, v) =>
            // The store stamps wall-clock time on finalized facts.
            k === "observed_at"
              ? "wall-clock"
              : Buffer.isBuffer(v)
                ? `hex:${v.toString("hex")}`
                : v,
          ),
        )
        .sort(),
    ]),
  );
}
function dumpWorld(world: World) {
  const { net } = world;
  return {
    devices: world.devices.map(dumpDevice),
    network: {
      blobs: [...net.blobs].map(([k, v]) => [
        k,
        Buffer.from(v).toString("hex"),
      ]),
      head: [...net.head],
      chain: [...net.chain].map(([k, v]) => [
        k,
        JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? `${x}n` : x)),
      ]),
      pending: [...net.pending],
      // A copy: the resumes after the capture keep appending to the live history.
      calls: structuredClone(net.calls),
    },
    clock: clock.time,
  };
}

/**
 * A crash at index k reaches the same state whether the pre-window state was
 * just built and restarted (fresh) or put back by `rewind` after another run
 * dirtied it (restore). Compared right after process loss and after two resumes.
 */
async function crashAt(
  prepare: () => Promise<World>,
  k: number,
  how: "fresh" | "restore",
) {
  det.count = 0;
  const world = await prepare();
  const start = det.count;
  if (how === "restore") {
    // Dirty every device and the network with a full unrelated run first.
    const other = world.scenario();
    other.crash.arm();
    await settle(other.run());
    other.crash.disarm();
    await other.resume();
    det.count = start;
    world.rewind();
  }
  // The matrix always starts the window on restarted processes (see
  // `crashMatrix`), so the build side restarts every window device on its own
  // file once, as a restore does.
  if (how === "fresh") for (const d of world.windowDevices) d.reopen();
  const s = world.scenario();
  s.crash.arm(k);
  await settle(s.run());
  const reached = s.crash.dead;
  s.restart();
  revive(s.crash);
  const crashed = dumpWorld(world);
  await s.resume();
  await s.resume();
  const result = {
    reached,
    crashed,
    resumed: dumpWorld(world),
    reads: s.reads(),
    digest: s.digest(),
  };
  cleanupHarness();
  return result;
}

describe("restore equivalence: a restored pre-window state behaves as a restarted fresh build", () => {
  const worlds: [string, () => Promise<World>][] = [
    [
      "source publish",
      () => sourceWorld({ text: "equivalence", window: "publish" }),
    ],
    [
      "source retain",
      () => sourceWorld({ text: "equivalence", window: "retain" }),
    ],
    [
      "destination partial download",
      () => destinationWorld({ text: "e".repeat(1300), chunk: 600 }),
    ],
    [
      "destination staged blob",
      () => destinationWorld({ blobBytes: 1500, chunk: 1500 }),
    ],
  ];
  for (const [name, prepare] of worlds)
    it(
      name,
      async () => {
        det.on = true;
        try {
          det.count = 0;
          const probe = await prepare();
          probe.rewind();
          const ref = probe.scenario();
          ref.crash.arm();
          await settle(ref.run());
          const trace = [...ref.crash.trace];
          cleanupHarness();
          // Seeded randomness: a second recording gives the same trace, so the
          // tier chosen from it is the same on every run.
          det.count = 0;
          const again = await prepare();
          again.rewind();
          const ref2 = again.scenario();
          ref2.crash.arm();
          await settle(ref2.run());
          expect([...ref2.crash.trace]).toEqual(trace);
          cleanupHarness();
          const tier = pullRequestTier(trace);
          // The window ends, a commit and the write before it, a network
          // effect, and points spread across the pull-request tier.
          const commit = trace.indexOf("commit");
          const effect = trace.findIndex((l) => l.startsWith("net-"));
          const spread = [0, 1, 2, 3, 4].map(
            (i) => tier[Math.floor((i * (tier.length - 1)) / 4)]!,
          );
          const indexes = [
            ...new Set([...spread, commit, commit - 1, effect]),
          ].filter((i) => i >= 0);
          expect(indexes.length).toBeGreaterThanOrEqual(5);
          for (const k of indexes) {
            const fresh = await crashAt(prepare, k, "fresh");
            const restored = await crashAt(prepare, k, "restore");
            expect(fresh.reached, `index ${k} reached`).toBe(true);
            const at = `index ${k} ${trace[k]}`;
            // Every row of every device (journal, checkpoints, epoch, writer
            // id), the network, the clock, the public reads and the digest.
            expect(restored.crashed, `${at}: right after process loss`).toEqual(
              fresh.crashed,
            );
            expect(restored.resumed, `${at}: after two resumes`).toEqual(
              fresh.resumed,
            );
            expect(restored.reads).toEqual(fresh.reads);
            expect(restored.digest).toEqual(fresh.digest);
          }
        } finally {
          det.on = false;
          cleanupHarness();
        }
      },
      60_000,
    );
});

describe("captured state is a copy", () => {
  it("a captured network history does not follow the live history, and a different history differs", async () => {
    const world = await sourceWorld({ text: "copy", window: "publish" });
    const captured = dumpWorld(world);
    const frozen = structuredClone(captured.network.calls);
    // The resumes after a capture append to the live history.
    world.net.calls.gets.push("late-get");
    world.net.calls.puts.push("late-put");
    expect(captured.network.calls).toEqual(frozen);
    // One extra failed GET before the crash, offset by one fewer GET later,
    // would be invisible to an aliased capture; a copy shows it.
    expect(dumpWorld(world).network.calls).not.toEqual(captured.network.calls);
    cleanupHarness();
  });
});

describe("unreached crash indexes", () => {
  it("fail the matrix unless the test names them with a reason", async () => {
    // A world whose crash run never reaches the last recorded point: the first
    // scenario run records one point more than every later run.
    let calls = 0;
    const prepare = async (): Promise<World> => {
      const world = await quarantineWorld();
      return {
        ...world,
        scenario() {
          const scenario = world.scenario();
          const run = scenario.run.bind(scenario);
          return {
            ...scenario,
            async run() {
              try {
                await run();
              } finally {
                if (calls++ === 0) world.crash.point("extra-point");
              }
            },
          };
        },
      };
    };
    // Each method records its own trace (restore and warm differ in length), so
    // each is run directly and its own last index is the one named.
    for (const method of ["restore", "warm"] as const) {
      calls = 0;
      const report = await runMatrix("unreached control", prepare, method, {});
      const last = report.points - 1;
      expect(report.failures.join("\n"), method).toMatch(
        /\[unreached\] crash index/,
      );
      calls = 0;
      const named = await runMatrix(
        "unreached control named",
        prepare,
        method,
        {
          expectedUnreached: {
            indexes: [last],
            reason: "the control adds one point to the recording run only",
          },
        },
      );
      expect(named.failures.join("\n"), method).not.toMatch(/\[unreached\]/);
    }
  }, 60_000);
});

describe("pull-request tier selection", () => {
  it("takes the window ends, every distinct step's ends and rollback point, and both sides of an effect", () => {
    const trace = [
      ...["before-insert:a", "after-insert:a", "before-update:b"],
      ...["after-update:b", "commit"],
      ...["net-before-put:s1", "net-after-put:s1"],
      ...["before-insert:a", "after-insert:a", "before-update:b"],
      ...["after-update:b", "commit"],
      ...["before-insert:a", "after-insert:a", "before-update:b"],
      ...["after-update:b", "commit"],
      ...["net-before-put:s2", "net-after-put:s2"],
      ...["before-insert:c", "after-insert:c"],
    ];
    const tier = pullRequestTier(trace);
    // Window ends.
    expect(tier).toContain(0);
    expect(tier).toContain(trace.length - 1);
    // First run of the repeated step: first write 0, rollback point 3, commit 4.
    expect(tier).toEqual(expect.arrayContaining([0, 3, 4]));
    // Last run of that step.
    expect(tier).toEqual(expect.arrayContaining([15, 16]));
    // Both sides of both effects.
    expect(tier).toEqual(expect.arrayContaining([5, 6, 17, 18]));
    // The middle run of the repeated step: first write 7, rollback point 10, commit 11.
    expect(tier).toEqual(expect.arrayContaining([7, 10, 11]));
    // Interior writes of a run are not walked.
    expect(tier).not.toContain(8);
    expect(tier).toEqual([...tier].sort((x, y) => x - y));
  });
});

// ------------------------------------------------ quarantine atomicity (44)

const epochOf = (d: TransportDevice, connection: string) => {
  const read = (d.store as { replicaIntegrityEpoch?: (key: string) => number })
    .replicaIntegrityEpoch;
  if (typeof read !== "function")
    throw new Error("store.replicaIntegrityEpoch is missing");
  return read.call(d.store, connection);
};
const appendUpsert = (text: string, counter: number): ReplicaOperation => ({
  kind: "upsert",
  owner,
  sourceId,
  connectionId: "conn",
  methodId: "export",
  generation: 1,
  revision: {
    counter,
    writerId: "f".repeat(32),
    operationId: `append-${text}`,
  },
  declaration: appendBinding,
  recordKey: "log",
  emittedAt: at,
  data: { id: "log", text },
  blobs: [],
});

async function quarantineWorld(): Promise<World> {
  const crash = new CrashController();
  const net = network({ crash });
  const b = transportDevice(net, { crash });
  b.declarations([
    { sourceId, binding },
    { sourceId, binding: appendBinding },
  ]);
  b.reopen();
  b.declarations([
    { sourceId, binding },
    { sourceId, binding: appendBinding },
  ]);
  b.receiver.import({
    credential,
    envelope: envelope([appendUpsert("first", 50)], "q1"),
  });
  let epochBefore = 0;
  try {
    epochBefore = epochOf(b, "conn");
  } catch {
    epochBefore = Number.NaN;
  }
  const rewind = checkpoint(net, [b], crash);
  const scenario = (): Scenario => ({
    crash,
    restart: () => {
      b.crashReopen();
      b.declarations([
        { sourceId, binding },
        { sourceId, binding: appendBinding },
      ]);
    },
    invariants: () => {
      // A committed key fence never coexists with a live projection of that key.
      const fenced = count(
        b.db,
        "SELECT count(*) AS n FROM pdpp_replica_quarantined_keys WHERE instance='conn' AND record_key='log'",
      );
      const live = count(
        b.db,
        "SELECT count(*) AS n FROM pdpp_records WHERE instance='conn' AND record_key='log' AND deleted=0",
      );
      return fenced && live
        ? ["[fence] fence committed with live data visible"]
        : [];
    },
    async run() {
      b.receiver.import({
        credential,
        envelope: envelope([appendUpsert("second", 51)], "q2"),
      });
    },
    async resume() {
      // Duplicate delivery of the conflicting batch is the replay.
      try {
        b.receiver.import({
          credential,
          envelope: envelope([appendUpsert("second", 51)], "q2"),
        });
      } catch {
        /* the reference keeps the fence; a refused replay is acceptable */
      }
    },
    reads: () => ({
      point: b.store.getRecord("conn", "messages", "log")?.data ?? null,
    }),
    digest: () => ({
      fenced: count(
        b.db,
        "SELECT count(*) AS n FROM pdpp_replica_quarantined_keys WHERE instance='conn'",
      ),
      retained: count(b.db, "SELECT count(*) AS n FROM pdpp_replica_received"),
    }),
    checkResumed() {
      const out: Violation[] = [];
      const epoch = safely("epoch", () => epochOf(b, "conn"));
      if (epoch.violation) return [epoch.violation];
      if (epoch.value !== epochBefore + 1)
        out.push(
          `[epoch] epoch ${epoch.value} after one quarantine (was ${epochBefore})`,
        );
      return out;
    },
  });
  return { crash, net, devices: [b], windowDevices: [b], rewind, scenario };
}

describe("section C: fences, outcomes and claims", () => {
  it(
    "44 quarantine transaction atomicity: old snapshot or fully fenced, epoch bumps exactly once across replay",
    async () => {
      const report = await crashMatrix("44 key quarantine", quarantineWorld);
      expectMatrix(report, 2);
    },
    matrixLimit,
  );

  it("43 a quarantine committed between computing and applying a projection cannot resurrect fenced data", async () => {
    const net = network();
    const b = transportDevice(net);
    b.declarations([
      { sourceId, binding },
      { sourceId, binding: appendBinding },
    ]);
    b.reopen();
    b.declarations([
      { sourceId, binding },
      { sourceId, binding: appendBinding },
    ]);
    b.receiver.import({
      credential,
      envelope: envelope([appendUpsert("first", 50)], "c1"),
    });
    const before = epochOf(b, "conn");
    b.receiver.import({
      credential,
      envelope: envelope([appendUpsert("second", 51)], "c2"),
    });
    // A stale recomputation (plain retry) after the fence must keep the key hidden.
    b.receiver.retry({ credential });
    expect(epochOf(b, "conn")).toBe(before + 1);
    expect(b.store.getRecord("conn", "messages", "log")).toBeUndefined();
    expect(count(b.db, "SELECT count(*) AS n FROM pdpp_replica_received")).toBe(
      2,
    );
  });

  it("45 work outcome atomicity: a progress receipt never pairs with retry/wait diagnostics of another execution", async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "atomic outcome" });
    const b = transportDevice(net);
    // First publish attempt fails, the second succeeds: the final row must not
    // carry the first attempt's diagnostics next to its progress outcome.
    let fail = true;
    net.faults.evidence = () => (fail ? new Error("rpc down") : undefined);
    await cycleAll([a], 1);
    fail = false;
    await cycleAll([a, b], 6);
    expect(b.get()).toEqual({ id: "a", text: "atomic outcome" });
    const records = workRecords(a.db).filter(
      (r) =>
        r.table === "pdpp_transport_fragments_out" ||
        r.table === "pdpp_transport_manifests_out",
    );
    expect(
      records.filter((r) => r.table === "pdpp_transport_manifests_out"),
    ).toHaveLength(1);
    for (const r of records) {
      expect(r.outcome).toBe("progress");
      expect(r.reason ?? null).toBeNull();
      expect(r.cause ?? null).toBeNull();
      expect(r.error).toBeNull();
      expect(r.attempts).toBe(0);
    }
    // B also imports its own registration batch; A's batch is the one under test.
    const writerA = (
      a.db.prepare("SELECT writer FROM pdpp_transport_state").get() as {
        writer: string;
      }
    ).writer;
    const imports = workRecords(b.db).filter(
      (r) => r.table === "pdpp_transport_import_work" && r.writer === writerA,
    );
    expect(imports.map((r) => r.outcome)).toEqual(["progress"]);
  });

  it("46 competing claims: a second worker on the same file cannot run concurrently, and a timed-out run's late result cannot overwrite newer state", async () => {
    const net = network();
    const a = transportDevice(net, {
      preexisting: "claimed",
      worker: { deadlineMs: 50 },
    });
    // Second handle on the same file, same process.
    const second = new Database(a.path);
    const secondStore = createReplicaRecordStore(second);
    const alias = createReplicaTransportWorker({
      db: second,
      enabled: true,
      expected: () => ({
        owner,
        declarations: [{ sourceId, binding: appendBinding }],
      }),
      exporter: secondStore.replication,
      receiver: createReplicaReceiver({
        db: second,
        store: secondStore,
        owner,
        authenticate: () => owner,
        declarations: () => [],
      }),
      credential,
      transport: net.port,
      authority: a.authority,
      now: clock.now,
    });
    let release = () => {};
    const hung = new Promise<void>((resolve) => (release = resolve));
    const realPut = net.port.put;
    net.port.put = async (part) => {
      await hung;
      return realPut(part);
    };
    let running: Promise<unknown> = Promise.resolve();
    try {
      running = a.cycle();
      await sleep(5);
      // The alias either refuses (another process holds the lock) or sees the
      // in-process guard and does nothing: never a concurrent run.
      const putsBefore = net.calls.puts.length;
      await alias.cycle().catch((error: unknown) => {
        expect(error).toMatchObject({ code: "replica_worker_active" });
      });
      expect(net.calls.puts.length).toBe(putsBefore);
      // The bounded run must give up at its deadline, not hang the step.
      const outcome = await Promise.race([
        running.then(
          () => "settled" as const,
          () => "settled" as const,
        ),
        sleep(1000).then(() => "hung" as const),
      ]);
      expect(outcome).toBe("settled");
      const afterDeadline = workRecords(a.db).filter(
        (r) => r.table === "pdpp_transport_manifests_out",
      );
      expect(afterDeadline).toHaveLength(1);
      expect(
        afterDeadline.every(
          (r) => r.outcome === "retry" && r.reason === "deadline_exceeded",
        ),
      ).toBe(true);
      // The late completion of the abandoned run changes nothing durable.
      release();
      await sleep(20);
      expect(
        workRecords(a.db).filter(
          (r) => r.table === "pdpp_transport_manifests_out",
        ),
      ).toEqual(afterDeadline);
    } finally {
      release();
      await running.catch(() => undefined);
      net.port.put = realPut;
      secondStore.close();
    }
  });
});

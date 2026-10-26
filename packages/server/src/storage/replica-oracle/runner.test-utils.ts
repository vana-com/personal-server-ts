/**
 * Every-prefix differential runner (oracle design §2). Drives each port with
 * the same commands, recomputes the frozen reference after every command,
 * and compares stored rows, owner and grant point and list reads, pending
 * markers and readable blob bytes. Each prefix is also replayed into fresh
 * stores as one delivery, which exposes stale incremental state.
 */
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  BINDINGS,
  BLOBS as BLOB_NAMES,
  blobOf,
  PROVISIONED_AT_START,
  UNIVERSE,
  type BindingName,
  type Command,
} from "./generator.test-utils.js";
import {
  liteDriver,
  liteMemoryPersistence,
  liteSqlitePersistence,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
  type BlobPayload,
  type PortSnapshot,
  type ReplicaPortDriver,
} from "./ports.test-utils.js";
import {
  emptyRefState,
  parseRowId,
  refConnectionStatus,
  refLive,
  refLocalWritable,
  refPendingRows,
  refProject,
  revisionId,
  type RefState,
  type RefWorld,
} from "./reference.test-utils.js";

export type PortName = "node" | "lite-memory" | "lite-sqlite";
export const ALL_PORTS: readonly PortName[] = [
  "node",
  "lite-memory",
  "lite-sqlite",
];

export interface Failure {
  prefix: number;
  command: Command | null;
  port: string;
  check: string;
  expected: unknown;
  actual: unknown;
}
export interface RunOptions {
  ports?: readonly PortName[];
  /** Replay every prefix into fresh stores (design §2). */
  freshReplay?: boolean;
  declared?: BindingName[];
}

interface PortRun {
  driver: ReplicaPortDriver;
  mappings: Map<string, { sourceId: string; methodId: string }>;
  canon: RefState;
}

const sortedKeys = (record: Record<string, unknown>) =>
  Object.keys(record).sort();
function normalize<T>(record: Record<string, T>) {
  return Object.fromEntries(
    sortedKeys(record).map((k) => [k, JSON.parse(canonicalJson(record[k]))]),
  );
}

async function openPort(name: PortName, declared: BindingName[]) {
  const declarations = declared.map((b) => BINDINGS[b]);
  const provisioned = [...PROVISIONED_AT_START];
  if (name === "node")
    return nodeDriver({ durable: true, declarations, provisioned });
  return liteDriver({
    name,
    persistence:
      name === "lite-memory"
        ? liteMemoryPersistence()
        : liteSqlitePersistence(),
    declarations,
    provisioned,
  });
}

/** Facts shared by every port: what the remote side delivered and the host decided. */
interface Shared {
  confirmed: Map<string, ReplicaOperation>;
  bytes: Set<string>;
  pending: Map<string, { ops: ReplicaOperation[]; blobs: string[] }>;
  declared: Set<BindingName>;
  terminal: Set<string>;
  batches: Map<string, { ops: ReplicaOperation[]; blobs: string[] }>;
}

function worldOf(
  shared: Shared,
  run: PortRun,
  extraBytes: Iterable<string> = [],
): RefWorld {
  return {
    owner: OWNER,
    mappings: run.mappings,
    declarations: [...shared.declared].map((b) => ({
      sourceId: SOURCE,
      binding: BINDINGS[b],
    })),
    bytes: new Set([...shared.bytes, ...extraBytes]),
    terminal: shared.terminal,
  };
}

/** Whether a port must accept a delivered batch: every mapped connection matches. */
function batchAdmissible(run: PortRun, ops: readonly ReplicaOperation[]) {
  return ops.every((op) => {
    const mapping = run.mappings.get(op.connectionId);
    return (
      !mapping ||
      (mapping.sourceId === op.sourceId && mapping.methodId === op.methodId)
    );
  });
}

async function attempt(
  fn: () => Promise<unknown>,
): Promise<string | undefined> {
  try {
    await fn();
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function compare(
  failures: Failure[],
  base: Omit<Failure, "check" | "expected" | "actual">,
  check: string,
  expected: unknown,
  actual: unknown,
) {
  if (canonicalJson(expected) !== canonicalJson(actual))
    failures.push({ ...base, check, expected, actual });
}

function expectedStored(state: RefState) {
  const out: Record<string, unknown> = {};
  for (const [id, row] of state.rows)
    out[id] = row.deleted
      ? { deleted: true }
      : { deleted: false, data: row.data };
  return normalize(out);
}
function actualStored(snapshot: PortSnapshot) {
  const out: Record<string, unknown> = {};
  for (const [id, row] of Object.entries(snapshot.stored))
    out[id] = row.deleted
      ? { deleted: true }
      : { deleted: false, data: row.data };
  return normalize(out);
}

function checkSnapshot(
  failures: Failure[],
  base: Omit<Failure, "check" | "expected" | "actual">,
  snapshot: PortSnapshot,
  canon: RefState,
  preview: RefState,
  evidence: readonly ReplicaOperation[],
) {
  compare(
    failures,
    base,
    "stored rows",
    expectedStored(canon),
    actualStored(snapshot),
  );
  const grant = normalize(Object.fromEntries(refLive(canon)));
  compare(
    failures,
    base,
    "grant point reads",
    grant,
    normalize(snapshot.grant.point),
  );
  compare(
    failures,
    base,
    "grant list reads",
    grant,
    normalize(snapshot.grant.list),
  );
  compare(failures, base, "grant pending markers", [], snapshot.grant.pending);
  const owner = normalize(Object.fromEntries(refLive(preview)));
  compare(
    failures,
    base,
    "owner point reads",
    owner,
    normalize(snapshot.owner.point),
  );
  compare(
    failures,
    base,
    "owner list reads",
    owner,
    normalize(snapshot.owner.list),
  );
  compare(
    failures,
    base,
    "owner pending markers",
    refPendingRows(canon, preview, evidence),
    snapshot.owner.pending,
  );
  // Every blob a live row references reads back its exact bytes.
  const views = { grant: refLive(canon), owner: refLive(preview) };
  for (const reader of ["grant", "owner"] as const) {
    const expected: Record<string, string | null> = {};
    for (const data of views[reader].values()) {
      const id = (data.blob_ref as { blob_id?: unknown } | undefined)?.blob_id;
      const name = BLOB_NAMES.find((n) => blobOf(n).descriptor.blobId === id);
      if (typeof id === "string")
        expected[id] = name
          ? Buffer.from(blobOf(name).bytes).toString("hex")
          : null;
    }
    compare(
      failures,
      base,
      `${reader} blob bytes`,
      expected,
      snapshot[reader].blobs,
    );
  }
}

/** Run a command list; returns every failure at the first failing prefix. */
export async function runCommands(
  commands: readonly Command[],
  options: RunOptions = {},
): Promise<Failure[]> {
  const declared = options.declared ?? ["m", "a"];
  const shared: Shared = {
    confirmed: new Map(),
    bytes: new Set(),
    pending: new Map(),
    declared: new Set(declared),
    terminal: new Set(),
    batches: new Map(),
  };
  const runs: PortRun[] = [];
  const opened: ReplicaPortDriver[] = [];
  try {
    for (const name of options.ports ?? ALL_PORTS) {
      const driver = await openPort(name, declared);
      opened.push(driver);
      runs.push({
        driver,
        mappings: new Map(
          PROVISIONED_AT_START.map((c) => [
            c,
            { sourceId: SOURCE, methodId: METHOD },
          ]),
        ),
        canon: emptyRefState(),
      });
    }
    let hasLocal = false;
    let before = await Promise.all(
      runs.map((run) => run.driver.snapshot(UNIVERSE)),
    );
    for (let prefix = 0; prefix <= commands.length; prefix++) {
      const command = prefix === 0 ? null : commands[prefix - 1];
      const failures: Failure[] = [];
      const touched = touchedConnections(command, shared);
      const journals = await Promise.all(
        runs.map((run) => run.driver.localOperations()),
      );
      if (command) {
        if (command.k === "local") hasLocal = true;
        await apply(command, shared, runs, journals, failures, prefix);
      }
      const after: PortSnapshot[] = [];
      for (const [i, run] of runs.entries()) {
        const base = { prefix, command, port: run.driver.name };
        const evidence = [
          ...shared.confirmed.values(),
          ...(await run.driver.localOperations()),
        ];
        run.canon = refProject(run.canon, worldOf(shared, run), evidence);
        const pendingOps = [...shared.pending.values()].flatMap((b) => b.ops);
        const pendingBytes = [...shared.pending.values()].flatMap((b) =>
          b.blobs.map((n) => blobOf(n).descriptor.blobId),
        );
        const preview = refProject(
          run.canon,
          worldOf(shared, run, pendingBytes),
          [...evidence, ...pendingOps],
        );
        const snapshot = await run.driver.snapshot(UNIVERSE);
        after.push(snapshot);
        checkSnapshot(failures, base, snapshot, run.canon, preview, evidence);
        // Exact duplicate delivery and reopen change no stored fact.
        if (command && (command.k === "dup" || command.k === "reopen"))
          compare(
            failures,
            base,
            `${command.k} leaves stored rows unchanged`,
            before[i].stored,
            snapshot.stored,
          );
        // A command scoped to some connections leaves every other connection's rows as they were.
        if (touched) {
          const others = (s: PortSnapshot) =>
            Object.fromEntries(
              Object.entries(s.stored).filter(
                ([id]) => !touched.has(parseRowId(id)[0]),
              ),
            );
          compare(
            failures,
            base,
            "unrelated connections unchanged",
            others(before[i]),
            others(snapshot),
          );
        }
      }
      // Ports agree on row versions and times whenever their references agree.
      const snapshots = after;
      before = after;
      for (let i = 1; i < runs.length; i++)
        if (
          canonicalJson(expectedStored(runs[i].canon)) ===
          canonicalJson(expectedStored(runs[0].canon))
        )
          compare(
            failures,
            {
              prefix,
              command,
              port: `${runs[0].driver.name}~${runs[i].driver.name}`,
            },
            "stored versions and times agree across ports",
            normalize(snapshots[0].stored),
            normalize(snapshots[i].stored),
          );
      if (!failures.length && options.freshReplay && !hasLocal && prefix > 0)
        failures.push(
          ...(await freshReplay(declared, shared, runs, prefix, command)),
        );
      if (failures.length) return failures;
    }
    return [];
  } finally {
    for (const driver of opened) driver.close();
  }
}

/**
 * Connections a command may change. An import also reaches every connection
 * whose retained operation shares a revision id with it (equivocation).
 */
function touchedConnections(
  command: Command | null,
  shared: Shared,
): Set<string> | undefined {
  if (!command) return undefined;
  if (command.k === "import") {
    const ids = new Set(command.ops.map(revisionId));
    return new Set([
      ...command.ops.map((op) => op.connectionId),
      ...[...shared.confirmed.values()]
        .filter((op) => ids.has(revisionId(op)))
        .map((op) => op.connectionId),
    ]);
  }
  if (
    command.k === "local" ||
    command.k === "quarantine" ||
    command.k === "provision"
  )
    return new Set([command.connection]);
  return undefined;
}

async function apply(
  command: Command,
  shared: Shared,
  runs: PortRun[],
  journals: ReplicaOperation[][],
  failures: Failure[],
  prefix: number,
) {
  const each = async (fn: (run: PortRun, i: number) => Promise<void>) => {
    for (const [i, run] of runs.entries()) await fn(run, i);
  };
  const expectOutcome = (
    run: PortRun,
    label: string,
    admissible: boolean,
    error: string | undefined,
  ) => {
    if (admissible !== (error === undefined))
      failures.push({
        prefix,
        command,
        port: run.driver.name,
        check: `${label} ${admissible ? "accepted" : "refused"}`,
        expected: admissible ? "accepted" : "refused",
        actual: error ?? "accepted",
      });
  };
  const payloads = (names: string[]): BlobPayload[] => names.map(blobOf);
  switch (command.k) {
    case "import":
    case "dup":
    case "bytes": {
      const batch =
        command.k === "import"
          ? { ops: command.ops, blobs: command.blobs }
          : shared.batches.get(command.id);
      // A shrunk prerequisite or an emptied batch: nothing to send.
      if (!batch?.ops.length) return;
      if (command.k === "import") shared.batches.set(command.id, batch);
      const blobs =
        command.k === "bytes"
          ? [...new Set([...batch.blobs, ...missingBlobs(batch.ops)])]
          : batch.blobs;
      let admitted = true;
      await each(async (run) => {
        const admissible = batchAdmissible(run, batch.ops);
        admitted &&= admissible;
        expectOutcome(
          run,
          "batch",
          admissible,
          await attempt(() =>
            run.driver.importBatch(command.id, batch.ops, payloads(blobs)),
          ),
        );
      });
      if (admitted) {
        for (const op of batch.ops) shared.confirmed.set(canonicalJson(op), op);
        for (const name of blobs)
          shared.bytes.add(blobOf(name).descriptor.blobId);
      }
      return;
    }
    case "declare":
      shared.declared.add(command.binding);
      await each(async (run) =>
        run.driver.declare([...shared.declared].map((b) => BINDINGS[b])),
      );
      return;
    case "retry":
      await each(async (run) => run.driver.retry());
      return;
    case "reopen":
      await each(async (run) => run.driver.reopen());
      return;
    case "quarantine":
      shared.terminal.add(command.connection);
      await each(async (run) => {
        if (run.mappings.has(command.connection))
          await run.driver.quarantineConnection(command.connection);
      });
      return;
    case "provision":
      await each(async (run) => {
        const conflicting = [...shared.confirmed.values()].some(
          (op) =>
            op.connectionId === command.connection &&
            (op.sourceId !== SOURCE || op.methodId !== METHOD),
        );
        const ok = await run.driver.provision(command.connection);
        if (ok)
          run.mappings.set(command.connection, {
            sourceId: SOURCE,
            methodId: METHOD,
          });
        if (ok === conflicting && !run.driver.name.startsWith("node"))
          failures.push({
            prefix,
            command,
            port: run.driver.name,
            check:
              "provisioning refused exactly when retained evidence disagrees",
            expected: !conflicting,
            actual: ok,
          });
      });
      return;
    case "local":
      await each(async (run, i) => {
        const binding = BINDINGS[command.binding];
        const evidence = [...shared.confirmed.values(), ...journals[i]];
        const world = worldOf(shared, run);
        const { generation } = refConnectionStatus(
          world,
          evidence,
          command.connection,
        );
        const data = { id: command.key, text: command.text };
        const op = {
          owner: OWNER,
          sourceId: SOURCE,
          connectionId: command.connection,
          methodId: METHOD,
          generation,
          kind: "upsert" as const,
          declaration: binding,
          recordKey: command.key,
          emittedAt: "2026-10-22T00:00:00Z",
          data,
          blobs: [],
          revision: { counter: 1, writerId: "probe", operationId: "probe" },
        };
        const admissible = refLocalWritable(world, evidence, op);
        const before = await run.driver.snapshot(UNIVERSE);
        const error = await attempt(() =>
          run.driver.local({
            requestId: command.id,
            connection: command.connection,
            generation,
            binding,
            key: command.key,
            data,
            emittedAt: op.emittedAt,
          }),
        );
        expectOutcome(run, "local write", admissible, error);
        const after = await run.driver.localOperations();
        const added = after.slice(journals[i].length);
        if (error !== undefined) {
          if (
            added.length ||
            canonicalJson(before.stored) !==
              canonicalJson((await run.driver.snapshot(UNIVERSE)).stored)
          )
            failures.push({
              prefix,
              command,
              port: run.driver.name,
              check: "refused local write leaves journal and rows unchanged",
              expected: { journal: journals[i].length, stored: before.stored },
              actual: {
                journal: after.length,
                stored: (await run.driver.snapshot(UNIVERSE)).stored,
              },
            });
          return;
        }
        const id = JSON.stringify([
          command.connection,
          binding.stream,
          command.key,
        ]);
        const prior = before.stored[id];
        const unchanged =
          prior &&
          !prior.deleted &&
          (canonicalJson(prior.data) === canonicalJson(data) ||
            binding.semantics === "append_only");
        const journaled = added.filter((o) => o.kind === "upsert");
        if (!(
          (journaled.length === 1 &&
            journaled[0].kind === "upsert" &&
            canonicalJson(journaled[0].data) === canonicalJson(data) &&
            journaled[0].connectionId === command.connection &&
            journaled[0].generation === generation) ||
          (journaled.length === 0 && unchanged)
        ))
          failures.push({
            prefix,
            command,
            port: run.driver.name,
            check: "accepted local write journals exactly its operation",
            expected: unchanged
              ? "no operation (unchanged)"
              : { data, generation },
            actual: added,
          });
      });
      return;
    case "stage": {
      if (!command.ops.length) return;
      // Platform difference: Lite refuses pending bytes without a claim in
      // the same batch, Node accepts and ignores them. Send claimed bytes only.
      const blobs = command.blobs.filter((name) =>
        command.ops.some(
          (op) =>
            op.kind === "blob-claim" &&
            op.blob.blobId === blobOf(name).descriptor.blobId,
        ),
      );
      shared.pending.set(command.id, { ops: command.ops, blobs });
      await each(async (run) => {
        const admissible = batchAdmissible(run, command.ops);
        const error = await attempt(() =>
          run.driver.stage(command.id, command.ops, payloads(blobs)),
        );
        expectOutcome(run, "pending batch", admissible, error);
        if (!admissible) shared.pending.delete(command.id);
      });
      return;
    }
    case "promote":
    case "drop": {
      const batch = shared.pending.get(command.id);
      if (!batch) return;
      shared.pending.delete(command.id);
      await each(async (run) => {
        const error = await attempt(() =>
          command.k === "promote"
            ? run.driver.promote(command.id)
            : run.driver.dropPending(command.id),
        );
        expectOutcome(run, command.k, true, error);
      });
      if (command.k === "promote") {
        for (const op of batch.ops) shared.confirmed.set(canonicalJson(op), op);
        for (const name of batch.blobs)
          shared.bytes.add(blobOf(name).descriptor.blobId);
      }
      return;
    }
  }
}

function missingBlobs(ops: readonly ReplicaOperation[]): string[] {
  const names: string[] = [];
  for (const op of ops)
    if (op.kind === "blob-claim") {
      const name = BLOB_NAMES.find(
        (n) => blobOf(n).descriptor.blobId === op.blob.blobId,
      );
      if (name) names.push(name);
    }
  return names;
}

/**
 * Replay the prefix's retained facts into fresh stores in one delivery, then
 * the terminal facts and the active pending batches. The reference follows
 * the same steps, so a port that kept stale incremental state disagrees.
 */
async function freshReplay(
  initialDeclared: BindingName[],
  shared: Shared,
  runs: PortRun[],
  prefix: number,
  command: Command | null,
): Promise<Failure[]> {
  const failures: Failure[] = [];
  // A baseline takes one declaration per stream, so later versions arrive
  // through `declare`, as on the live path.
  const initial = initialDeclared.map((b) => BINDINGS[b]);
  const declared = [...shared.declared].map((b) => BINDINGS[b]);
  const mappings = runs[0].mappings;
  const provisioned = [...mappings.keys()];
  const fresh: ReplicaPortDriver[] = [
    nodeDriver({ declarations: initial, provisioned }),
    await liteDriver({
      name: "lite-memory",
      persistence: liteMemoryPersistence(),
      declarations: initial,
      provisioned,
    }),
  ];
  try {
    for (const driver of fresh)
      if (declared.length !== initial.length) await driver.declare(declared);
    const ops = [...shared.confirmed.values()];
    const blobs = BLOB_NAMES.filter((n) =>
      shared.bytes.has(blobOf(n).descriptor.blobId),
    ).map(blobOf);
    for (const driver of fresh) {
      const base = { prefix, command, port: `fresh-${driver.name}` };
      const run: PortRun = {
        driver,
        mappings: new Map(mappings),
        canon: emptyRefState(),
      };
      if (ops.length) {
        const error = await attempt(() =>
          driver.importBatch("fresh-replay", ops, blobs),
        );
        if (error) {
          failures.push({
            ...base,
            check: "fresh replay accepted",
            expected: "accepted",
            actual: error,
          });
          continue;
        }
      }
      const evidence = [...ops, ...(await driver.localOperations())];
      const terminal = shared.terminal;
      run.canon = refProject(
        run.canon,
        { ...worldOf(shared, run), terminal: new Set() },
        evidence,
      );
      for (const connection of terminal)
        if (mappings.has(connection))
          await driver.quarantineConnection(connection);
      run.canon = refProject(run.canon, worldOf(shared, run), evidence);
      for (const [id, batch] of shared.pending)
        await driver.stage(id, batch.ops, batch.blobs.map(blobOf));
      const pendingOps = [...shared.pending.values()].flatMap((b) => b.ops);
      const pendingBytes = [...shared.pending.values()].flatMap((b) =>
        b.blobs.map((n) => blobOf(n).descriptor.blobId),
      );
      const preview = refProject(
        run.canon,
        worldOf(shared, run, pendingBytes),
        [...evidence, ...pendingOps],
      );
      checkSnapshot(
        failures,
        base,
        await driver.snapshot(UNIVERSE),
        run.canon,
        preview,
        evidence,
      );
    }
  } finally {
    for (const driver of fresh) driver.close();
  }
  return failures;
}

export function formatFailure(
  seed: number | undefined,
  commands: readonly Command[],
  failures: Failure[],
) {
  const first = failures[0];
  return JSON.stringify(
    {
      seed,
      failingPrefix: first?.prefix,
      failures: failures.slice(0, 6).map((f) => ({
        port: f.port,
        check: f.check,
        command: f.command,
        expected: f.expected,
        actual: f.actual,
      })),
      minimizedCommands: commands,
    },
    null,
    1,
  );
}

import type { Database } from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { keccak256, type Hex } from "viem";
import { createHash } from "node:crypto";
import {
  binaryWriter,
  readBinaryChunks,
  deleteBinary,
  verifyBinary,
} from "./pdpp-binary-chunks.js";
import {
  encodeReplicaPayload,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
} from "@opendatalabs/personal-server-ts-core/replication/stream";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  decodeReplicaFragment,
  isReplicaScope,
  ReplicaFragmentUnsigned,
  replicaMetadataHash,
  REPLICA_MAX_BLOB_BYTES,
  REPLICA_SCOPE_PREFIX,
  type PreparedFragment,
  type ReplicaFragment,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  replicaRegistrationState,
  replicaAwaitingFinality,
  replicaRegistrationInactive,
  replicaChainCommitment,
  type ReplicaTransportPort,
  type ReplicaRegistrationEvidence,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  abortable,
  createReplicaCoordinator,
  type ReplicaAttempt,
  type ReplicaSettle,
  type ProgressReport,
  type ReplicaBudget,
  type ReplicaPhaseHandler,
  type ReplicaWorkItem,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  dependencyKey,
  outcomeReason,
  retryFromError,
  ReplicaFramingUnsupported,
  ReplicaProblemError,
  type ReplicaDependency,
  type ReplicaOutcome,
  type ReplicaPhase,
  type ReplicaPhaseOutcome,
} from "@opendatalabs/personal-server-ts-core/replication/outcome";
import { replicaCopyKey } from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { REPLICA_REFETCH_BUDGET } from "./pdpp-replica-copies.js";
import { captureWrites, replicationAdmitted } from "./pdpp-replication-door.js";
import {
  defaultReplicaBackoff,
  REPLICA_TERMINAL,
  replicaEligibleAt,
  replicaEligibleAtSql,
  type ReplicaEligibility,
  type ReplicaWorkState,
} from "@opendatalabs/personal-server-ts-core/replication/schedule";
import {
  createCachedReplicaRoster,
  type ReplicaRosterPort,
} from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  authorizeReplicaBatch,
  replicaOperationWriterRefusal,
  signReplicaBatch,
  type ReplicaAuthorityRefusal,
  type ReplicaBatchFacts,
  type ReplicaBatchSigner,
  type ReplicaEnvironment,
  type ReplicaPartition,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { REPLICA_WAIT_FALLBACK_MS } from "@opendatalabs/personal-server-ts-core/replication/schedule";
import type { ReplicationExport } from "./pdpp-replication-sqlite.js";
import {
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
  type ReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";

// One process owns a transport writer per database; other local instances serialize cycles.
const activeDatabases = new Set<Database | string>();
const ownedTokens = new Set<string>();

const migration = `
CREATE TABLE IF NOT EXISTS pdpp_transport_lock (id INTEGER PRIMARY KEY CHECK(id=1), pid INTEGER NOT NULL, token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_transport_state (
 id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, writer TEXT NOT NULL,
 baseline_cursor INTEGER NOT NULL DEFAULT 0, baseline_done INTEGER NOT NULL DEFAULT 0,
 tail_cursor INTEGER, sequence INTEGER NOT NULL DEFAULT 0, previous_json TEXT, scan_cursor TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_batches (
 batch TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL, previous_json TEXT,
 collected_at TEXT NOT NULL, digest TEXT NOT NULL, payload BLOB NOT NULL, prepared INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_outbox (
 scope TEXT PRIMARY KEY, batch TEXT NOT NULL, plaintext BLOB NOT NULL, encrypted BLOB NOT NULL,
 data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'ready',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_inbox (
 scope TEXT PRIMARY KEY, fragment_json TEXT, state TEXT NOT NULL DEFAULT 'ready',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_imported (
 writer TEXT NOT NULL, batch TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(writer,batch), UNIQUE(writer,sequence));
CREATE TABLE IF NOT EXISTS pdpp_transport_import_work (
 writer TEXT NOT NULL, batch TEXT NOT NULL, sequence INTEGER NOT NULL,
 outcome TEXT, reason TEXT, cause_json TEXT, dependency TEXT, error TEXT,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
 wait_since INTEGER, checked_block TEXT, PRIMARY KEY(writer,batch));
CREATE INDEX IF NOT EXISTS pdpp_import_work_dependency ON pdpp_transport_import_work(dependency) WHERE outcome='wait';
CREATE TABLE IF NOT EXISTS pdpp_transport_phase_state (
 phase TEXT PRIMARY KEY, outcome TEXT, reason TEXT, cause_json TEXT, dependency TEXT, error TEXT,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
 wait_since INTEGER, checked_block TEXT, fingerprint TEXT);
`;
/** Durable outcome columns shared by every per-item work table. */
const WORK_COLUMNS: [string, string][] = [
  ["outcome", "TEXT"],
  ["reason", "TEXT"],
  ["cause_json", "TEXT"],
  ["dependency", "TEXT"],
  ["wait_since", "INTEGER"],
  ["checked_block", "TEXT"],
];
type State = {
  owner: string;
  writer: string;
  baseline_cursor: number;
  baseline_done: number;
  tail_cursor: number | null;
  sequence: number;
  previous_json: string | null;
  scan_cursor: string | null;
};
type Work = {
  attempts: number;
  next_attempt: number;
  wait_since: number | null;
  checked_block: string | null;
};
type Batch = Work & {
  batch: string;
  sequence: number;
  previous_json: string | null;
  collected_at: string;
  digest: string;
  total_bytes: number;
  legacy: number;
};
type Outbox = Work & {
  scope: string;
  batch: string;
  data_hash: `0x${string}`;
  metadata_hash: `0x${string}`;
};
type Inbox = Work & {
  scope: string;
  data_hash: `0x${string}` | null;
  metadata_hash: `0x${string}` | null;
};
type Item<R> = ReplicaWorkItem & { row: R };

const workState = (row: Work): ReplicaWorkState => ({
  attempts: row.attempts,
  nextEligible: row.next_attempt,
  waitSince: row.wait_since ?? null,
  checkedBlock: row.checked_block ?? null,
});
/** Values for WORK_SET, in order. `error` keeps a closed code, never exception text. */
function workValues(outcome: ReplicaOutcome, state: ReplicaWorkState) {
  const reason = outcome.tag === "progress" ? null : outcomeReason(outcome);
  return [
    outcome.tag,
    reason,
    outcome.tag === "retry" && outcome.cause
      ? canonicalJson(outcome.cause)
      : null,
    outcome.tag === "wait" ? dependencyKey(outcome.dependency) : null,
    outcome.tag === "progress" || outcome.tag === "wait" ? null : reason,
    state.attempts,
    state.nextEligible,
    state.waitSince,
    state.checkedBlock,
  ];
}
const WORK_SET =
  "outcome=?,reason=?,cause_json=?,dependency=?,error=?,attempts=?,next_attempt=?,wait_since=?,checked_block=?";
/** Scope format: pdpp_replica_v1.<writer>_<batch>.<index>. */
const writerOfScope = (scope: string) =>
  scope.slice(
    REPLICA_SCOPE_PREFIX.length + 1,
    REPLICA_SCOPE_PREFIX.length + 33,
  );
const SCOPE_WRITER_SQL = `substr(scope,${REPLICA_SCOPE_PREFIX.length + 2},32)`;

/** The owner binding every phase runs under, validated before any phase. */
export class ReplicaAuthorityError extends Error {
  readonly code = "replica_authority_mismatch";
  constructor() {
    super("replica transport owner binding mismatch");
    this.name = "ReplicaAuthorityError";
  }
}

/** Internal experiment only. No bootstrap wiring; false by default. */
export function createReplicaTransportWorker(deps: {
  db: Database;
  enabled?: boolean;
  expected: () => EnvelopeExpectation;
  exporter: ReplicationExport;
  receiver: ReturnType<typeof createReplicaReceiver>;
  credential: unknown;
  transport: ReplicaTransportPort;
  /** Who may write (host contract §3). */
  authority: {
    /**
     * The registered PS server key: Node `key.json`, or the Lite server
     * identity. Never the owner wallet or the Lite owner sync signer.
     */
    signer: ReplicaBatchSigner;
    /**
     * The gateway roster, uncached. The worker caches each answer for at most
     * REPLICA_ROSTER_MAX_AGE_MS on its own clock.
     */
    roster: ReplicaRosterPort;
    /** EIP-712 domain chain and environment of this owner's partition. */
    chainId: number;
    environment: ReplicaEnvironment;
  };
  now?: () => number;
  maxBlobBytes?: number;
  targetChunkBytes?: number;
  pageSize?: number;
  /** Units per phase per step. Defaults keep today's per-cycle limits. */
  quantum?: Partial<Record<ReplicaPhase, number>>;
  /** Items per writer per phase per step. */
  perWriter?: number;
  /** Per-run deadline; a late result is discarded. */
  deadlineMs?: number;
  /**
   * Delay after a successful revalidation of one imported slot. The default 0
   * rechecks every imported slot round-robin on every step, so a finalized
   * conflict retracts data on the next step.
   */
  revalidateIntervalMs?: number;
  /** Completed non-matching re-downloads of a batch before the owner decides. */
  refetchBudget?: number;
}) {
  const { db, transport } = deps;
  const now = deps.now ?? Date.now;
  const roster = createCachedReplicaRoster(deps.authority.roster, { now });
  const server = deps.authority.signer.address.toLowerCase();
  const cap = deps.maxBlobBytes ?? REPLICA_MAX_BLOB_BYTES;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > REPLICA_MAX_BLOB_BYTES)
    throw new RangeError("invalid storage cap");
  db.exec(migration);
  const addColumns = (table: string, wanted: [string, string][]) => {
    const existing = new Set(
      (
        db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]
      ).map((c) => c.name),
    );
    for (const [name, type] of wanted)
      if (!existing.has(name))
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  };
  for (const table of [
    "pdpp_transport_batches",
    "pdpp_transport_outbox",
    "pdpp_transport_inbox",
  ])
    addColumns(table, WORK_COLUMNS);
  addColumns("pdpp_transport_batches", [
    ["total_bytes", "INTEGER"],
    ["admission_json", "TEXT"],
  ]);
  addColumns("pdpp_transport_import_work", [
    ["refetch_attempts", "INTEGER NOT NULL DEFAULT 0"],
  ]);
  addColumns("pdpp_transport_inbox", [
    ["data_hash", "TEXT"],
    ["metadata_hash", "TEXT"],
    ["finalized", "INTEGER NOT NULL DEFAULT 0"],
    ["evidence_checked", "INTEGER NOT NULL DEFAULT 0"],
  ]);
  db.exec(
    `CREATE TABLE IF NOT EXISTS pdpp_transport_preparing (token TEXT NOT NULL, scope TEXT NOT NULL, batch TEXT NOT NULL, plaintext BLOB NOT NULL, encrypted BLOB NOT NULL, data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL, PRIMARY KEY(token,scope));`,
  );
  // Older workers retained decoded fragments without their verified hash-pair
  // preimages. Re-download those ready rows; never infer finality from the old JSON.
  if (deps.enabled === true)
    db.prepare(
      `UPDATE pdpp_transport_inbox
      SET fragment_json=NULL,data_hash=NULL,metadata_hash=NULL,finalized=0,next_attempt=0,error=NULL
      WHERE state='ready' AND fragment_json IS NOT NULL
        AND (data_hash IS NULL OR metadata_hash IS NULL)`,
    ).run();
  deps.receiver.setPendingEnabled(deps.enabled === true);
  db.exec(
    "CREATE INDEX IF NOT EXISTS pdpp_inbox_evidence_checked ON pdpp_transport_inbox(evidence_checked) WHERE fragment_json IS NOT NULL AND state='imported'",
  );
  const enabled = () => deps.enabled === true;
  const state = () =>
    db.prepare("SELECT * FROM pdpp_transport_state WHERE id=1").get() as State;

  /**
   * One validated authority context for every phase: the expected owner, the
   * persisted binding, the transport port's owner and the writer identity's
   * owner must agree. Checked before any phase runs, so a wrong-owner reopen
   * cannot encrypt, publish or import. False, with nothing written, when the
   * replication door closed since the step began.
   */
  function authority(identity: ReplicaWriterIdentity): boolean {
    const owner = deps.expected().owner;
    return db
      .transaction(() => {
        if (!replicationAdmitted(db)) return false;
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_transport_state (id,owner,writer) VALUES (1,?,?)",
        ).run(owner, identity.transportWriter);
        const bound = state();
        if (
          bound.owner !== owner ||
          identity.seed.owner !== owner.toLowerCase() ||
          (transport.owner !== undefined &&
            transport.owner.toLowerCase() !== owner.toLowerCase())
        )
          throw new ReplicaAuthorityError();
        if (bound.writer !== identity.transportWriter) startWriter(identity);
        return true;
      })
      .immediate();
  }
  /**
   * A new writer identity (re-registration, reset or restore) starts its own
   * chain at sequence 1, and its first publication is a full current-state
   * baseline under the new writer. The old writer's unprepared batches and
   * unpublished fragments are abandoned: their operations name the old
   * operation writer, which no receiver accepts from the new one. The
   * baseline carries their effect instead, so a peer that missed any old
   * batch still converges. The same transaction switches the writer and pins
   * the baseline; a crash resumes it from its durable cursor. The rebaseline
   * is a capture, so the door's fence does not count it as a bypass.
   */
  function startWriter(identity: ReplicaWriterIdentity) {
    const baseline = captureWrites(db, () => deps.exporter.rebaseline());
    db.prepare(
      "UPDATE pdpp_transport_state SET writer=?,sequence=0,previous_json=NULL,baseline_cursor=?,baseline_done=0,tail_cursor=NULL WHERE id=1",
    ).run(identity.transportWriter, baseline?.after ?? 0);
    db.prepare("DELETE FROM pdpp_transport_batches").run();
    db.prepare(
      "UPDATE pdpp_transport_outbox SET state='abandoned' WHERE state='ready'",
    ).run();
  }
  /** This receiver's partition: its owner, chain and environment. */
  const partition = (): ReplicaPartition => ({
    owner: state().owner,
    chainId: deps.authority.chainId,
    environment: deps.authority.environment,
  });
  const factsOf = (fragment: ReplicaFragment): ReplicaBatchFacts => ({
    batch: fragment.batch,
    sequence: fragment.sequence,
    previous: fragment.previous,
    digest: fragment.digest,
    totalBytes: fragment.totalBytes,
    count: fragment.count,
  });
  /** Receiver checks 2-5 (host contract §3.4) for one fragment's statement. */
  const authorizeFragment = (fragment: ReplicaFragment, signal: AbortSignal) =>
    authorizeReplicaBatch({
      authority: fragment.authority,
      facts: factsOf(fragment),
      transportWriter: fragment.writer,
      receiver: partition(),
      roster: (address) => roster.server(address, { signal }),
    });
  const refused = (
    reason: ReplicaAuthorityRefusal,
    key: string,
  ): ReplicaPhaseOutcome => ({ tag: "quarantine", proof: { reason, key } });
  const rosterWait = (address: string): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: { kind: "roster", key: address },
  });

  /** An attempt with no durable effect besides its outcome. */
  const verdict = (outcome: ReplicaPhaseOutcome): ReplicaAttempt => ({
    outcome,
  });
  /** An attempt whose effect commits only together with its own outcome. */
  const withPlan = (
    outcome: ReplicaPhaseOutcome,
    effect: () => void,
  ): ReplicaAttempt => ({
    outcome,
    plan: () => {
      effect();
    },
  });
  /**
   * Every adapter's commit: in one transaction run this attempt's plan,
   * settle the (possibly refined) verdict and write the item's state.
   */
  const commitIn =
    <I extends ReplicaWorkItem>(
      write: (outcome: ReplicaOutcome, work: ReplicaWorkState, item: I) => void,
    ) =>
    (item: I, attempt: ReplicaAttempt, settle: ReplicaSettle): ReplicaOutcome =>
      // The receiver's own boundary: its plans read and write derived state,
      // which a transaction opened on the raw connection would not refresh.
      deps.receiver.atomically(() => {
        const settled = settle(attempt.plan?.() ?? attempt.outcome);
        write(settled.outcome, settled.state, item);
        return settled.outcome;
      });
  /** Network calls stop at the attempt's deadline or the host's abort. */
  const call = <T>(signal: AbortSignal, start: () => Promise<T>) =>
    abortable(signal, start);
  /** The coordinator's eligibility policy over a work table's columns. */
  const due = (e: ReplicaEligibility) =>
    `${replicaEligibleAtSql(e)} <= ${e.now}`;
  /** Earliest eligibility among rows of `from` (a table plus WHERE clause). */
  const earliestIn = (e: ReplicaEligibility, from: string) => {
    const row = db
      .prepare(`SELECT min(${replicaEligibleAtSql(e)}) AS next FROM ${from}`)
      .get() as { next: number | null } | undefined;
    return row?.next ?? undefined;
  };
  /**
   * Writer-fair due selection (see ReplicaPhaseHandler.due). Parameters:
   * perWriter, the writer served last ('' for none), total.
   */
  const dueWindow = (
    from: string,
    writer: string,
    order: string,
    where: string,
  ) =>
    `SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY ${writer} ORDER BY ${order}) AS writer_rank FROM ${from} WHERE ${where}) WHERE writer_rank<=? ORDER BY writer_rank, ${writer}<=?, ${writer}, ${order} LIMIT ?`;

  const finalityWait = (
    evidence: ReplicaRegistrationEvidence,
    key: string,
  ): ReplicaPhaseOutcome => ({
    tag: "wait",
    dependency: {
      kind: "finality",
      key,
      checkedBlock: String(evidence.chain!.blockNumber),
    },
  });

  // --------------------------------------------------------------- retain
  const singleton = (phase: ReplicaPhase) =>
    (db
      .prepare("SELECT * FROM pdpp_transport_phase_state WHERE phase=?")
      .get(phase) as
      | (Work & { fingerprint: string | null; outcome: string | null })
      | undefined) ?? {
      outcome: null,
      attempts: 0,
      next_attempt: 0,
      wait_since: null,
      checked_block: null,
      fingerprint: null,
    };
  function settleSingleton(
    phase: ReplicaPhase,
    outcome: ReplicaOutcome,
    work: ReplicaWorkState,
    fingerprint?: string,
  ) {
    db.prepare(
      `INSERT INTO pdpp_transport_phase_state (phase) VALUES (?) ON CONFLICT(phase) DO NOTHING`,
    ).run(phase);
    db.prepare(
      `UPDATE pdpp_transport_phase_state SET ${WORK_SET}${fingerprint === undefined ? "" : ",fingerprint=?"} WHERE phase=?`,
    ).run(
      ...workValues(outcome, work),
      ...(fingerprint === undefined ? [] : [fingerprint]),
      phase,
    );
  }
  /** A singleton phase's durable deadline, by the shared eligibility policy. */
  function singletonEligibleAt(
    row: Work & { outcome?: string | null },
    e: ReplicaEligibility,
  ) {
    return replicaEligibleAt(
      {
        finalityWait: false,
        nextEligible: row.next_attempt,
        waitSince: row.wait_since,
        checkedBlock: row.checked_block,
      },
      e,
    );
  }
  /** Only an outstanding Retry or Wait of a singleton is a deadline. */
  function singletonDeadline(phase: ReplicaPhase, e: ReplicaEligibility) {
    const row = singleton(phase);
    return row.outcome === "retry" || row.outcome === "wait"
      ? singletonEligibleAt(row, e)
      : undefined;
  }
  /** The local export has operations not yet retained. One indexed probe. */
  function tailPending() {
    const s = state();
    return (
      !s.baseline_done ||
      deps.exporter.readTailPage({
        limit: 1,
        ...(s.tail_cursor === null ? {} : { afterSequence: s.tail_cursor }),
      }).operations.length > 0
    );
  }
  const retain: ReplicaPhaseHandler<Item<Work>> = {
    phase: "retain",
    due(e) {
      const row = singleton("retain");
      const at = singletonEligibleAt(row, e);
      if (at === undefined || at > e.now) return [];
      // An idle tail costs one indexed probe and no budget unit.
      if (!tailPending()) return [];
      return [
        {
          id: "retain",
          phase: "retain",
          writer: "",
          state: workState(row),
          row,
        },
      ];
    },
    async run() {
      const s = state();
      const options = { limit: deps.pageSize ?? 50 };
      const page = s.baseline_done
        ? deps.exporter.readTailPage({
            ...options,
            ...(s.tail_cursor === null ? {} : { afterSequence: s.tail_cursor }),
          })
        : deps.exporter.readBaselinePage({
            ...options,
            afterSequence: s.baseline_cursor,
          });
      const batch = randomUUID().replaceAll("-", "");
      let digest = "",
        totalBytes = 0;
      try {
        if (page.operations.length) {
          const envelope: ReplicaEnvelope = {
            format: "vana-pdpp-replica",
            version: 1,
            owner: s.owner,
            batchId: batch,
            operations: page.operations,
          };
          decodeReplicaEnvelope(canonicalJson(envelope), deps.expected());
          const writer = binaryWriter(db, "payload", batch);
          const hash = createHash("sha256");
          for await (const bytes of encodeReplicaPayload(
            envelope,
            async function* (id) {
              yield* deps.exporter.readPinnedBlobChunks(id);
            },
          )) {
            db.transaction(() => writer.write(bytes))();
            hash.update(bytes);
            totalBytes += bytes.length;
          }
          writer.finish();
          digest = `sha256:${hash.digest("hex")}`;
        }
      } catch (error) {
        deleteBinary(db, "payload", batch);
        throw new ReplicaProblemError("retain_failed", { cause: error });
      }
      // Queue + export cursor commit together with the phase outcome. They
      // acknowledge durable local responsibility, not publication.
      return withPlan(
        { tag: "progress", receipt: { phase: "retain", key: batch } },
        () => {
          const current = state();
          if (
            current.sequence !== s.sequence ||
            current.baseline_cursor !== s.baseline_cursor ||
            current.baseline_done !== s.baseline_done ||
            current.tail_cursor !== s.tail_cursor
          )
            throw new ReplicaProblemError("retain_failed");
          if (page.operations.length) {
            if (!verifyBinary(db, "payload", batch, digest, totalBytes))
              throw new ReplicaProblemError("retain_failed");
            db.prepare(
              "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,payload,total_bytes) VALUES (?,?,?,?,?,?,?)",
            ).run(
              batch,
              s.sequence + 1,
              s.previous_json,
              new Date(now()).toISOString(),
              digest,
              new Uint8Array(),
              totalBytes,
            );
            db.prepare(
              "UPDATE pdpp_transport_state SET sequence=?, previous_json=? WHERE id=1",
            ).run(s.sequence + 1, canonicalJson({ batch, digest }));
          }
          if (!s.baseline_done) {
            deps.exporter.acknowledgeBaselinePage(
              deps.exporter.getBaselineCheckpoint(),
              page.nextAfterSequence,
            );
            db.prepare(
              "UPDATE pdpp_transport_state SET baseline_cursor=?, baseline_done=? WHERE id=1",
            ).run(page.nextAfterSequence, page.hasMore ? 0 : 1);
          } else
            db.prepare(
              "UPDATE pdpp_transport_state SET tail_cursor=? WHERE id=1",
            ).run(page.nextAfterSequence);
        },
      );
    },
    commit: commitIn((outcome, work) => {
      settleSingleton("retain", outcome, work);
    }),
    commitProblem: "retain_failed",
    earliest(e) {
      return (
        singletonDeadline("retain", e) ?? (tailPending() ? e.now : undefined)
      );
    },
  };

  // -------------------------------------------------------------- prepare
  async function* payloadBytes(batch: Batch): AsyncIterable<Uint8Array> {
    if (!batch.legacy) {
      yield* readBinaryChunks(db, "payload", batch.batch);
      return;
    }
    // Durable batches retained by older workers remain retryable.
    const row = db
      .prepare("SELECT payload FROM pdpp_transport_batches WHERE batch=?")
      .get(batch.batch) as { payload: Buffer };
    for (let offset = 0; offset < row.payload.length; offset += 64 * 1024)
      yield row.payload.subarray(offset, offset + 64 * 1024);
  }
  const prepare: ReplicaPhaseHandler<Item<Batch>> = {
    phase: "prepare",
    due(e, limit) {
      return (
        db
          .prepare(
            `SELECT batch,sequence,previous_json,collected_at,digest,attempts,next_attempt,wait_since,checked_block,coalesce(total_bytes,length(payload)) AS total_bytes,total_bytes IS NULL AS legacy FROM pdpp_transport_batches WHERE prepared=0 AND ${due(e)} ORDER BY next_attempt,sequence LIMIT ?`,
          )
          .all(limit.total) as Batch[]
      ).map((row) => ({
        id: row.batch,
        phase: "prepare",
        writer: "",
        state: workState(row),
        bytes: row.total_bytes,
        row,
      }));
    },
    async run(item, signal) {
      const batch = item.row;
      const token = randomUUID();
      const s = state();
      const identity = currentReplicaWriterIdentity(db);
      let chunkBytes = deps.targetChunkBytes ?? 4 * 1024 * 1024;
      let preparedCount = 0;
      try {
        // Batches belong to the current writer; startWriter drops older ones.
        if (identity?.transportWriter !== s.writer)
          throw new ReplicaProblemError("prepare_failed");
        while (true) {
          try {
            preparedCount = 0;
            for await (const part of fragmentReplicaStream({
              owner: s.owner,
              writer: s.writer,
              batch: batch.batch,
              sequence: batch.sequence,
              previous: batch.previous_json
                ? (JSON.parse(batch.previous_json) as Predecessor)
                : null,
              collectedAt: batch.collected_at,
              digest: batch.digest,
              totalBytes: batch.total_bytes,
              bytes: () => payloadBytes(batch),
              sign: (facts) =>
                signReplicaBatch({
                  signer: deps.authority.signer,
                  partition: partition(),
                  seed: identity.seed,
                  facts,
                }),
              encrypt: (scope, bytes) =>
                call(signal, () => transport.encrypt(scope, bytes)),
              maxBlobBytes: cap,
              targetChunkBytes: chunkBytes,
            })) {
              preparedCount++;
              db.prepare(
                "INSERT INTO pdpp_transport_preparing VALUES (?,?,?,?,?,?,?)",
              ).run(
                token,
                part.scope,
                batch.batch,
                part.plaintext,
                part.encrypted,
                part.dataHash,
                part.metadataHash,
              );
            }
            break;
          } catch (error) {
            db.prepare(
              "DELETE FROM pdpp_transport_preparing WHERE token=?",
            ).run(token);
            // Only the typed, measured framing failure narrows the chunk size or
            // becomes Unsupported. Every other error is a transient Retry.
            // Unsupported is terminal for this batch only: later batches of
            // this writer still prepare and publish, and a remote importer
            // holds them as Wait(predecessor) until an explicit
            // readmitUnsupported() under a new capability publishes it.
            if (!(error instanceof ReplicaFramingUnsupported)) throw error;
            if (error.dimension === "fragment_bytes" && chunkBytes > 1) {
              chunkBytes = Math.max(1, Math.floor(chunkBytes / 2));
              continue;
            }
            return withPlan(
              {
                tag: "unsupported",
                admission: {
                  reason: "replica_framing_unsupported",
                  actual: error.actual,
                  limit: error.limit,
                  capability:
                    error.dimension === "fragment_bytes"
                      ? `cap:${cap}`
                      : `fragments:${error.limit}`,
                },
              },
              () =>
                db
                  .prepare(
                    "UPDATE pdpp_transport_batches SET prepared=-1,admission_json=? WHERE batch=?",
                  )
                  .run(
                    canonicalJson({
                      actual: error.actual,
                      limit: error.limit,
                      capability:
                        error.dimension === "fragment_bytes"
                          ? `cap:${cap}`
                          : `fragments:${error.limit}`,
                    }),
                    batch.batch,
                  ),
            );
          }
        }
      } catch (error) {
        db.prepare("DELETE FROM pdpp_transport_preparing WHERE token=?").run(
          token,
        );
        return verdict(retryFromError(error, "prepare_failed"));
      }
      return withPlan(
        { tag: "progress", receipt: { phase: "prepare", key: batch.batch } },
        () => {
          const current = db
            .prepare(
              "SELECT prepared FROM pdpp_transport_batches WHERE batch=?",
            )
            .get(batch.batch) as { prepared: number };
          // Concurrent preparation may choose different randomized ciphertext.
          // Only the first committed bytes can go on wire.
          if (!current.prepared) {
            const retained = db
              .prepare(
                "SELECT count(*) AS count FROM pdpp_transport_preparing WHERE token=?",
              )
              .get(token) as { count: number };
            if (
              retained.count !== preparedCount ||
              preparedCount !== Math.ceil(batch.total_bytes / chunkBytes)
            )
              throw new ReplicaProblemError("prepare_failed");
            db.prepare(
              "INSERT INTO pdpp_transport_outbox (scope,batch,plaintext,encrypted,data_hash,metadata_hash) SELECT scope,batch,plaintext,encrypted,data_hash,metadata_hash FROM pdpp_transport_preparing WHERE token=?",
            ).run(token);
            db.prepare(
              "UPDATE pdpp_transport_batches SET prepared=1 WHERE batch=?",
            ).run(batch.batch);
          }
          db.prepare("DELETE FROM pdpp_transport_preparing WHERE token=?").run(
            token,
          );
        },
      );
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_batches SET ${WORK_SET} WHERE batch=?`,
      ).run(...workValues(outcome, work), item.id);
    }),
    commitProblem: "prepare_failed",
    earliest(e) {
      return earliestIn(e, "pdpp_transport_batches WHERE prepared=0");
    },
  };

  // -------------------------------------------------------------- publish
  const publish: ReplicaPhaseHandler<Item<Outbox>> = {
    phase: "publish",
    due(e, limit) {
      // Parked waits are filtered before LIMIT so they cannot hide fresh or error work.
      return (
        db
          .prepare(
            dueWindow(
              `(SELECT rowid AS position,scope,batch,data_hash,metadata_hash,attempts,next_attempt,wait_since,checked_block,outcome,dependency FROM pdpp_transport_outbox WHERE state='ready')`,
              "batch",
              "next_attempt,position",
              due(e),
            ),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Outbox[]
      ).map((row) => ({
        id: row.scope,
        phase: "publish",
        // Local batches take turns like remote writers do.
        writer: row.batch,
        state: workState(row),
        row,
      }));
    },
    async run(item, signal) {
      const row = item.row;
      const expected = {
        owner: state().owner,
        scope: row.scope,
        dataHash: row.data_hash,
        metadataHash: row.metadata_hash,
      };
      try {
        let evidence = await call(signal, () => transport.evidence(row.scope));
        let status = replicaRegistrationState(evidence, expected);
        if (status === "absent") {
          const bytes = db
            .prepare(
              "SELECT plaintext,encrypted FROM pdpp_transport_outbox WHERE scope=?",
            )
            .get(row.scope) as { plaintext: Buffer; encrypted: Buffer };
          const part: PreparedFragment = {
            scope: row.scope,
            plaintext: bytes.plaintext,
            encrypted: bytes.encrypted,
            dataHash: row.data_hash,
            metadataHash: row.metadata_hash,
          };
          await call(signal, () => transport.put(part));
          await call(signal, () => transport.register(part));
          evidence = await call(signal, () => transport.evidence(row.scope));
          status = replicaRegistrationState(evidence, expected);
        }
        if (status === "conflict")
          return verdict({
            tag: "quarantine",
            proof: {
              reason: "immutable_registration_conflict",
              key: row.scope,
            },
          });
        if (status === "confirmed")
          return verdict({
            tag: "progress",
            receipt: { phase: "publish", key: row.scope },
          });
        if (
          replicaAwaitingFinality(evidence, expected) ||
          replicaRegistrationInactive(evidence, expected)
        )
          return verdict(finalityWait(evidence, row.scope));
        return verdict({ tag: "retry", problem: "registration_unconfirmed" });
      } catch (error) {
        return verdict(retryFromError(error, "publish_failed"));
      }
    },
    commit: (item, attempt, settle) =>
      commitIn((outcome, work) =>
        db
          .prepare(
            `UPDATE pdpp_transport_outbox SET ${WORK_SET},state=? WHERE scope=?`,
          )
          .run(
            ...workValues(outcome, work),
            outcome.tag === "progress"
              ? "published"
              : outcome.tag === "quarantine"
                ? "quarantined"
                : "ready",
            item.id,
          ),
      )(item, attempt, settle),
    commitProblem: "publish_failed",
    earliest(e) {
      return earliestIn(e, "pdpp_transport_outbox WHERE state='ready'");
    },
  };

  // ------------------------------------------------------------- discover
  const discover: ReplicaPhaseHandler<Item<Work>> = {
    phase: "discover",
    due(e) {
      const row = singleton("discover");
      return (singletonEligibleAt(row, e) ?? Infinity) <= e.now
        ? [
            {
              id: "discover",
              phase: "discover",
              writer: "",
              state: workState(row),
              row,
            },
          ]
        : [];
    },
    async run(_item, signal) {
      let page: { scopes: string[]; cursor: string | null };
      try {
        page = await call(signal, () => transport.list(state().scan_cursor));
      } catch (error) {
        return verdict(retryFromError(error, "discovery_failed"));
      }
      // Page admissions and its cursor commit together. A null cursor restarts
      // from page one next step: no timestamp high-water mark can hide a late registration.
      return withPlan(
        {
          tag: "progress",
          receipt: { phase: "discover", key: page.cursor ?? "" },
        },
        () => {
          for (const scope of page.scopes.filter(isReplicaScope))
            db.prepare(
              "INSERT OR IGNORE INTO pdpp_transport_inbox (scope) VALUES (?)",
            ).run(scope);
          db.prepare(
            "UPDATE pdpp_transport_state SET scan_cursor=? WHERE id=1",
          ).run(page.cursor);
        },
      );
    },
    commit: commitIn((outcome, work) => {
      settleSingleton("discover", outcome, work);
    }),
    commitProblem: "discovery_failed",
    earliest(e) {
      // A polling source: only an outstanding Retry is a deadline.
      return singletonDeadline("discover", e);
    },
  };

  // ------------------------------------------------------------- download
  const inboxItem =
    (phase: ReplicaPhase) =>
    (row: Inbox): Item<Inbox> => ({
      id: row.scope,
      phase,
      writer: writerOfScope(row.scope),
      state: workState(row),
      row,
    });
  const download: ReplicaPhaseHandler<Item<Inbox>> = {
    phase: "download",
    due(e, limit) {
      return (
        db
          .prepare(
            dueWindow(
              `(SELECT rowid AS position,scope,attempts,next_attempt,wait_since,checked_block,outcome,dependency,data_hash,metadata_hash,${SCOPE_WRITER_SQL} AS writer FROM pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NULL)`,
              "writer",
              "next_attempt,position",
              due(e),
            ),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Inbox[]
      ).map(inboxItem("download"));
    },
    async run(item, signal) {
      const row = item.row;
      try {
        const evidence = await call(signal, () =>
          transport.evidence(row.scope),
        );
        const status = replicaRegistrationState(evidence, {
          owner: state().owner,
          scope: row.scope,
        });
        if (status === "conflict")
          return verdict({
            tag: "quarantine",
            proof: {
              reason: "immutable_registration_conflict",
              key: row.scope,
            },
          });
        // Gateway heads may be optimistic. They bind cheap decrypt/hash validation,
        // but only pinned finalized evidence permits canonical promotion.
        const head = evidence.head;
        if (
          !head ||
          head.owner.toLowerCase() !== state().owner.toLowerCase() ||
          head.scope !== row.scope ||
          head.version !== "1" ||
          head.deleted
        )
          return verdict({ tag: "retry", problem: "head_unavailable" });
        const encrypted = await call(signal, () => transport.get(row.scope));
        if (encrypted.length > cap)
          throw new ReplicaProblemError("download_failed");
        const plaintext = await call(signal, () =>
          transport.decrypt(row.scope, encrypted),
        );
        let fragment: ReplicaFragment | undefined;
        let collectedAt: string;
        try {
          fragment = decodeReplicaFragment(plaintext, row.scope, state().owner);
          collectedAt = fragment.collectedAt;
        } catch (error) {
          if (!(error instanceof ReplicaFragmentUnsigned)) throw error;
          collectedAt = error.collectedAt;
        }
        const dataHash = keccak256(plaintext);
        const metadataHash = replicaMetadataHash(
          row.scope,
          collectedAt,
          encrypted.length,
        );
        if (dataHash !== head.dataHash || metadataHash !== head.metadataHash)
          throw new ReplicaProblemError("commitment_mismatch");
        // Authority runs only on bytes that match the registered commitment,
        // so replacing stored ciphertext cannot get a real fragment refused.
        if (!fragment) return verdict(refused("signature_invalid", row.scope));
        const authorized = await authorizeFragment(fragment, signal);
        if (authorized.tag === "refused")
          return verdict(refused(authorized.reason, row.scope));
        if (authorized.tag === "wait")
          return verdict(rosterWait(authorized.server));
        return withPlan(
          { tag: "progress", receipt: { phase: "download", key: row.scope } },
          () =>
            db
              .prepare(
                "UPDATE pdpp_transport_inbox SET fragment_json=?,data_hash=?,metadata_hash=? WHERE scope=?",
              )
              .run(canonicalJson(fragment), dataHash, metadataHash, row.scope),
        );
      } catch (error) {
        // Network and unavailable bytes are retryable; authenticated malformed bytes back off.
        return verdict(retryFromError(error, "download_failed"));
      }
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_inbox SET ${WORK_SET},state=? WHERE scope=?`,
      ).run(
        ...workValues(outcome, work),
        outcome.tag === "quarantine" ? "quarantined" : "ready",
        item.id,
      );
    }),
    commitProblem: "download_failed",
    earliest(e) {
      return earliestIn(
        e,
        "pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NULL",
      );
    },
  };

  // ---------------------------------------------- confirm (finality refresh)
  const batchOfScope = (scope: string) => {
    const row = db
      .prepare(
        "SELECT json_extract(fragment_json,'$.writer') AS writer, json_extract(fragment_json,'$.batch') AS batch FROM pdpp_transport_inbox WHERE scope=?",
      )
      .get(scope) as
      { writer: string | null; batch: string | null } | undefined;
    return row?.writer && row.batch
      ? { writer: row.writer, batch: row.batch }
      : undefined;
  };
  /** Make matching waits due now. Durable: survives a lost notification. */
  function wake(key: string, at: number) {
    return db
      .prepare(
        "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND dependency=? AND next_attempt>?",
      )
      .run(at, key, at).changes;
  }
  const confirm: ReplicaPhaseHandler<Item<Inbox>> = {
    phase: "confirm",
    due(e, limit) {
      // Metadata only: retained fragment bodies stay in SQLite.
      return (
        db
          .prepare(
            dueWindow(
              `(SELECT rowid AS position,scope,attempts,next_attempt,wait_since,checked_block,outcome,dependency,data_hash,metadata_hash,${SCOPE_WRITER_SQL} AS writer FROM pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NOT NULL AND finalized=0)`,
              "writer",
              "next_attempt,position",
              due(e),
            ),
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Inbox[]
      ).map(inboxItem("confirm"));
    },
    async run(item, signal) {
      // Only unfinalized fragments are selected: finalized evidence for a slot
      // does not change, and revalidation covers imported slots.
      const row = item.row;
      try {
        const evidence = await call(signal, () =>
          transport.evidence(row.scope),
        );
        const expected = {
          owner: state().owner,
          scope: row.scope,
          dataHash: row.data_hash ?? undefined,
          metadataHash: row.metadata_hash ?? undefined,
        };
        const status = replicaRegistrationState(evidence, expected);
        const record = factOf(row.scope, evidence);
        // A finalized fact that disagrees with this fragment (or a version
        // above one) is final for the slot. The batch's copy decision, not
        // this phase, chooses refetch, owner or terminal.
        if (
          (status === "confirmed" || status === "conflict") &&
          row.data_hash !== null &&
          row.metadata_hash !== null
        ) {
          const of = batchOfScope(row.scope);
          return withPlan(
            { tag: "progress", receipt: { phase: "confirm", key: row.scope } },
            () => {
              record?.();
              db.prepare(
                "UPDATE pdpp_transport_inbox SET finalized=1 WHERE scope=?",
              ).run(row.scope);
              if (of) wake(`fragments:${of.writer}:${of.batch}`, now());
            },
          );
        }
        const waiting =
          replicaAwaitingFinality(evidence, expected) ||
          replicaRegistrationInactive(evidence, expected)
            ? finalityWait(evidence, row.scope)
            : ({
                tag: "retry",
                problem: "registration_unconfirmed",
              } as const);
        return record
          ? withPlan(waiting, () => {
              record();
            })
          : verdict(waiting);
      } catch (error) {
        // A hint never shortens this error backoff (see hintAllowsSql).
        return verdict(retryFromError(error, "evidence_unavailable"));
      }
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        `UPDATE pdpp_transport_inbox SET ${WORK_SET},state=? WHERE scope=?`,
      ).run(
        ...workValues(outcome, work),
        outcome.tag === "quarantine" ? "quarantined" : "ready",
        item.id,
      );
    }),
    commitProblem: "evidence_unavailable",
    earliest(e) {
      return earliestIn(
        e,
        "pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NOT NULL AND finalized=0",
      );
    },
  };

  // ----------------------------------------- revalidate (imported slots)
  /** Ordered retained fragments of one complete batch, read one row at a time. */
  function retainedBytes(writer: string, batch: string) {
    const scopes = db
      .prepare(
        `SELECT scope FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND json_extract(fragment_json,'$.writer')=? AND json_extract(fragment_json,'$.batch')=? ORDER BY json_extract(fragment_json,'$.index')`,
      )
      .all(writer, batch) as { scope: string }[];
    return () =>
      assembleReplicaStream(async function* () {
        for (const { scope } of scopes)
          yield JSON.parse(
            (
              db
                .prepare(
                  "SELECT fragment_json FROM pdpp_transport_inbox WHERE scope=?",
                )
                .get(scope) as { fragment_json: string }
            ).fragment_json,
          ) as ReplicaFragment;
      });
  }
  /** Retract an imported batch's identities after a proven finalized conflict. */
  async function quarantineRetained(scope: string) {
    const fragment = JSON.parse(
      (
        db
          .prepare(
            "SELECT fragment_json FROM pdpp_transport_inbox WHERE scope=?",
          )
          .get(scope) as { fragment_json: string }
      ).fragment_json,
    ) as ReplicaFragment;
    const entries = db
      .prepare(
        "SELECT scope FROM pdpp_transport_inbox WHERE json_extract(fragment_json,'$.writer')=? AND json_extract(fragment_json,'$.batch')=?",
      )
      .all(fragment.writer, fragment.batch) as { scope: string }[];
    // A partially downloaded batch has never authorized canonical data. A
    // complete retained batch lets the receiver retract only its identities.
    // Retraction needs the authenticated envelope, not current declaration admission.
    const payload =
      entries.length === fragment.count
        ? await inspectReplicaPayload(
            retainedBytes(fragment.writer, fragment.batch),
            undefined,
          )
        : undefined;
    if (payload && payload.envelope.batchId !== fragment.batch)
      throw new ReplicaProblemError("payload_invalid");
    return () => {
      if (payload)
        deps.receiver.quarantineImported({
          credential: deps.credential,
          envelope: payload.envelope,
        });
      for (const entry of entries)
        db.prepare(
          "UPDATE pdpp_transport_inbox SET state='quarantined',outcome='quarantine',reason='immutable_registration_conflict',error='immutable_registration_conflict' WHERE scope=?",
        ).run(entry.scope);
    };
  }
  /**
   * A finalized fact disagrees with an imported slot. A copy-backed batch
   * records the fact and takes the copy decision, which is terminal for a
   * disproved promoted copy (contract A, H). A batch imported before copies
   * existed retracts its identities as before.
   */
  async function importedConflict(
    scope: string,
    evidence: ReplicaRegistrationEvidence,
  ): Promise<ReplicaAttempt> {
    const header = db
      .prepare(
        "SELECT json_extract(fragment_json,'$.writer') AS writer, json_extract(fragment_json,'$.batch') AS batch, json_extract(fragment_json,'$.sequence') AS sequence FROM pdpp_transport_inbox WHERE scope=?",
      )
      .get(scope) as { writer: string; batch: string; sequence: number };
    const id = canonicalJson([header.writer, header.batch]);
    const legacy: ReplicaPhaseOutcome = {
      tag: "quarantine",
      proof: { reason: "immutable_registration_conflict", key: scope },
    };
    if (!deps.receiver.copies.list(id).length)
      return withPlan(legacy, await quarantineRetained(scope));
    const record = factOf(scope, evidence);
    return {
      outcome: legacy,
      plan: () => {
        record?.();
        const decision = deps.receiver.copies.decide(id, {
          attempts: 0,
          budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
        });
        if (decision.kind !== "terminal")
          return { tag: "retry", problem: "commitment_mismatch" };
        deps.receiver.copies.apply({
          credential: deps.credential,
          id,
          decision,
        });
        quarantineWriterFrom(header.writer, header.sequence);
        return {
          tag: "quarantine",
          proof: { reason: "finalized_conflict", key: id },
        };
      },
    };
  }
  const revalidate: ReplicaPhaseHandler<Item<Inbox>> = {
    phase: "revalidate",
    due(e, limit) {
      // Round-robin by last check, so a fixed prefix cannot starve later slots.
      return (
        db
          .prepare(
            `SELECT scope,attempts,next_attempt,wait_since,checked_block,data_hash,metadata_hash FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='imported' AND ${due(e)} ORDER BY evidence_checked,rowid LIMIT ?`,
          )
          .all(limit.total) as Inbox[]
      ).map(inboxItem("revalidate"));
    },
    async run(item, signal) {
      const row = item.row;
      try {
        // A preceding sibling may already have quarantined this batch.
        const current = db
          .prepare("SELECT state FROM pdpp_transport_inbox WHERE scope=?")
          .get(row.scope) as { state: string };
        if (current.state === "quarantined")
          return verdict({
            tag: "quarantine",
            proof: {
              reason: "immutable_registration_conflict",
              key: row.scope,
            },
          });
        const evidence = await call(signal, () =>
          transport.evidence(row.scope),
        );
        const status = replicaRegistrationState(evidence, {
          owner: state().owner,
          scope: row.scope,
          ...(row.data_hash &&
            row.metadata_hash && {
              dataHash: row.data_hash,
              metadataHash: row.metadata_hash,
            }),
        });
        if (status === "conflict") return importedConflict(row.scope, evidence);
        const checked = {
          tag: "progress" as const,
          receipt: { phase: "revalidate" as const, key: row.scope },
        };
        // Only a confirmed check is Progress. Unavailable or inactive evidence
        // is not a successful check (an imported slot stays visible meanwhile).
        if (status !== "confirmed") {
          const expected = {
            owner: state().owner,
            scope: row.scope,
            dataHash: row.data_hash ?? undefined,
            metadataHash: row.metadata_hash ?? undefined,
          };
          return verdict(
            replicaRegistrationInactive(evidence, expected)
              ? finalityWait(evidence, row.scope)
              : { tag: "retry", problem: "evidence_unavailable" },
          );
        }
        if (row.data_hash && row.metadata_hash) return verdict(checked);
        // Upgrade legacy retained rows only after downloading the exact retained
        // fragment and verifying its hash-pair against finalized evidence.
        const encrypted = await call(signal, () => transport.get(row.scope));
        if (encrypted.length > cap)
          throw new ReplicaProblemError("download_failed");
        const plaintext = await call(signal, () =>
          transport.decrypt(row.scope, encrypted),
        );
        const fragment = decodeReplicaFragment(
          plaintext,
          row.scope,
          state().owner,
        );
        const retained = db
          .prepare(
            "SELECT fragment_json FROM pdpp_transport_inbox WHERE scope=?",
          )
          .get(row.scope) as { fragment_json: string };
        if (canonicalJson(fragment) !== retained.fragment_json)
          throw new ReplicaProblemError("commitment_mismatch");
        const dataHash = keccak256(plaintext);
        const metadataHash = replicaMetadataHash(
          row.scope,
          fragment.collectedAt,
          encrypted.length,
        );
        const pinned = replicaRegistrationState(evidence, {
          owner: state().owner,
          scope: row.scope,
          dataHash,
          metadataHash,
        });
        // The exact retained bytes disagree with the finalized commitment: the
        // legacy slot is not the registered data. Withdraw it (finding j).
        if (pinned === "conflict") return importedConflict(row.scope, evidence);
        if (pinned !== "confirmed")
          throw new ReplicaProblemError("commitment_mismatch");
        return withPlan(checked, () =>
          db
            .prepare(
              "UPDATE pdpp_transport_inbox SET data_hash=?,metadata_hash=? WHERE scope=?",
            )
            .run(dataHash, metadataHash, row.scope),
        );
      } catch (error) {
        return verdict(retryFromError(error, "evidence_unavailable"));
      }
    },
    commit: commitIn((outcome, work, item) => {
      const checked = (
        db
          .prepare(
            "SELECT COALESCE(MAX(evidence_checked),0) AS value FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='imported'",
          )
          .get() as { value: number }
      ).value;
      const interval = deps.revalidateIntervalMs ?? 0;
      // A revalidated slot is never terminal: it is checked again on the sweep interval.
      const next =
        outcome.tag === "progress"
          ? { ...work, nextEligible: now() + interval }
          : work;
      if (outcome.tag !== "quarantine")
        db.prepare(
          `UPDATE pdpp_transport_inbox SET ${WORK_SET},evidence_checked=? WHERE scope=?`,
        ).run(...workValues(outcome, next), checked + 1, item.id);
    }),
    commitProblem: "evidence_unavailable",
    earliest(e) {
      // A sweep on the host's cadence: only Retry and Wait are deadlines.
      return earliestIn(
        e,
        "pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='imported' AND outcome IN ('retry','wait')",
      );
    },
  };

  // --------------------------------------------------------------- import
  type Refetch = { attempts: number; budget: number };
  type ImportFragment = {
    scope: string;
    finalized: number;
    data_hash: string | null;
    metadata_hash: string | null;
  };
  /**
   * Fail closed at writer scope (contract H): every retained fragment of the
   * writer from `sequence` on leaves import and revalidation.
   */
  function quarantineWriterFrom(writer: string, sequence: number) {
    db.prepare(
      "UPDATE pdpp_transport_inbox SET state='quarantined',outcome='quarantine',reason='finalized_conflict',error='finalized_conflict' WHERE fragment_json IS NOT NULL AND json_extract(fragment_json,'$.writer')=? AND json_extract(fragment_json,'$.sequence')>=?",
    ).run(writer, sequence);
  }
  /** Durable acknowledgement of an imported batch, and its successor's wake. */
  function acknowledge(
    group: Group,
    first: ReplicaFragment,
    metadata: ImportFragment[],
  ) {
    if (
      !db
        .prepare(
          "SELECT 1 FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(group.writer, group.batch)
    )
      db.prepare("INSERT INTO pdpp_transport_imported VALUES (?,?,?,?)").run(
        group.writer,
        group.batch,
        first.sequence,
        first.digest,
      );
    for (const row of metadata)
      db.prepare(
        "UPDATE pdpp_transport_inbox SET state='imported',error=NULL WHERE scope=?",
      ).run(row.scope);
    wake(`predecessor:${group.writer}:${first.sequence}`, now());
  }
  /**
   * The copy decision for one complete download of a batch (contract v3.1
   * §3 "Coordinator step"). Runs inside the import outcome transaction, over
   * the durable copies, facts and disposition it commits with.
   */
  function decideImport(
    group: Group,
    first: ReplicaFragment,
    metadata: ImportFragment[],
    stage: ((refetch: Refetch) => void) | undefined,
  ): ReplicaPhaseOutcome {
    const { writer, batch } = group;
    const id = canonicalJson([writer, batch]);
    const key = `${writer}:${batch}`;
    const credential = deps.credential;
    db.prepare(
      "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
    ).run(writer, batch, group.sequence);
    const refetch: Refetch = {
      attempts: (
        db
          .prepare(
            "SELECT refetch_attempts FROM pdpp_transport_import_work WHERE writer=? AND batch=?",
          )
          .get(writer, batch) as { refetch_attempts: number }
      ).refetch_attempts,
      budget: deps.refetchBudget ?? REPLICA_REFETCH_BUDGET,
    };
    stage?.(refetch);
    const decision = deps.receiver.copies.decide(id, refetch);
    const terminal = (): ReplicaPhaseOutcome => {
      quarantineWriterFrom(writer, first.sequence);
      return {
        tag: "quarantine",
        proof: { reason: "finalized_conflict", key: id },
      };
    };
    const progress: ReplicaPhaseOutcome = {
      tag: "progress",
      receipt: { phase: "import", key },
    };
    switch (decision.kind) {
      case "terminal":
        deps.receiver.copies.apply({ credential, id, decision });
        return terminal();
      case "wait":
        deps.receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "fragments", key } };
      case "owner":
        deps.receiver.copies.apply({ credential, id, decision });
        return { tag: "wait", dependency: { kind: "owner", key } };
      case "refetch": {
        // One completed non-matching observation spends one unit of budget,
        // in the transaction that commits it; a discarded attempt spends none.
        deps.receiver.copies.apply({ credential, id, decision });
        db.prepare(
          "UPDATE pdpp_transport_import_work SET refetch_attempts=refetch_attempts+1 WHERE writer=? AND batch=?",
        ).run(writer, batch);
        const at = now() + defaultReplicaBackoff(refetch.attempts + 1);
        for (const row of metadata)
          db.prepare(
            "UPDATE pdpp_transport_inbox SET fragment_json=NULL,data_hash=NULL,metadata_hash=NULL,finalized=0,state='ready',outcome=NULL,reason=NULL,cause_json=NULL,dependency=NULL,error=NULL,attempts=0,next_attempt=?,wait_since=NULL,checked_block=NULL WHERE scope=?",
          ).run(at, row.scope);
        return { tag: "wait", dependency: { kind: "fragments", key } };
      }
      case "reconcile_promoted":
        deps.receiver.copies.apply({ credential, id, decision });
        acknowledge(group, first, metadata);
        return progress;
      case "promote": {
        const result = deps.receiver.copies.promote({
          credential,
          id,
          copyKey: decision.copyKey,
        });
        if (result.kind === "terminal") return terminal();
        if (result.kind === "wait_predecessor")
          return {
            tag: "wait",
            dependency: {
              kind: "predecessor",
              key: `${writer}:${first.sequence - 1}`,
            },
          };
        acknowledge(group, first, metadata);
        return progress;
      }
    }
  }
  /**
   * The verified finalized fact a scope's evidence carries (contract F2), as
   * an effect for the caller's outcome transaction. Unavailable evidence
   * (thrown) and a chain object for another owner or slot are not facts.
   * The effect returns true when the fact is new, and then wakes the batch.
   */
  function factOf(
    scope: string,
    evidence: ReplicaRegistrationEvidence,
  ): (() => boolean) | undefined {
    const chain = evidence.chain;
    const header = db
      .prepare(
        "SELECT json_extract(fragment_json,'$.writer') AS writer, json_extract(fragment_json,'$.batch') AS batch, json_extract(fragment_json,'$.index') AS position FROM pdpp_transport_inbox WHERE scope=?",
      )
      .get(scope) as
      | { writer: string | null; batch: string | null; position: number | null }
      | undefined;
    if (
      !chain ||
      !header?.writer ||
      !header.batch ||
      header.position === null ||
      chain.owner.toLowerCase() !== state().owner.toLowerCase() ||
      chain.scope !== scope ||
      chain.version !== "1" ||
      !/^(0|[1-9][0-9]*)$/.test(chain.currentVersion)
    )
      return undefined;
    const { writer, batch, position } = header;
    return () => {
      const added = deps.receiver.copies.recordFact({
        credential: deps.credential,
        id: canonicalJson([writer, batch]),
        scope,
        fragmentIndex: position,
        fact: {
          chainId: chain.chainId,
          registry: chain.registry,
          owner: chain.owner,
          currentVersion: chain.currentVersion,
          status: chain.status,
          commitment: chain.commitment,
          blockNumber: chain.blockNumber,
          blockHash: chain.blockHash,
          // Eligibility is the fact's own: Active, with a live head matching
          // the chain commitment (contract D, I).
          eligible:
            replicaRegistrationState(evidence, {
              owner: state().owner,
              scope,
            }) === "confirmed",
        },
      });
      if (added) {
        wake(`fragments:${writer}:${batch}`, now());
        wake(`owner:${writer}:${batch}`, now());
      }
      return added;
    };
  }
  type Group = Work & { writer: string; batch: string; sequence: number };
  const importRun: ReplicaPhaseHandler<Item<Group>> = {
    phase: "import",
    due(e, limit) {
      // JSON metadata only: no retained content strings from incomplete or other groups.
      return (
        db
          .prepare(
            `WITH headers AS MATERIALIZED (SELECT json_extract(fragment_json,'$.writer') AS writer, json_extract(fragment_json,'$.batch') AS batch, json_extract(fragment_json,'$.count') AS expected_count, json_extract(fragment_json,'$.sequence') AS sequence FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='ready'),
            complete AS (SELECT writer,batch,min(sequence) AS sequence FROM headers GROUP BY writer,batch HAVING count(*)=max(expected_count)),
            candidates AS (SELECT c.writer,c.batch,c.sequence,coalesce(w.attempts,0) AS attempts,coalesce(w.next_attempt,0) AS next_attempt,w.wait_since,w.checked_block FROM complete c LEFT JOIN pdpp_transport_import_work w ON w.writer=c.writer AND w.batch=c.batch WHERE w.writer IS NULL OR (${replicaEligibleAtSql(e, { outcome: "w.outcome", dependency: "w.dependency", next: "w.next_attempt", since: "w.wait_since", checked: "w.checked_block" })} <= ${e.now} AND coalesce(w.outcome,'') NOT IN ('quarantine','unsupported')))
            SELECT * FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY writer ORDER BY next_attempt,sequence,batch) AS writer_rank FROM candidates) WHERE writer_rank<=? ORDER BY writer_rank, writer<=?, writer, next_attempt, sequence, batch LIMIT ?`,
          )
          .all(limit.perWriter, limit.after ?? "", limit.total) as Group[]
      ).map((row) => ({
        id: `${row.writer}:${row.batch}`,
        phase: "import",
        writer: row.writer,
        state: workState(row),
        row,
      }));
    },
    async run(item, signal) {
      const { writer, batch } = item.row;
      const id = item.id;
      const metadata = db
        .prepare(
          `WITH headers AS MATERIALIZED (SELECT scope,finalized,data_hash,metadata_hash,json_extract(fragment_json,'$.index') AS position,json_extract(fragment_json,'$.writer') AS writer,json_extract(fragment_json,'$.batch') AS batch FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='ready') SELECT scope,finalized,data_hash,metadata_hash,position FROM headers WHERE writer=? AND batch=? ORDER BY position`,
        )
        .all(writer, batch) as ImportFragment[];
      const first = JSON.parse(
        (
          db
            .prepare(
              "SELECT fragment_json FROM pdpp_transport_inbox WHERE scope=?",
            )
            .get(metadata[0]!.scope) as { fragment_json: string }
        ).fragment_json,
      ) as ReplicaFragment;
      const pendingId = canonicalJson([writer, batch]);
      /** Terminal for this batch; the receiver drops any staged copy of it. */
      const refuse = (
        proof: { reason: ReplicaAuthorityRefusal | "batch_equivocation" },
        receiverReason: string = proof.reason,
      ) =>
        withPlan(
          { tag: "quarantine", proof: { reason: proof.reason, key: id } },
          () => {
            deps.receiver.quarantine({
              credential: deps.credential,
              id: pendingId,
              reason: receiverReason,
            });
            for (const row of metadata)
              db.prepare(
                "UPDATE pdpp_transport_inbox SET state='quarantined',error=? WHERE scope=?",
              ).run(proof.reason, row.scope);
          },
        );
      // Every import attempt asks the roster again, so a batch admitted at
      // download on an answer up to REPLICA_ROSTER_MAX_AGE_MS old is
      // revalidated before it is staged or promoted.
      const authorized = await authorizeFragment(first, signal);
      if (authorized.tag === "wait")
        return verdict(rosterWait(authorized.server));
      if (authorized.tag === "refused")
        return refuse({ reason: authorized.reason });
      const imported = db
        .prepare(
          "SELECT digest,sequence FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(writer, batch) as { digest: string; sequence: number } | undefined;
      const sequenceHolder = db
        .prepare(
          "SELECT batch FROM pdpp_transport_imported WHERE writer=? AND sequence=?",
        )
        .get(writer, first.sequence) as { batch: string } | undefined;
      // A different batch reusing an imported writer sequence (or a changed
      // digest) is proven equivocation: terminal, never a hot retry.
      if (
        (imported &&
          (imported.digest !== first.digest ||
            imported.sequence !== first.sequence)) ||
        (sequenceHolder && sequenceHolder.batch !== batch)
      )
        return refuse({ reason: "batch_equivocation" }, "batch equivocation");
      const staging: string[] = [];
      /**
       * Copy custody of this download, if its copy is not retained yet. It
       * commits only inside this attempt's outcome transaction, so a crash
       * or a discarded attempt never leaves custody without its outcome.
       */
      let stage: ((refetch: Refetch) => void) | undefined;
      const fragments = metadata.map((row) => ({
        dataHash: (row.data_hash ?? "").toLowerCase(),
        metadataHash: (row.metadata_hash ?? "").toLowerCase(),
      }));
      try {
        if (fragments.some((f) => !f.dataHash || !f.metadataHash))
          throw new ReplicaProblemError("payload_invalid");
        const copyKey = replicaCopyKey(
          fragments.map((f) =>
            replicaChainCommitment(f.dataHash as Hex, f.metadataHash as Hex),
          ),
        );
        const retained = deps.receiver.copies
          .list(pendingId)
          .some((copy) => copy.copyKey === copyKey);
        if (!retained) {
          const writers = new Map<
            number,
            { key: string; writer: ReturnType<typeof binaryWriter> }
          >();
          const payload = await inspectReplicaPayload(
            retainedBytes(writer, batch),
            undefined,
            (_blobId, chunk, blobIndex) => {
              let target = writers.get(blobIndex);
              if (!target) {
                const key = randomUUID();
                staging.push(key);
                target = { key, writer: binaryWriter(db, "staging", key) };
                writers.set(blobIndex, target);
              }
              db.transaction(() => target.writer.write(chunk))();
            },
          );
          // A discarded attempt stops before it prepares any custody.
          signal.throwIfAborted();
          if (payload.envelope.batchId !== first.batch)
            throw new ReplicaProblemError("payload_invalid");
          // Check 7: every operation names the signer's operation writer.
          const misattributed = replicaOperationWriterRefusal(
            payload.envelope.operations,
            authorized.writers,
          );
          if (misattributed) return refuse({ reason: misattributed });
          // Trusted retained declarations, never claims copied from the envelope.
          // An unknown declaration is a dependency the host can supply later.
          const expected = deps.expected();
          const missing = payload.envelope.operations.find(
            (op) =>
              "declaration" in op &&
              !expected.declarations.some(
                (entry) =>
                  entry.sourceId === op.sourceId &&
                  canonicalJson(entry.binding) ===
                    canonicalJson(op.declaration),
              ),
          );
          if (missing && "declaration" in missing)
            return verdict({
              tag: "wait",
              dependency: {
                kind: "declaration",
                key: `${missing.sourceId}:${missing.declaration.stream}`,
              },
            });
          decodeReplicaEnvelope(canonicalJson(payload.envelope), expected);
          const stagedBlobs = payload.blobs.map((blob, index) => {
            let target = writers.get(index);
            if (!target) {
              const key = randomUUID();
              staging.push(key);
              target = { key, writer: binaryWriter(db, "staging", key) };
            }
            if (target.writer.finish() !== blob.sizeBytes)
              throw new ReplicaProblemError("payload_invalid");
            return {
              blobId: blob.blobId,
              key: target.key,
              sizeBytes: blob.sizeBytes,
            };
          });
          stage = (refetch) => {
            deps.receiver.copies.stage({
              credential: deps.credential,
              copy: {
                id: pendingId,
                writer,
                batch,
                sequence: first.sequence,
                previous: first.previous,
                envelopeDigest: first.digest,
                envelope: payload.envelope,
                fragments,
              },
              stagedBlobs,
              refetch,
            });
            for (const key of staging) deleteBinary(db, "staging", key);
          };
        }
        const plan = stage;
        // The copy decision runs inside the outcome transaction, over the
        // durable copies, facts and disposition it commits with.
        return {
          outcome: {
            tag: "progress",
            receipt: { phase: "import", key: id },
          },
          plan: () => decideImport(item.row, first, metadata, plan),
        };
      } catch (error) {
        stage = undefined;
        return verdict(retryFromError(error, "import_failed"));
      } finally {
        // Without a plan to consume it, staging is scratch. A discarded
        // attempt's staging is reclaimed at the next step start.
        if (!stage) for (const key of staging) deleteBinary(db, "staging", key);
      }
    },
    commit: commitIn((outcome, work, item) => {
      db.prepare(
        "INSERT INTO pdpp_transport_import_work (writer,batch,sequence) VALUES (?,?,?) ON CONFLICT(writer,batch) DO NOTHING",
      ).run(item.row.writer, item.row.batch, item.row.sequence);
      db.prepare(
        `UPDATE pdpp_transport_import_work SET ${WORK_SET} WHERE writer=? AND batch=?`,
      ).run(...workValues(outcome, work), item.row.writer, item.row.batch);
    }),
    commitProblem: "import_failed",
    earliest(e) {
      return earliestIn(
        e,
        "pdpp_transport_import_work WHERE coalesce(outcome,'') NOT IN ('progress','quarantine','unsupported')",
      );
    },
  };

  // ----------------------------------------- reconcile (retained dependencies)
  /**
   * Durable fingerprint of what retained operations outside an import can wait
   * on: local connection mappings and trusted declarations. Two small reads,
   * never retained history. An import reconciles inside its own transaction,
   * so received operations are not part of it. A validator change that keeps
   * the declaration digest arrives as onDependencyChanged("declaration:...").
   */
  function dependencyFingerprint() {
    const bindings = db
      .prepare(
        "SELECT instance,source_id,method,generation,deleted_at FROM pdpp_instance_binding ORDER BY instance",
      )
      .all();
    const declarations = deps
      .expected()
      .declarations.map((d) => [d.sourceId, d.binding.digest, d.binding.stream])
      .sort();
    return createHash("sha256")
      .update(canonicalJson({ bindings, declarations }))
      .digest("hex");
  }
  let fingerprint = "";
  /** The first unmet dependency a reconcile reported, in a stable order. */
  function pendingDependency(
    plan: ReturnType<typeof deps.receiver.retry>,
  ): ReplicaDependency | undefined {
    const found: ReplicaDependency[] = [];
    for (const issue of plan.pending)
      for (const op of issue.operations)
        if (issue.reason === "missing_local_connection")
          found.push({ kind: "mapping", key: op.connectionId });
        else if (issue.reason === "missing_declaration" && "declaration" in op)
          found.push({
            kind: "declaration",
            key: `${op.sourceId}:${op.declaration.stream}`,
          });
        else
          found.push({
            kind: "reset",
            key: `${op.connectionId}:${op.generation}`,
          });
    return found.sort((x, y) =>
      dependencyKey(x).localeCompare(dependencyKey(y)),
    )[0];
  }
  /**
   * Canonical reconcile of retained history. It reads every retained
   * operation, so it runs only when a dependency changed: the fingerprint
   * moved, a host notification woke it, or an outstanding Wait reached its
   * bounded fallback. With nothing outstanding it is never due on a timer.
   */
  const reconcile: ReplicaPhaseHandler<Item<Work>> = {
    phase: "reconcile",
    due(e) {
      const row = singleton("reconcile");
      return row.fingerprint !== fingerprint ||
        (singletonEligibleAt(row, e) ?? Infinity) <= e.now
        ? [
            {
              id: "reconcile",
              phase: "reconcile",
              writer: "",
              state: workState(row),
              row,
            },
          ]
        : [];
    },
    async run() {
      // The canonical commit runs inside this attempt's outcome transaction:
      // the plan reconciles and returns the verdict its result implies.
      const seen = fingerprint;
      return {
        outcome: {
          tag: "progress",
          receipt: { phase: "reconcile", key: seen },
        },
        plan: () => {
          const plan = deps.receiver.retry({ credential: deps.credential });
          const dependency = pendingDependency(plan);
          return dependency ? { tag: "wait", dependency } : undefined;
        },
      };
    },
    commit: commitIn((outcome, work) =>
      settleSingleton(
        "reconcile",
        outcome,
        // With nothing outstanding it waits for a dependency change only.
        outcome.tag === "progress"
          ? { ...work, nextEligible: REPLICA_TERMINAL }
          : work,
        fingerprint,
      ),
    ),
    commitProblem: "reconcile_failed",
    earliest(e) {
      const row = singleton("reconcile");
      if (row.fingerprint !== fingerprint) return e.now;
      return singletonEligibleAt(row, e);
    },
    wake(key, at) {
      const row = singleton("reconcile");
      const outstanding = (
        db
          .prepare(
            "SELECT dependency FROM pdpp_transport_phase_state WHERE phase='reconcile'",
          )
          .get() as { dependency: string | null } | undefined
      )?.dependency;
      // A declaration notification can change validation of any retained
      // operation; other keys matter only when they are what it waits on.
      if (
        row.next_attempt <= at ||
        (!key.startsWith("declaration:") && key !== outstanding)
      )
        return 0;
      db.prepare(
        "UPDATE pdpp_transport_phase_state SET next_attempt=? WHERE phase='reconcile'",
      ).run(at);
      return 1;
    },
  };

  const coordinator = createReplicaCoordinator({
    phases: [
      retain,
      prepare,
      publish,
      discover,
      download,
      confirm,
      revalidate,
      importRun,
      reconcile,
    ] as ReplicaPhaseHandler[],
    quantum: {
      retain: 1,
      prepare: 4,
      publish: 50,
      discover: 1,
      download: 50,
      confirm: 50,
      revalidate: 50,
      import: 50,
      reconcile: 1,
      ...deps.quantum,
    },
    perWriter: deps.perWriter,
    deadlineMs: deps.deadlineMs,
    background: ["revalidate"],
    clock: now,
    ...(transport.finality && {
      hint: {
        head: (signal: AbortSignal) =>
          abortable(signal, () => transport.finality!.head()),
      },
    }),
  });

  function acquireWriter(token: string) {
    db.transaction(() => {
      const holder = db
        .prepare("SELECT pid,token FROM pdpp_transport_lock WHERE id=1")
        .get() as { pid: number; token: string } | undefined;
      if (holder?.pid === process.pid && !ownedTokens.has(holder.token)) {
        db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
      } else if (holder) {
        try {
          process.kill(holder.pid, 0);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ESRCH") {
            db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
          } else throw error;
        }
        if (db.prepare("SELECT 1 FROM pdpp_transport_lock WHERE id=1").get())
          throw Object.assign(
            new Error("replica database worker already active"),
            { code: "replica_worker_active" },
          );
      }
      db.prepare("INSERT INTO pdpp_transport_lock VALUES (1,?,?)").run(
        process.pid,
        token,
      );
    }).immediate();
    ownedTokens.add(token);
  }
  let running = false;
  const databaseKey = db.name && db.name !== ":memory:" ? db.name : db;
  const idle = (): ProgressReport => ({
    receipts: [],
    waits: [],
    problems: [],
    quarantines: [],
    unsupported: [],
    nextWake: undefined,
  });

  /**
   * One bounded coordinator step. The authority context is validated before any
   * phase; a mismatch rejects the step without encrypt, network or receiver calls.
   */
  async function step(
    input: { budget?: ReplicaBudget; signal?: AbortSignal } = {},
  ): Promise<ProgressReport> {
    // A closed door stops replication for good: no identity, capture or
    // publish work.
    if (
      !enabled() ||
      running ||
      activeDatabases.has(databaseKey) ||
      !replicationAdmitted(db)
    )
      return idle();
    // Writer ids come from this server's own registration. Until it is
    // registered under the owner, nothing runs.
    running = true;
    let own;
    try {
      own = await enableReplicaWriterIdentity({
        db,
        owner: deps.expected().owner,
        server,
        roster,
        signal: input.signal,
      });
    } finally {
      running = false;
    }
    if (own.tag === "waiting")
      return {
        ...idle(),
        waits: [
          {
            id: "writer-identity",
            phase: "retain",
            dependency: { kind: "roster", key: server },
          },
        ],
        nextWake: now() + REPLICA_WAIT_FALLBACK_MS,
      };
    const writerToken = randomUUID();
    acquireWriter(writerToken);
    running = true;
    activeDatabases.add(databaseKey);
    try {
      // Under the writer lock: a new identity resets the writer's chain.
      if (!authority(own.identity)) return idle();
      // Only this process owns the worker. None of these hidden stages can be published.
      db.transaction(() => {
        db.prepare("DELETE FROM pdpp_transport_preparing").run();
        for (const table of ["pdpp_binary_chunks", "pdpp_binary_manifests"]) {
          db.prepare(
            `DELETE FROM ${table} WHERE namespace='staging' OR (namespace='payload' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_batches b WHERE b.batch=${table}.blob_id))`,
          ).run();
        }
      }).immediate();
      const current = dependencyFingerprint();
      if (current !== fingerprint) {
        fingerprint = current;
        db.prepare(
          "UPDATE pdpp_transport_import_work SET next_attempt=? WHERE outcome='wait' AND (dependency LIKE 'mapping:%' OR dependency LIKE 'declaration:%') AND next_attempt>?",
        ).run(now(), now());
      }
      return await coordinator.step(
        now(),
        input.signal,
        input.budget ?? { units: Number.POSITIVE_INFINITY },
      );
    } finally {
      running = false;
      activeDatabases.delete(databaseKey);
      try {
        db.prepare(
          "DELETE FROM pdpp_transport_lock WHERE id=1 AND token=?",
        ).run(writerToken);
      } finally {
        ownedTokens.delete(writerToken);
      }
    }
  }
  return {
    step,
    /** Legacy entry point: one unbounded step. Rejects when a whole phase failed. */
    async cycle(): Promise<void> {
      const report = await step();
      const failed = report.problems.filter((p) =>
        ["retain", "discover", "reconcile"].includes(p.phase),
      );
      if (failed.length)
        throw new AggregateError(
          failed.map(
            (p) =>
              new ReplicaProblemError(p.problem, {
                ...(p.cause && { cause: p.cause }),
              }),
          ),
          "Replica transport cycle incomplete",
        );
    },
    /**
     * Explicit capability change: re-admit Unsupported batches that were
     * measured against a different capability than the current cap. Same
     * batch, digest and operations; the old admission stays as history. A
     * plain restart never re-admits. Returns the number re-admitted.
     */
    readmitUnsupported(): number {
      return db
        .prepare(
          `UPDATE pdpp_transport_batches SET prepared=0,outcome=NULL,reason=NULL,error=NULL,attempts=0,next_attempt=0
          WHERE prepared=-1 AND coalesce(json_extract(admission_json,'$.capability'),'') <> ?`,
        )
        .run(`cap:${cap}`).changes;
    },
    /** A host-observed dependency change (e.g. `mapping:<connection>`). Idempotent. */
    onDependencyChanged(key: string) {
      return wake(key, now()) + coordinator.onDependencyChanged(key, now());
    },
  };
}

import {
  systemStreamIdentity,
  type SystemStreamDescriptor,
} from "./system-stream-descriptor.js";
import { isReservedSystemConnector } from "../policy/reserved-scopes.js";
import { keccakOf } from "../stream-sync/crypto-port.js";
import { readBeginReceipt } from "./run-receipts.js";
import { RegistryRefusedError } from "../stream-sync/ports.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  canonicalJson,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  isPlainObject,
  pkHash,
  primaryKeyValues,
  streamScope,
  toHex,
  type JsonValue,
  type ControlState,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  computeRecordKeyFromData,
  keyMatchesData,
} from "../storage/pdpp-records/record-key.js";
import {
  RunIntakeError,
  type BatchRequest,
  type BatchResponse,
  type BeginRequest,
  type BeginResponse,
  type ConnectionCheckpoint,
  type IntakeDeclarations,
} from "../stream-sync/intake.js";
import { syncBeforeBegin } from "./bootstrap.js";
import { foldAppliedCursors } from "./cursor.js";
import { compareSemver } from "../stream-sync/semver.js";
import type { ConnectionRow } from "./deps.js";
import { announceRecordsCommitted, type LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { checkRunFence } from "./fence.js";
import {
  ADMIT_ROW_OFFSET,
  admitUpserts,
  clampRunStart,
  compactTombstones,
  connectorBlockedStreams,
  guardFailureMarks,
  type AdmitRow,
} from "./admit.js";

export interface RunIntakeStore {
  begin(
    runId: string,
    req: BeginRequest,
    declarations: IntakeDeclarations,
  ): Promise<BeginResponse>;
  batch(runId: string, req: BatchRequest): Promise<BatchResponse>;
  /** The connection's saved cursors (`ConnectionCheckpoint`), or null. */
  checkpoint(connector: string): Promise<ConnectionCheckpoint | null>;
}

/**
 * What `begin` reads as a connector's START state, without a run: the
 * connection's checkpoint entry per stream, with the connector version that
 * wrote it. It takes the same basis `begin` does: the registry is read and
 * applied first (`syncBeforeBegin`, a foreign control row reported, not
 * saved), so a connection deleted or reconnected on another device is not
 * read from a stale local view, and the applied cursors are folded, as before
 * every read of the checkpoint. A connection whose control row is not this
 * owner's, is deleted, or cannot be read from the registry has none; so does
 * one with a stream flagged `needs_full`, as `begin` would read the whole
 * connection in full.
 *
 * `cursorVersion` is the version of the connector that wrote the stream's
 * entry as this device knows it (`stream_state.cursor_version`); a fold stamps
 * it with the published cursor's version, so it can be newer than the entry a
 * reader holds in between. A reader that compares it with its own connector
 * version therefore errs on the side of a full read.
 */
async function readConnectionCheckpoint(
  deps: LocalSyncDeps,
  connector: string,
): Promise<ConnectionCheckpoint | null> {
  const { db } = deps;
  const id = controlScope(connector, "");
  const synced = await syncBeforeBegin(deps, connector, { foreign: "report" });
  if (
    synced.unreachable ||
    !synced.connection ||
    synced.connection.controlState === "deleted" ||
    synced.connection.controlState === "foreign" ||
    synced.control?.kind === "foreign" ||
    synced.control?.kind === "deleted"
  )
    return null;
  await foldAppliedCursors(db, id);
  // No cursors while any stream must be read in full next: one flagged
  // `needs_full`, or one whose head is incomplete. Only a full read completes
  // an incomplete head (a run resumed from this cursor publishes `complete`
  // from its base, which an incomplete or reset base cannot give), so handing
  // the cursor out again would resume from the same place forever.
  const [row] = await db.query<{
    checkpoint: string | null;
    control_state: string;
    full_next: number;
  }>(
    `SELECT c.checkpoint, c.control_state,
      EXISTS(SELECT 1 FROM stream_state s WHERE s.connection_id=c.connection_id AND (s.needs_full=1 OR s.complete=0)) AS full_next
      FROM connections c WHERE c.connection_id=?`,
    [id],
  );
  if (
    !row ||
    row.checkpoint === null ||
    row.control_state === "deleted" ||
    row.full_next === 1
  )
    return null;
  const stored: unknown = JSON.parse(row.checkpoint);
  if (!isPlainObject(stored)) return null;
  const versions = new Map(
    (
      await db.query<{ stream: string; cursor_version: string | null }>(
        "SELECT stream, cursor_version FROM stream_state WHERE connection_id=?",
        [id],
      )
    ).map((entry) => [entry.stream, entry.cursor_version]),
  );
  const streams: Record<
    string,
    { state: JsonValue; cursorVersion: string | null }
  > = {};
  for (const [stream, state] of Object.entries(
    stored as Record<string, JsonValue>,
  )) {
    if (state === undefined) continue;
    streams[stream] = { state, cursorVersion: versions.get(stream) ?? null };
  }
  return Object.keys(streams).length ? { connectionId: id, streams } : null;
}

type Run = {
  connection_id: string;
  state: string;
  last_batch: number;
  o: number;
  generation: number | null;
  artifact_version: string;
  admitting: number;
  selected_streams: string | null;
};
const invalid = (message: string) =>
  new RunIntakeError("invalid_request", message);
const replay: BatchResponse = {
  applied: false,
  accepted: 0,
  deletesSkipped: 0,
};

// These transaction-local triggers close the gap between asynchronous checks
// and the write batch. RAISE aborts the WHOLE batch, including trigger creation.
// No schema or driver-specific transaction API is needed (SQLite 3.22).
const STOPPED = `EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = NEW.connection_id
  AND (c.control_state='deleted' OR EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector=c.connector)))`;
const FENCED = `EXISTS (SELECT 1 FROM runs r JOIN connections c ON c.connection_id=r.connection_id
  WHERE r.run_id=NEW.run_id AND (c.control_state='deleted'
    OR EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector=c.connector)
    OR (r.generation IS NOT NULL AND c.generation > r.generation)
    OR EXISTS (SELECT 1 FROM run_streams rs JOIN stream_state s
      ON s.connection_id=r.connection_id AND s.stream=rs.stream
      WHERE rs.run_id=r.run_id AND s.last_delete_version > rs.delete_snapshot)))`;
/**
 * The two ways a staged row can share a record key with a different
 * primary-key hash: with a committed record, or with a row staged by any run of
 * the same connection. Each runs once per staged row inside the batch, so each
 * must be answered by an index search (`records_by_key`, `run_rows_by_key`).
 */
export const STAGED_KEY_CONFLICTS: readonly string[] = [
  `EXISTS (SELECT 1 FROM records x JOIN runs r ON r.connection_id=x.connection_id
      WHERE r.run_id=NEW.run_id AND x.stream=NEW.stream AND x.record_key=NEW.record_key AND x.pk_hash<>NEW.pk_hash)`,
  `EXISTS (SELECT 1 FROM run_rows x JOIN runs r ON r.run_id=x.run_id JOIN runs n ON n.run_id=NEW.run_id
      WHERE r.connection_id=n.connection_id AND x.stream=NEW.stream AND x.record_key=NEW.record_key AND x.pk_hash<>NEW.pk_hash)`,
];
const ROW_CHECK = `CREATE TEMP TRIGGER intake_rows_check BEFORE INSERT ON main.run_rows BEGIN
  SELECT RAISE(ABORT,'connection_stopped') WHERE ${FENCED};
  SELECT RAISE(ABORT,'key_type_conflict') WHERE
    ${STAGED_KEY_CONFLICTS.join("\n    OR ")};
END`;
const BATCH_CHECK = `CREATE TEMP TRIGGER intake_batch_check BEFORE UPDATE OF last_batch ON main.runs BEGIN
  SELECT RAISE(ABORT,'connection_stopped') WHERE ${FENCED};
END`;

/** Begin and batch stage durable rows; end owns their merge into records. */
export function createRunIntakeStore(
  deps: LocalSyncDeps,
  systemStream?: SystemStreamDescriptor,
): RunIntakeStore {
  const trusted = systemStream ? systemStreamIdentity(systemStream) : null;
  const { db } = deps;
  const active = new Map<
    string,
    { request: string; response: BeginResponse }
  >();
  // Serialize a run's calls, not a connection's collector. Other runs can
  // collect while publish holds its connection queue slot for network I/O.
  const tails = new Map<string, Promise<unknown>>();
  function serial<T>(id: string, work: () => Promise<T>): Promise<T> {
    const next = (tails.get(id) ?? Promise.resolve())
      .catch(() => undefined)
      .then(work);
    tails.set(id, next);
    void next
      .finally(() => {
        if (tails.get(id) === next) tails.delete(id);
      })
      .catch(() => undefined);
    return next;
  }
  async function stopped(id: string): Promise<boolean> {
    return (
      (
        await db.query<{ n: number }>(
          `SELECT 1 AS n FROM connections c WHERE c.connection_id=?
      AND (c.control_state='deleted' OR EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector=c.connector))`,
          [id],
        )
      ).length > 0
    );
  }
  async function discard(id: string) {
    await db.batch([
      { sql: "DELETE FROM run_rows WHERE run_id=?", params: [id] },
      {
        sql: "UPDATE run_streams SET decision='discarded',reason='fence',replace=0 WHERE run_id=?",
        params: [id],
      },
      {
        sql: "UPDATE connections SET checkpoint=NULL WHERE connection_id=(SELECT connection_id FROM runs WHERE run_id=?)",
        params: [id],
      },
      {
        sql: "UPDATE stream_state SET needs_full=1,complete=0 WHERE connection_id=(SELECT connection_id FROM runs WHERE run_id=?) AND stream IN (SELECT stream FROM run_streams WHERE run_id=?)",
        params: [id, id],
      },
      { sql: "UPDATE runs SET state='ended' WHERE run_id=?", params: [id] },
    ]);
    active.delete(id);
  }
  async function live(id: string): Promise<Run> {
    const [run] = await db.query<Run>(
      "SELECT connection_id,state,last_batch,o,generation,artifact_version,admitting,selected_streams FROM runs WHERE run_id=?",
      [id],
    );
    if (!run || run.state !== "collecting") {
      active.delete(id);
      throw new RunIntakeError("gone");
    }
    if (
      run.connection_id.startsWith("pdpp.vana-system-") &&
      run.connection_id !== trusted?.connectionId
    )
      throw invalid("reserved system run");
    if (
      (await stopped(run.connection_id)) ||
      (await checkRunFence(deps, id, "batch")).length > 0
    ) {
      await discard(id);
      throw new RunIntakeError("connection_stopped");
    }
    return run;
  }
  return {
    checkpoint: (connector) => readConnectionCheckpoint(deps, connector),
    begin: (runId, req, declarations) =>
      serial(runId, async () => {
        if (
          !/^[A-Za-z0-9._-]{1,128}$/.test(runId) ||
          !isPlainObject(req as unknown)
        )
          throw invalid("bad run or request");
        if (
          typeof req.connector !== "string" ||
          req.connector.includes("|") ||
          req.connector.includes(".")
        )
          throw invalid("invalid connector key");
        if (
          (isReservedSystemConnector(req.connector) ||
            systemStream !== undefined) &&
          (!systemStream ||
            req.connector !== systemStream.connector ||
            JSON.stringify(declarations) !==
              JSON.stringify(trusted!.declarations))
        )
          throw invalid("reserved system connector");
        if (typeof req.artifactDigest !== "string" || !req.artifactDigest)
          throw invalid("artifactDigest is required");
        if (
          !req.owner ||
          !/^0x[0-9a-fA-F]{40}$/.test(req.owner.address) ||
          !(req.owner.leaseId === null || typeof req.owner.leaseId === "string")
        )
          throw invalid("owner address and lease are required");
        if (req.owner.address.toLowerCase() !== deps.ownerAddress.toLowerCase())
          throw new RunIntakeError("owner_mismatch");
        for (const flag of [req.wantFull, req.connect])
          if (flag !== undefined && typeof flag !== "boolean")
            throw invalid("invalid run flag");
        if (
          req.observedAt !== undefined &&
          (!Number.isFinite(req.observedAt) || req.observedAt < 0)
        )
          throw invalid("invalid observedAt");
        if (
          req.expectedControlVersion !== undefined &&
          (!Number.isSafeInteger(req.expectedControlVersion) ||
            req.expectedControlVersion < 0)
        )
          throw invalid("invalid expectedControlVersion");
        const receipt = await readBeginReceipt(db, runId, req);
        if (receipt) return receipt;
        if (declarations.connector !== req.connector)
          throw invalid("connector does not match artifact");
        const seen = new Set<string>();
        try {
          streamScope(req.connector, "", "s");
          for (const d of declarations.streams) {
            streamScope(req.connector, "", d.name);
            if (
              d.name.includes("|") ||
              seen.has(d.name) ||
              d.primaryKey.length === 0 ||
              d.primaryKey.some((k) => typeof k !== "string" || !k)
            )
              throw invalid("invalid stream declaration");
            seen.add(d.name);
          }
        } catch {
          throw invalid("invalid connector or stream declaration");
        }
        if (req.streams !== undefined && !Array.isArray(req.streams))
          throw invalid("streams must be an array");
        for (const entry of req.streams ?? []) {
          if (!isPlainObject(entry as unknown) || !seen.has(entry.name))
            throw invalid("stream is not declared");
          if (entry.fields != null || entry.resources != null)
            throw new RunIntakeError("restricted_scope_unsupported");
          if (entry.resumed !== undefined && typeof entry.resumed !== "boolean")
            throw invalid("invalid run flag");
        }
        if (
          req.selectedStreams !== undefined &&
          (!Array.isArray(req.selectedStreams) ||
            new Set(req.selectedStreams).size !== req.selectedStreams.length ||
            req.selectedStreams.some((name) => !seen.has(name)))
        )
          throw invalid("invalid selected streams");
        const id = controlScope(req.connector, "");
        const text = canonicalJson(JSON.parse(JSON.stringify(req)));
        // End is a separate owner. Reap its completed begin responses without
        // evicting live collectors (which must still replay idempotently).
        if (active.size >= 128) {
          const ids = [...active.keys()];
          for (let at = 0; at < ids.length; at += 256) {
            const page = ids.slice(at, at + 256);
            const ended = await db.query<{ run_id: string }>(
              `SELECT run_id FROM runs WHERE state='ended' AND run_id IN (${page.map(() => "?").join(",")})`,
              page,
            );
            for (const row of ended) active.delete(row.run_id);
          }
        }
        const held = active.get(runId);
        if (held) {
          await live(runId);
          if (text !== held.request) throw new RunIntakeError("run_conflict");
          return held.response;
        }
        if (
          (await db.query("SELECT 1 FROM runs WHERE run_id=?", [runId])).length
        )
          throw new RunIntakeError("gone");
        // An unfinished intent must finish before reconnect; never remove its
        // durable fence merely because a new collector asked to connect.
        if (
          (
            await db.query("SELECT 1 FROM delete_intents WHERE connector=?", [
              req.connector,
            ])
          ).length
        )
          throw new RunIntakeError("connection_stopped");
        // A device without a participation row must learn from the registry
        // whether the connection exists; the local connect shortcut cannot.
        const participates = async () =>
          !!systemStream ||
          (
            await db.query(
              "SELECT 1 FROM connection_participation WHERE connection_id=?",
              [id],
            )
          ).length > 0;
        const joinedBeforeSync = await participates();
        let synced = await collectionBasis(
          deps,
          systemStream ? { ...req, connect: true } : req,
          !joinedBeforeSync,
        );
        // Another key's control row: this owner cannot publish what a run
        // would collect. Nothing is written for it (`syncBeforeBegin`).
        if (synced.control?.kind === "foreign")
          throw new RunIntakeError("control_foreign");
        let observed: ControlState | undefined = synced.control ?? undefined;
        if (req.expectedControlVersion !== undefined) {
          if (synced.unreachable)
            throw new RunIntakeError("control_basis_unavailable");
          if (
            (synced.connection?.controlVersion ?? 0) !==
            req.expectedControlVersion
          )
            throw new RunIntakeError("control_basis_mismatch");
        }
        let admittedControlVersion = synced.connection?.controlVersion ?? 0;
        let reconnected = false;
        if (
          synced.connection?.controlState === "deleted" &&
          req.connect === true &&
          !synced.unreachable
        ) {
          const hashes = await controlHashes(
            keccakOf(deps.streamCrypto),
            await deriveKeyCheck((m) => deps.keys.namespaceHmac(m)),
          );
          const version = synced.connection.controlVersion + 1;
          const signature = await deps.signer.signAddData({
            ownerAddress: deps.ownerAddress,
            scope: id,
            dataHash: hashes.activeData,
            metadataHash: hashes.activeMetadata,
            expectedVersion: BigInt(version),
          });
          try {
            const posted = await deps.registry.post({
              ownerAddress: deps.ownerAddress,
              scope: id,
              dataHash: hashes.activeData,
              metadataHash: hashes.activeMetadata,
              expectedVersion: String(version),
              signature,
            });
            if (posted.kind === "conflict")
              throw new RunIntakeError("control_basis_mismatch");
          } catch (error) {
            if (error instanceof RegistryRefusedError && error.status === 409)
              throw new RunIntakeError("control_basis_mismatch");
            throw error;
          }
          admittedControlVersion = version;
          reconnected = true;
          // The successful compare-and-set is the control observation. Reuse
          // it while applying the log; a second GET adds no admission safety.
          synced = await syncBeforeBegin(deps, req.connector, {
            foreign: "report",
            committedControl: {
              found: true,
              version,
              dataHash: hashes.activeData,
              metadataHash: hashes.activeMetadata,
              deleted: false,
            },
          });
          observed = synced.control ?? undefined;
          if (synced.unreachable)
            throw new RunIntakeError("control_basis_unavailable");
          if (synced.connection?.controlVersion !== admittedControlVersion)
            throw new RunIntakeError("control_basis_mismatch");
        }
        if (await stopped(id)) throw new RunIntakeError("connection_stopped");
        // The sync above may have ended this device's participation: it first
        // learned of a new lifetime of the connection. Judge it only now.
        const joined = await participates();
        // The join gate. An absent control row, read from the registry, means
        // this device creates the connection; an explicit reconnect of a
        // connection this device saw deleted starts a new lifetime it creates.
        // An active row is another device's connection: ask first.
        if (!joined) {
          // `unreachable` also covers a log apply that could not finish after
          // the control row was read: then the row is known, and decides.
          if (synced.control === null)
            throw new RunIntakeError("control_basis_unavailable");
          if (
            !reconnected &&
            synced.control?.kind === "active" &&
            req.join !== true
          )
            throw new RunIntakeError("join_required");
        }
        // The cursors of the segments just applied are the stream's entries.
        await foldAppliedCursors(db, id);
        const [cached] = await db.query<{
          checkpoint: string | null;
          needs_full: number;
        }>(
          `SELECT c.checkpoint,EXISTS(SELECT 1 FROM stream_state s WHERE s.connection_id=c.connection_id AND s.needs_full=1) AS needs_full FROM connections c WHERE c.connection_id=?`,
          [id],
        );
        const full =
          !systemStream &&
          (req.connect === true ||
            req.wantFull === true ||
            cached?.checkpoint == null ||
            cached.needs_full === 1);
        const collection = full ? "full_refresh" : "incremental";
        const modes = new Map(
          declarations.streams.map((d) => [
            d.name,
            full || d.incremental === false
              ? ("full_refresh" as const)
              : ("incremental" as const),
          ]),
        );
        // Each stream's cursor carries the version of the connector that
        // wrote it, here or on another device. An older connector than that
        // may misread it: refused, before anything is written. A version
        // order that is unknown (either is not semver) reads the stream in full.
        if (!full) {
          const written = await db.query<{
            stream: string;
            cursor_version: string;
          }>(
            "SELECT stream, cursor_version FROM stream_state WHERE connection_id=? AND cursor_version IS NOT NULL",
            [id],
          );
          for (const { stream, cursor_version } of written) {
            if (
              modes.get(stream) !== "incremental" ||
              cursor_version === declarations.version
            )
              continue;
            const order = compareSemver(cursor_version, declarations.version);
            if (order === 1)
              throw new RunIntakeError(
                "connector_update_required",
                `stream ${stream}: its cursor was written by connector ${cursor_version}, newer than ${declarations.version}`,
              );
            if (order === null) modes.set(stream, "full_refresh");
          }
        }
        let state: JsonValue | null = cached?.checkpoint
          ? JSON.parse(cached.checkpoint)
          : null;
        if (isPlainObject(state)) {
          state = Object.fromEntries(
            Object.entries(state).filter(
              ([name]) => modes.get(name) !== "full_refresh",
            ),
          );
          if (Object.keys(state).length === 0) state = null;
        }
        const o = Math.trunc(
          Math.min(req.observedAt ?? deps.now(), deps.now() + 300_000),
        );
        const generation =
          synced.connection?.controlState === "active"
            ? synced.connection.generation
            : null;
        const keyCheck = await deriveKeyCheck((m) =>
          deps.keys.namespaceHmac(m),
        );
        const response: BeginResponse = {
          runId,
          status: "collecting",
          discardReason: null,
          stuck: false,
          binding: { keyCheck },
          start: { collection_mode: collection, state },
          streams: declarations.streams.map((d) => ({
            ...d,
            incremental: d.incremental !== false,
            mode: modes.get(d.name)!,
          })),
        };
        const statements: SqlStatement[] = [
          {
            sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns) VALUES (?,?,'')",
            params: [id, req.connector],
          },
          {
            sql: `CREATE TEMP TRIGGER intake_begin_check BEFORE INSERT ON main.runs BEGIN
              SELECT RAISE(ABORT,'control_basis_mismatch') WHERE NEW.begin_control_version IS NOT NULL
                AND EXISTS (SELECT 1 FROM connections c WHERE c.connection_id=NEW.connection_id AND c.control_version<>NEW.begin_control_version);
              SELECT RAISE(ABORT,'connection_stopped') WHERE ${STOPPED}; END`,
          },
          {
            sql: "INSERT INTO runs(run_id,connection_id,o,generation,artifact_version,collection_mode,state,begin_control_version,begin_request,begin_response,selected_streams) VALUES (?,?,?,?,?,?,'collecting',?,?,?,?)",
            params: [
              runId,
              id,
              o,
              generation,
              declarations.version,
              collection,
              admittedControlVersion,
              text,
              JSON.stringify(response),
              req.selectedStreams === undefined
                ? null
                : JSON.stringify(req.selectedStreams),
            ],
          },
        ];
        for (const d of declarations.streams) {
          if (
            req.selectedStreams !== undefined &&
            !req.selectedStreams.includes(d.name)
          )
            continue;
          statements.push(
            {
              sql: "INSERT OR IGNORE INTO stream_state(connection_id,stream,primary_key,semantics,incremental) VALUES (?,?,?,?,?)",
              params: [
                id,
                d.name,
                JSON.stringify(d.primaryKey),
                d.semantics,
                d.incremental === false ? 0 : 1,
              ],
            },
            ...(d.keyTypes
              ? [
                  {
                    sql: "UPDATE stream_state SET key_types=? WHERE connection_id=? AND stream=?",
                    params: [JSON.stringify(d.keyTypes), id, d.name],
                  },
                ]
              : []),
            {
              sql: `INSERT INTO run_streams(run_id,stream,delete_snapshot,basis_version,basis_generation,basis_data_hash,primary_key,profile_key,profile_version,full_read,coverage_strategy,semantics)
            SELECT ?,stream,last_delete_version,CASE WHEN head_version>0 THEN head_version ELSE NULL END,CASE WHEN head_version>0 THEN head_generation ELSE ? END,head_data_hash,?,NULL,?,?,?,?
            FROM stream_state WHERE connection_id=? AND stream=?`,
              params: [
                runId,
                synced.unreachable
                  ? null
                  : (synced.connection?.generation ?? null),
                JSON.stringify(d.primaryKey),
                declarations.version,
                // A full read is what the stream's rows prove, not what the
                // run's mode asked for: a windowed read, or one resumed from
                // a cursor handed out before the run, is not one.
                modes.get(d.name) === "full_refresh" &&
                !(req.streams ?? []).some(
                  (s) =>
                    s.name === d.name &&
                    (s.time_range != null || s.resumed === true),
                )
                  ? 1
                  : 0,
                d.coverageStrategy ?? null,
                d.semantics,
                id,
                d.name,
              ],
            },
          );
        }
        if (!joined)
          statements.push({
            sql: "INSERT OR IGNORE INTO connection_participation(connection_id,joined_at) VALUES (?,?)",
            params: [id, deps.now()],
          });
        // The clock proposes the stamp; the stamps the device holds are its
        // lower bound, whatever the mode.
        statements.push(clampRunStart(runId));
        if (deps.publishWhileCollecting === true) {
          // The run keeps this mode to its end. Compaction counts the new run.
          statements.push(
            {
              sql: "UPDATE runs SET admitting=1 WHERE run_id=?",
              params: [runId],
            },
            ...compactTombstones(id),
          );
        }
        statements.push({ sql: "DROP TRIGGER temp.intake_begin_check" });
        try {
          await db.batch(statements);
        } catch (error) {
          if (String(error).includes("control_basis_mismatch"))
            throw new RunIntakeError("control_basis_mismatch");
          if (String(error).includes("connection_stopped"))
            throw new RunIntakeError("connection_stopped");
          throw error;
        }
        active.set(runId, { request: text, response });
        // The control row is the caller's to read once: a replay or a stored
        // receipt answers without it, and it is not saved with the run.
        return observed === undefined
          ? response
          : { ...response, control: observed };
      }),
    batch: (runId, req) =>
      serial(runId, async () => {
        const run = await live(runId);
        if (
          !isPlainObject(req as unknown) ||
          !Number.isSafeInteger(req.batch) ||
          req.batch < 0 ||
          !Array.isArray(req.records)
        )
          throw invalid("batch and records are required");
        if (req.batch <= run.last_batch) return replay;
        if (req.batch !== run.last_batch + 1)
          throw new RunIntakeError(
            "batch_gap",
            "batch_gap",
            run.last_batch + 1,
          );
        const streams = new Map(
          (
            await db.query<{
              stream: string;
              primary_key: string;
              semantics: string | null;
            }>(
              "SELECT stream,primary_key,semantics FROM run_streams WHERE run_id=?",
              [runId],
            )
          ).map((s) => [
            s.stream,
            {
              primaryKey: JSON.parse(s.primary_key) as string[],
              semantics: s.semantics,
            },
          ]),
        );
        const selected: string[] | null =
          run.selected_streams === null
            ? null
            : JSON.parse(run.selected_streams);
        const rows: SqlStatement[] = [];
        const upserts: AdmitRow[] = [];
        let accepted = 0;
        for (const record of req.records) {
          if (
            !isPlainObject(record as unknown) ||
            !streams.has(record.stream) ||
            (selected !== null && !selected.includes(record.stream)) ||
            !isPlainObject(record.data)
          )
            throw invalid("invalid record or stream");
          if (
            record.op !== undefined &&
            record.op !== "upsert" &&
            record.op !== "delete"
          )
            throw invalid("invalid record op");
          const declaration = streams.get(record.stream)!;
          if (
            record.op === "delete" &&
            declaration.semantics !== "mutable_state"
          )
            throw invalid("delete requires a mutable_state stream");
          const primaryKey = declaration.primaryKey;
          let body: string;
          let bodySha256: string;
          let recordKey: string;
          let hash: string;
          let keyValues: string;
          try {
            keyValues = canonicalJson(
              primaryKeyValues(record.data, primaryKey) as JsonValue,
            );
            recordKey = computeRecordKeyFromData(record.data, primaryKey);
            if (
              record.key !== undefined &&
              !keyMatchesData(record.key, record.data, primaryKey)
            )
              throw invalid("record key does not match data");
            body = canonicalJson(record.data);
            bodySha256 = toHex(sha256(new TextEncoder().encode(body)));
            hash = await pkHash(
              async (b) => sha256(b),
              record.data,
              primaryKey,
            );
          } catch {
            throw invalid("invalid record or primary key");
          }
          rows.push({
            sql: `INSERT OR REPLACE INTO run_rows(run_id,stream,pk_hash,record_key,body,body_sha256,op,pk_values)
          SELECT ?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM runs WHERE run_id=? AND state='collecting' AND last_batch=?)`,
            params: [
              runId,
              record.stream,
              hash,
              recordKey,
              body,
              bodySha256,
              record.op === "delete" ? "delete" : "upsert",
              keyValues,
              runId,
              run.last_batch,
            ],
          });
          if (record.op !== "delete")
            upserts.push({
              stream: record.stream,
              pkHash: hash,
              recordKey,
              body,
              bodySha256,
            });
          accepted++;
        }
        const admitting = run.admitting === 1;
        // A stream whose connector the head refuses (version floor or key) has
        // its upserts staged, not admitted: run end refuses it the same way.
        const { blocked, facts } = admitting
          ? await connectorBlockedStreams(deps, runId, run)
          : { blocked: new Set<string>(), facts: new Map() };
        const admitted = upserts.filter((u) => !blocked.has(u.stream));
        const admittedStreams = [...new Set(admitted.map((u) => u.stream))];
        const admission =
          admitting && admitted.length > 0
            ? admitUpserts({
                op: deps.newOp(),
                connectionId: run.connection_id,
                runId,
                o: run.o,
                batch: req.batch,
                rows: admitted,
                facts,
                guard: {
                  sql: "EXISTS (SELECT 1 FROM runs WHERE run_id=? AND state='collecting' AND last_batch=?)",
                  params: [runId, run.last_batch],
                },
              })
            : [];
        // A stream whose facts changed since the check is staged, not admitted:
        // run end merges it.
        const guardMarks =
          admission.length > 0
            ? guardFailureMarks(
                run.connection_id,
                runId,
                facts,
                admittedStreams,
              )
            : [];
        // The mark outlives the batch: run end reports `updateRequired` for it
        // even when another refusal (commit order) comes first there.
        const blockedStreams = [
          ...new Set(
            upserts.filter((u) => blocked.has(u.stream)).map((u) => u.stream),
          ),
        ];
        const marks: SqlStatement[] = blockedStreams.map((stream) => ({
          sql: "UPDATE run_streams SET reason='connector_update_required', unadmitted=1 WHERE run_id=? AND stream=?",
          params: [runId, stream],
        }));
        let outcome: Awaited<ReturnType<typeof db.batch>>;
        try {
          outcome = await db.batch([
            { sql: ROW_CHECK },
            { sql: BATCH_CHECK },
            ...rows,
            ...admission,
            ...guardMarks,
            {
              sql: "UPDATE runs SET last_batch=? WHERE run_id=? AND state='collecting' AND last_batch=?",
              params: [req.batch, runId, run.last_batch],
            },
            ...marks,
            { sql: "DROP TRIGGER temp.intake_rows_check" },
            { sql: "DROP TRIGGER temp.intake_batch_check" },
          ]);
          if (
            outcome.changes[
              rows.length + admission.length + guardMarks.length + 2
            ] === 0
          ) {
            await live(runId);
            return replay;
          }
        } catch (error) {
          if (String(error).includes("key_type_conflict"))
            throw invalid("key_type_conflict");
          if (String(error).includes("connection_stopped")) {
            await discard(runId);
            throw new RunIntakeError("connection_stopped");
          }
          throw error;
        }
        if (!admitting) return { applied: true, accepted, deletesSkipped: 0 };
        const base = 2 + rows.length + ADMIT_ROW_OFFSET;
        const markBase = 2 + rows.length + admission.length;
        const notAdmitted = new Set(
          admittedStreams.filter((_, i) => outcome.changes[markBase + i] === 1),
        );
        // A row skipped for a remembered delete; rows of a stream whose facts
        // changed are counted as staged, not as skipped.
        const tombstoned = admitted.filter(
          (u, i) =>
            outcome.changes[base + i] === 0 && !notAdmitted.has(u.stream),
        ).length;
        const landed = admitted.filter(
          (_, i) => outcome.changes[base + i] !== 0,
        ).length;
        if (landed > 0) announceRecordsCommitted(deps);
        return {
          applied: true,
          accepted,
          deletesSkipped: 0,
          tombstoned,
          ...(marks.length > 0 ? { updateRequired: true } : {}),
        };
      }),
  };
}

/**
 * An explicit full collection needs no remote checkpoint. Its local head is
 * the immutable replacement basis; publish compares that log position and
 * control lifetime atomically. A competing commit applies the winner and
 * replans without replacing rows this collector never observed.
 * Retry admission, reconnect and repair still need an authoritative read, and
 * so does a device that has not joined the connection (`authoritative`).
 */
async function collectionBasis(
  deps: LocalSyncDeps,
  request: BeginRequest,
  authoritative: boolean,
): Promise<Awaited<ReturnType<typeof syncBeforeBegin>>> {
  if (
    !authoritative &&
    request.connect === true &&
    request.expectedControlVersion === undefined
  ) {
    const id = controlScope(request.connector, "");
    const local = await deps.queue.run(id, "end", async () => {
      const [row] = await deps.db.query<
        ConnectionRow & { partial: number } & Record<string, string | number>
      >(
        `SELECT connection_id AS connectionId, connector, ns, generation,
          control_state AS controlState, control_version AS controlVersion,
          apply_partial AS partial FROM connections WHERE connection_id=?`,
        [id],
      );
      if (
        row &&
        (row.partial ||
          (row.controlState !== "active" && row.controlState !== "absent"))
      )
        return null;
      const control: ControlState =
        row?.controlState === "active"
          ? { kind: "active", generation: row.generation }
          : { kind: "absent" };
      return { connection: row ?? null, control, unreachable: false };
    });
    if (local) return local;
  }
  return syncBeforeBegin(deps, request.connector, { foreign: "report" });
}

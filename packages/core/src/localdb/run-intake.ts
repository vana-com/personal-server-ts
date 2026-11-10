import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
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
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import {
  RunIntakeError,
  type BatchRequest,
  type BatchResponse,
  type BeginRequest,
  type BeginResponse,
  type IntakeDeclarations,
} from "../stream-sync/intake.js";
import { syncBeforeBegin } from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { checkRunFence } from "./fence.js";

export interface RunIntakeStore {
  begin(
    runId: string,
    req: BeginRequest,
    declarations: IntakeDeclarations,
  ): Promise<BeginResponse>;
  batch(runId: string, req: BatchRequest): Promise<BatchResponse>;
}

type Run = { connection_id: string; state: string; last_batch: number };
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
const ROW_CHECK = `CREATE TEMP TRIGGER intake_rows_check BEFORE INSERT ON main.run_rows BEGIN
  SELECT RAISE(ABORT,'connection_stopped') WHERE ${FENCED};
  SELECT RAISE(ABORT,'key_type_conflict') WHERE
    EXISTS (SELECT 1 FROM records x JOIN runs r ON r.connection_id=x.connection_id
      WHERE r.run_id=NEW.run_id AND x.stream=NEW.stream AND x.record_key=NEW.record_key AND x.pk_hash<>NEW.pk_hash)
    OR EXISTS (SELECT 1 FROM run_rows x JOIN runs r ON r.run_id=x.run_id JOIN runs n ON n.run_id=NEW.run_id
      WHERE r.connection_id=n.connection_id AND x.stream=NEW.stream AND x.record_key=NEW.record_key AND x.pk_hash<>NEW.pk_hash);
END`;
const BATCH_CHECK = `CREATE TEMP TRIGGER intake_batch_check BEFORE UPDATE OF last_batch ON main.runs BEGIN
  SELECT RAISE(ABORT,'connection_stopped') WHERE ${FENCED};
END`;

/** Begin and batch stage durable rows; end owns their merge into records. */
export function createRunIntakeStore(deps: LocalSyncDeps): RunIntakeStore {
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
      "SELECT connection_id,state,last_batch FROM runs WHERE run_id=?",
      [id],
    );
    if (!run || run.state !== "collecting") {
      active.delete(id);
      throw new RunIntakeError("gone");
    }
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
        }
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
        if (req.connect !== true && (await stopped(id)))
          throw new RunIntakeError("connection_stopped");
        let synced = await syncBeforeBegin(deps, req.connector);
        if (
          synced.connection?.controlState === "deleted" &&
          req.connect === true &&
          !synced.unreachable
        ) {
          const hashes = await controlHashes(
            async (b) => keccak_256(b),
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
          await deps.registry.post({
            ownerAddress: deps.ownerAddress,
            scope: id,
            dataHash: hashes.activeData,
            metadataHash: hashes.activeMetadata,
            expectedVersion: String(version),
            signature,
          });
          synced = await syncBeforeBegin(deps, req.connector);
        }
        if (await stopped(id)) throw new RunIntakeError("connection_stopped");
        const [cached] = await db.query<{
          checkpoint: string | null;
          needs_full: number;
        }>(
          `SELECT c.checkpoint,EXISTS(SELECT 1 FROM stream_state s WHERE s.connection_id=c.connection_id AND s.needs_full=1) AS needs_full FROM connections c WHERE c.connection_id=?`,
          [id],
        );
        const full =
          req.connect === true ||
          req.wantFull === true ||
          cached?.checkpoint == null ||
          cached.needs_full === 1;
        const collection = full ? "full_refresh" : "incremental";
        const modes = new Map(
          declarations.streams.map((d) => [
            d.name,
            full || d.incremental === false
              ? ("full_refresh" as const)
              : ("incremental" as const),
          ]),
        );
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
        const statements: SqlStatement[] = [
          {
            sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns) VALUES (?,?,'')",
            params: [id, req.connector],
          },
          {
            sql: `CREATE TEMP TRIGGER intake_begin_check BEFORE INSERT ON main.runs BEGIN SELECT RAISE(ABORT,'connection_stopped') WHERE ${STOPPED}; END`,
          },
          {
            sql: "INSERT INTO runs(run_id,connection_id,o,generation,artifact_version,collection_mode,state) VALUES (?,?,?,?,?,?,'collecting')",
            params: [
              runId,
              id,
              o,
              generation,
              declarations.version,
              collection,
            ],
          },
        ];
        for (const d of declarations.streams) {
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
            {
              sql: `INSERT INTO run_streams(run_id,stream,delete_snapshot,basis_version,basis_generation,basis_data_hash,primary_key,profile_key,profile_version,full_read)
            SELECT ?,stream,last_delete_version,CASE WHEN head_version>0 THEN head_version ELSE NULL END,CASE WHEN head_version>0 THEN head_generation ELSE ? END,head_data_hash,?,NULL,?,?
            FROM stream_state WHERE connection_id=? AND stream=?`,
              params: [
                runId,
                synced.unreachable
                  ? null
                  : (synced.connection?.generation ?? null),
                JSON.stringify(d.primaryKey),
                declarations.version,
                modes.get(d.name) === "full_refresh" &&
                !(req.streams ?? []).some(
                  (s) => s.name === d.name && s.time_range != null,
                )
                  ? 1
                  : 0,
                id,
                d.name,
              ],
            },
          );
        }
        statements.push({ sql: "DROP TRIGGER temp.intake_begin_check" });
        try {
          await db.batch(statements);
        } catch (error) {
          if (String(error).includes("connection_stopped"))
            throw new RunIntakeError("connection_stopped");
          throw error;
        }
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
        active.set(runId, { request: text, response });
        return response;
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
            await db.query<{ stream: string; primary_key: string }>(
              "SELECT stream,primary_key FROM run_streams WHERE run_id=?",
              [runId],
            )
          ).map((s) => [s.stream, JSON.parse(s.primary_key) as string[]]),
        );
        const rows: SqlStatement[] = [];
        let accepted = 0;
        let deletesSkipped = 0;
        for (const record of req.records) {
          if (
            !isPlainObject(record as unknown) ||
            !streams.has(record.stream) ||
            !isPlainObject(record.data)
          )
            throw invalid("invalid record or stream");
          if (
            record.op !== undefined &&
            record.op !== "upsert" &&
            record.op !== "delete"
          )
            throw invalid("invalid record op");
          if (record.op === "delete") {
            deletesSkipped++;
            continue;
          }
          const primaryKey = streams.get(record.stream)!;
          let body: string;
          let recordKey: string;
          let hash: string;
          try {
            primaryKeyValues(record.data, primaryKey);
            recordKey = computeRecordKeyFromData(record.data, primaryKey);
            body = canonicalJson(record.data);
            hash = await pkHash(
              async (b) => sha256(b),
              record.data,
              primaryKey,
            );
          } catch {
            throw invalid("invalid record or primary key");
          }
          rows.push({
            sql: `INSERT OR REPLACE INTO run_rows(run_id,stream,pk_hash,record_key,body,body_sha256)
          SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM runs WHERE run_id=? AND state='collecting' AND last_batch=?)`,
            params: [
              runId,
              record.stream,
              hash,
              recordKey,
              body,
              toHex(sha256(new TextEncoder().encode(body))),
              runId,
              run.last_batch,
            ],
          });
          accepted++;
        }
        try {
          const outcome = await db.batch([
            { sql: ROW_CHECK },
            { sql: BATCH_CHECK },
            ...rows,
            {
              sql: "UPDATE runs SET last_batch=? WHERE run_id=? AND state='collecting' AND last_batch=?",
              params: [req.batch, runId, run.last_batch],
            },
            { sql: "DROP TRIGGER temp.intake_rows_check" },
            { sql: "DROP TRIGGER temp.intake_batch_check" },
          ]);
          if (outcome.changes[rows.length + 2] === 0) {
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
        return { applied: true, accepted, deletesSkipped };
      }),
  };
}

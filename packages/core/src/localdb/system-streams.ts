import {
  canonicalJson,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import type { LocalSyncDeps } from "./deps.js";
import { createRunIntakeStore } from "./run-intake.js";
import { createRunEndStore } from "./run-end.js";
import {
  systemStreamIdentity,
  type SystemStreamDescriptor,
} from "./system-stream-descriptor.js";

type ProducerLane = { local: Promise<unknown>; maintenance: Promise<unknown> };
const producerLanes = new WeakMap<SqlDriver, Map<string, ProducerLane>>();

/** A durable local producer. Only canonical intake writes replicated records. */
export function createSystemStreamStore(
  deps: LocalSyncDeps,
  descriptor: SystemStreamDescriptor & {
    readonly timestampField: string;
    readonly validate?: (data: JsonObject) => void;
  },
) {
  const { db } = deps;
  const identity = systemStreamIdentity(descriptor);
  // System producers always admit fenced batches and retain explicit-delete
  // tombstones, independently of connector collection feature flags.
  // Activity rides a later publish; neither enqueue nor canonical admission
  // may schedule a publish just for the system stream.
  const producerDeps = {
    ...deps,
    publishWhileCollecting: true,
    recordsCommitted: undefined,
  };
  const intake = createRunIntakeStore(producerDeps, descriptor);
  const end = createRunEndStore(producerDeps);
  let lanes = producerLanes.get(db);
  if (!lanes) producerLanes.set(db, (lanes = new Map()));
  const laneKey = JSON.stringify([identity.connectionId, descriptor.stream]);
  let lane = lanes.get(laneKey);
  if (!lane)
    lanes.set(
      laneKey,
      (lane = { local: Promise.resolve(), maintenance: Promise.resolve() }),
    );
  // All handles share local mutation order. Canonical drain may wait for the
  // sync queue or registry; it must never hold up append's durable local commit.
  function serial<T>(
    kind: keyof ProducerLane,
    work: () => Promise<T>,
  ): Promise<T> {
    const result = lane![kind].catch(() => {}).then(work);
    lane![kind] = result;
    return result;
  }
  function encode(data: JsonObject) {
    descriptor.validate?.(data);
    const body = canonicalJson(data);
    const sortAt = data[descriptor.timestampField];
    if (
      typeof sortAt !== "string" ||
      !Number.isFinite(Date.parse(sortAt)) ||
      new Date(sortAt).toISOString() !== sortAt ||
      new TextEncoder().encode(body).length > 4096
    )
      throw new Error("Invalid system stream record");
    return {
      body,
      sortAt,
      id: computeRecordKeyFromData(data, [...descriptor.primaryKey]),
    };
  }
  async function canonical(id: string, body: string) {
    const rows = await db.query<{ body: string }>(
      "SELECT body FROM records WHERE connection_id=? AND stream=? AND record_key=?",
      [identity.connectionId, descriptor.stream, id],
    );
    return rows.length === 1 && rows[0]!.body === body;
  }
  async function project(): Promise<number> {
    let applied = 0;
    for (;;) {
      const [checkpoint] = await db.query<{ seq: number }>(
        "SELECT seq FROM system_stream_checkpoint WHERE connection_id=? AND stream=?",
        [identity.connectionId, descriptor.stream],
      );
      const changes = await db.query<{
        seq: number;
        record_id: string;
        body: string | null;
      }>(
        `SELECT seq,record_id,body FROM system_stream_changes
         WHERE connection_id=? AND stream=? AND seq>? ORDER BY seq LIMIT 200`,
        [identity.connectionId, descriptor.stream, checkpoint?.seq ?? 0],
      );
      if (!changes.length) return applied;
      const statements: SqlStatement[] = [];
      for (const row of changes) {
        const params = [
          identity.connectionId,
          descriptor.stream,
          row.record_id,
        ];
        if (row.body === null) {
          statements.push(
            {
              sql: "DELETE FROM system_stream_projection WHERE connection_id=? AND stream=? AND record_id=?",
              params,
            },
            {
              sql: "DELETE FROM system_stream_outbox WHERE connection_id=? AND stream=? AND record_id=?",
              params,
            },
          );
          continue;
        }
        let encoded: ReturnType<typeof encode>;
        try {
          encoded = encode(JSON.parse(row.body));
          if (encoded.id !== row.record_id)
            throw new Error("Invalid system stream key");
        } catch {
          statements.push({
            sql: "INSERT OR IGNORE INTO system_stream_quarantine VALUES (?,?,?,?)",
            params: [...params, row.body],
          });
          continue;
        }
        const { body, sortAt } = encoded;
        // A conflicting duplicate is retained for inspection; it cannot replace
        // the first visible body. Import never calls append or creates outbox work.
        statements.push(
          {
            sql: "INSERT OR IGNORE INTO system_stream_quarantine SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM system_stream_projection WHERE connection_id=? AND stream=? AND record_id=? AND body<>?)",
            params: [...params, body, ...params, body],
          },
          {
            sql: "INSERT OR IGNORE INTO system_stream_projection VALUES (?,?,?,?,?)",
            params: [...params, sortAt, body],
          },
        );
      }
      statements.push({
        sql: "INSERT OR REPLACE INTO system_stream_checkpoint VALUES (?,?,?)",
        params: [
          identity.connectionId,
          descriptor.stream,
          changes[changes.length - 1]!.seq,
        ],
      });
      statements.push({
        sql: "DELETE FROM system_stream_changes WHERE connection_id=? AND stream=? AND seq<=?",
        params: [
          identity.connectionId,
          descriptor.stream,
          changes[changes.length - 1]!.seq,
        ],
      });
      // Projection and imported position advance in the same local transaction.
      await db.batch(statements);
      applied += changes.length;
      if (changes.length < 200) return applied;
    }
  }
  return {
    project: () => serial("local", project),
    descriptor,
    identity,
    async instanceId(): Promise<string> {
      await db.batch([
        {
          sql: "INSERT OR IGNORE INTO system_stream_instance(id,instance_id) VALUES (1,?)",
          params: [deps.newOp()],
        },
      ]);
      return (
        await db.query<{ instance_id: string }>(
          "SELECT instance_id FROM system_stream_instance WHERE id=1",
        )
      )[0]!.instance_id;
    },
    append(data: JsonObject): Promise<void> {
      return serial("local", async () => {
        await project();
        const { body, sortAt, id } = encode(data);
        const params = [identity.connectionId, descriptor.stream, id];
        const old = await db.query<{ body: string }>(
          "SELECT body FROM system_stream_projection WHERE connection_id=? AND stream=? AND record_id=?",
          params,
        );
        if (old.length) {
          if (old[0]!.body !== body) {
            await db.batch([
              {
                sql: "INSERT OR IGNORE INTO system_stream_quarantine VALUES (?,?,?,?)",
                params: [...params, body],
              },
            ]);
            throw new Error("Conflicting system stream record");
          }
          return;
        }
        await db.batch([
          {
            sql: "INSERT OR IGNORE INTO system_stream_outbox SELECT ?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM system_stream_projection WHERE connection_id=? AND stream=? AND record_id=?)",
            params: [
              ...params,
              body,
              sortAt,
              deps.newOp(),
              deps.now(),
              ...params,
            ],
          },
          {
            sql: "INSERT OR IGNORE INTO system_stream_projection VALUES (?,?,?,?,?)",
            params: [...params, sortAt, body],
          },
        ]);
        const [stored] = await db.query<{ body: string }>(
          "SELECT body FROM system_stream_projection WHERE connection_id=? AND stream=? AND record_id=?",
          params,
        );
        if (stored?.body !== body) {
          await db.batch([
            {
              sql: "INSERT OR IGNORE INTO system_stream_quarantine VALUES (?,?,?,?)",
              params: [...params, body],
            },
          ]);
          throw new Error("Conflicting system stream record");
        }
      });
    },
    /** Bounded canonical retention, shared by all server-owned consumers. */
    removeBefore(cutoff: string): Promise<number> {
      return serial("maintenance", async () => {
        if ((await db.query("SELECT 1 FROM bootstrap_load LIMIT 1")).length)
          return 0;
        await serial("local", project);
        const rows = await db.query<{ record_id: string; body: string }>(
          `SELECT p.record_id,p.body FROM system_stream_projection p
           JOIN records r ON r.connection_id=p.connection_id AND r.stream=p.stream AND r.record_key=p.record_id
           WHERE p.connection_id=? AND p.stream=? AND p.sort_at<? ORDER BY p.sort_at,p.record_id LIMIT 200`,
          [identity.connectionId, descriptor.stream, cutoff],
        );
        if (!rows.length) return 0;
        const [floor] = await db.query<{ o: number }>(
          "SELECT COALESCE(MAX(floor_o),0) AS o FROM stream_state WHERE connection_id=?",
          [identity.connectionId],
        );
        const runId = deps.newOp();
        await intake.begin(
          runId,
          {
            connector: descriptor.connector,
            artifactDigest: `system:${descriptor.version}`,
            owner: { address: deps.ownerAddress, leaseId: null },
            observedAt: Math.max(deps.now(), (floor?.o ?? 0) + 1),
          },
          identity.declarations,
        );
        await intake.batch(runId, {
          batch: 0,
          records: rows.map((row) => ({
            stream: descriptor.stream,
            op: "delete",
            data: JSON.parse(row.body),
          })),
        });
        await end.end(runId, {
          finish: "completed",
          lastBatch: 0,
          checkpoints: {},
          streams: Object.fromEntries([
            [
              descriptor.stream,
              {
                liveRecord: false,
                explicitDelete: true,
                retryableSkip: false,
                otherSkip: false,
                preflightExclusion: false,
                detailGap: "none",
                invalidDetailCoverage: false,
                failedInDone: false,
              },
            ],
          ]),
        });
        for (const row of rows) {
          const remains = await db.query(
            "SELECT 1 FROM records WHERE connection_id=? AND stream=? AND record_key=?",
            [identity.connectionId, descriptor.stream, row.record_id],
          );
          if (remains.length)
            throw new Error("System stream canonical deletion refused");
        }
        await serial("local", project);
        return rows.length;
      });
    },
    /** Bounded recovery sweep; no network work runs in append. */
    drain(): Promise<number> {
      return serial("maintenance", async () => {
        // Bootstrap owns canonical writes across network batches. Keep this
        // outbox durable while the sync cycle finishes that work first.
        if ((await db.query("SELECT 1 FROM bootstrap_load LIMIT 1")).length)
          return 0;
        await serial("local", project);
        const rows = await db.query<{
          record_id: string;
          body: string;
          run_id: string;
          observed_at: number;
        }>(
          "SELECT record_id,body,run_id,observed_at FROM system_stream_outbox WHERE connection_id=? AND stream=? ORDER BY observed_at,record_id LIMIT 200",
          [identity.connectionId, descriptor.stream],
        );
        for (const row of rows) {
          if (!(await canonical(row.record_id, row.body))) {
            const [run] = await db.query<{ state: string }>(
              "SELECT state FROM runs WHERE run_id=?",
              [row.run_id],
            );
            if (run?.state === "ended") {
              row.run_id = deps.newOp();
              row.observed_at = Math.max(deps.now(), row.observed_at + 1);
              await db.batch([
                {
                  sql: "UPDATE system_stream_outbox SET run_id=?,observed_at=? WHERE connection_id=? AND stream=? AND record_id=?",
                  params: [
                    row.run_id,
                    row.observed_at,
                    identity.connectionId,
                    descriptor.stream,
                    row.record_id,
                  ],
                },
              ]);
            }
            if (!run || run.state === "ended") {
              const [floor] = await db.query<{ o: number }>(
                "SELECT COALESCE(MAX(floor_o),0) AS o FROM stream_state WHERE connection_id=?",
                [identity.connectionId],
              );
              row.observed_at = Math.max(row.observed_at, (floor?.o ?? 0) + 1);
              await db.batch([
                {
                  sql: "UPDATE system_stream_outbox SET observed_at=? WHERE connection_id=? AND stream=? AND record_id=?",
                  params: [
                    row.observed_at,
                    identity.connectionId,
                    descriptor.stream,
                    row.record_id,
                  ],
                },
              ]);
            }
            const req = {
              connector: descriptor.connector,
              artifactDigest: `system:${descriptor.version}`,
              owner: { address: deps.ownerAddress, leaseId: null },
              observedAt: row.observed_at,
            };
            await intake.begin(row.run_id, req, identity.declarations);
            await intake.batch(row.run_id, {
              batch: 0,
              records: [
                {
                  stream: descriptor.stream,
                  op: "upsert",
                  data: JSON.parse(row.body),
                },
              ],
            });
            await end.end(row.run_id, {
              finish: "completed",
              lastBatch: 0,
              checkpoints: {},
              streams: Object.fromEntries([
                [
                  descriptor.stream,
                  {
                    liveRecord: true,
                    explicitDelete: false,
                    retryableSkip: false,
                    otherSkip: false,
                    preflightExclusion: false,
                    detailGap: "none",
                    invalidDetailCoverage: false,
                    failedInDone: false,
                  },
                ],
              ]),
            });
          }
          // Accepted/staged is not canonical admission. A fence or profile refusal
          // keeps the outbox durable and refuses acknowledgement.
          if (!(await canonical(row.record_id, row.body)))
            throw new Error("System stream canonical admission refused");
          await db.batch([
            {
              sql: "DELETE FROM system_stream_outbox WHERE connection_id=? AND stream=? AND record_id=? AND body=?",
              params: [
                identity.connectionId,
                descriptor.stream,
                row.record_id,
                row.body,
              ],
            },
          ]);
        }
        return rows.length;
      });
    },
  };
}

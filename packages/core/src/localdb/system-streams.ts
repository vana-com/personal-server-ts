import {
  canonicalJson,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { LocalSyncDeps } from "./deps.js";
import { createRunIntakeStore } from "./run-intake.js";
import { createRunEndStore } from "./run-end.js";
import {
  systemStreamIdentity,
  type SystemStreamDescriptor,
} from "./system-stream-descriptor.js";

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
  const intake = createRunIntakeStore(deps, descriptor);
  const end = createRunEndStore(deps);
  let tail: Promise<unknown> = Promise.resolve();
  function serial<T>(work: () => Promise<T>): Promise<T> {
    const result = tail.catch(() => {}).then(work);
    tail = result;
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
  return {
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
      return serial(async () => {
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
            sql: "INSERT INTO system_stream_outbox VALUES (?,?,?,?,?,?,?)",
            params: [...params, body, sortAt, deps.newOp(), deps.now()],
          },
          {
            sql: "INSERT INTO system_stream_projection VALUES (?,?,?,?,?)",
            params: [...params, sortAt, body],
          },
        ]);
      });
    },
    /** Bounded recovery sweep; no network work runs in append. */
    drain(): Promise<number> {
      return serial(async () => {
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
              streams: {
                [descriptor.stream]: {
                  liveRecord: true,
                  explicitDelete: false,
                  retryableSkip: false,
                  otherSkip: false,
                  preflightExclusion: false,
                  detailGap: "none",
                  invalidDetailCoverage: false,
                  failedInDone: false,
                },
              },
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

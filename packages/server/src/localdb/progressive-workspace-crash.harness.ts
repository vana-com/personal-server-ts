import { randomUUID } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/index.js";
import {
  openLogWorkspace,
  openProgressiveLogWorkspace,
} from "../../../core/src/localdb/workspace-consumer.js";
import { pkHash } from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";

export const binding = {
  owner: "o",
  databaseIncarnation: "db",
  connection: "c",
  generation: 1,
  keyCheck: "key",
  operation: "partial-crash",
  expectedHead: "head",
  codecVersion: 1,
};
export const identity = { dataHash: "head", blobName: "blob" };
export async function replay(
  db: SqlDriver,
  stopAfterSetup = false,
  useOwner = false,
) {
  const ws = useOwner
    ? await openProgressiveLogWorkspace(db, binding, randomUUID)
    : await openLogWorkspace(db, binding);
  const meta = {
    stream: "s",
    primaryKey: ["id"],
    profile: { key: null, version: "1" },
    complete: true,
  };
  const hash = await pkHash(async (bytes) => sha256(bytes), { id: "k" }, [
    "id",
  ]);
  await ws.partial.initialize({
    start: 0,
    snapshot: true,
    total: 3,
    finalIdentity: identity,
    observedAt: 0,
  });
  await ws.partial.name(
    2,
    meta,
    { generation: 1, observedAt: 0 },
    identity,
    true,
  );
  await ws.partial.noteKey(1, "s", hash, ["k"], { o: 2, r: "r" });
  for (let index = 0; index < 3; index++)
    await ws.partial.scanned(index, identity);
  if (stopAfterSetup) return;
  const lease = await ws.acquire(128 * 1024 * 1024);
  try {
    for (let index = 0; index < 3; index++) {
      const operations =
        index === 1
          ? [
              {
                kind: "delete" as const,
                stream: "s",
                pkHash: hash,
                key: ["k"],
                stamp: { o: 2, r: "r" },
              },
            ]
          : [
              {
                kind: "upsert" as const,
                stream: "s",
                pkHash: hash,
                stamp: { o: index + 1, r: "r" },
                firstSeen: null,
                value: { id: "k", v: index + 1 },
              },
            ];
      await ws.partial.commitPart(
        index,
        { generation: 1, observedAt: 0, streams: [meta], operations },
        identity,
        () => `part-${index}`,
        lease,
        index === 2
          ? { position: 3, base: 3, refs: [], snapshot: null }
          : undefined,
      );
    }
  } finally {
    await lease.release();
  }
}
if (process.argv[1]?.endsWith("progressive-workspace-crash.harness.ts")) {
  const [path, edge, target] = process.argv.slice(2);
  const db = await openLocalDb(openBetterSqlite3(path!), {
    owner: "o",
    network: "test",
    deviceId: "d",
  });
  const actual = db.batch.bind(db);
  db.batch = async (statements) => {
    const match = statements.some((s) =>
      target === "owner"
        ? s.sql.startsWith("INSERT OR REPLACE INTO workspace_partial_passes")
        : target === "scan"
          ? s.sql.startsWith("INSERT OR REPLACE INTO workspace_cells") &&
            s.params?.[1] === "partial-parts"
          : target === "body"
            ? s.sql.startsWith(
                "INSERT OR REPLACE INTO workspace_partial_incoming",
              )
            : s.sql.startsWith("INSERT INTO workspace_receipts") &&
              s.params?.[1] === target,
    );
    const stop = async () => {
      process.send!({ edge, target });
      await new Promise(() => {});
    };
    if (match && edge === "before") await stop();
    const result = await actual(statements);
    if (match && edge === "after") await stop();
    return result;
  };
  await replay(db, false, true);
  throw new Error("boundary_not_reached");
}

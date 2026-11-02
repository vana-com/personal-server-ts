import type { Database, Statement } from "better-sqlite3";
import type {
  ReplicaEffectContext,
  ReplicaSql,
  ReplicaSqlValue,
} from "@opendatalabs/personal-server-ts-core/replication/effects";

const statements = new WeakMap<Database, Map<string, Statement>>();
/**
 * Prepared statements kept per database, least recently used first out.
 * Some engine queries embed the step's clock in their text, so an unbounded
 * cache would grow by a few statements every step.
 */
export const REPLICA_STATEMENT_CACHE_SIZE = 256;

/** better-sqlite3 binds Buffers; a plain Uint8Array becomes a view of the same bytes. */
const bind = (params: readonly ReplicaSqlValue[]) =>
  params.map((value) =>
    value instanceof Uint8Array && !Buffer.isBuffer(value)
      ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
      : value,
  );

/** Shared replica effects over a synchronous better-sqlite3 connection. */
export function nodeReplicaSql(db: Database): ReplicaSql {
  let cache = statements.get(db);
  if (!cache) statements.set(db, (cache = new Map()));
  const prepared = (text: string) => {
    let statement = cache.get(text);
    if (statement) cache.delete(text);
    else statement = db.prepare(text);
    cache.set(text, statement);
    if (cache.size > REPLICA_STATEMENT_CACHE_SIZE)
      cache.delete(cache.keys().next().value!);
    return statement;
  };
  return {
    get: (text, params) =>
      prepared(text).get(...bind(params)) as
        Record<string, unknown> | undefined,
    all: (text, params) =>
      prepared(text).all(...bind(params)) as Record<string, unknown>[],
    run: (text, params) => ({
      changes: prepared(text).run(...bind(params)).changes,
    }),
    exec: (text) => {
      db.exec(text);
    },
  };
}

/** The effect context for Node: statements run on the caller's connection. */
export const nodeReplicaContext = (db: Database): ReplicaEffectContext => ({
  sql: nodeReplicaSql(db),
});

import { Worker } from "node:worker_threads";
import Database from "better-sqlite3";
import type {
  SqlDriver,
  SqlReader,
  SqlStatement,
  SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";

export { createStatementCache } from "./statement-cache.cjs";

interface WorkerReply {
  readonly id: number;
  readonly ok: boolean;
  readonly result?: unknown;
  readonly error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string;
  };
}

/** Statement texts the worker may hold by id; later texts travel inline. */
const MAX_STATEMENT_IDS = 256;

/** A statement on the wire: its text only on first use, then its id. */
interface WireStatement {
  readonly sid?: number;
  readonly sql?: string;
  readonly params?: readonly SqlValue[];
}

/** Structured clone turns a Buffer into a plain Uint8Array; callers read
 * blobs as Buffers from the native driver, so restore that type. */
const asBuffers = <R extends Record<string, SqlValue>>(rows: R[]): R[] => {
  for (const row of rows)
    for (const key in row) {
      const v = row[key];
      if (v instanceof Uint8Array && !Buffer.isBuffer(v))
        (row as Record<string, SqlValue>)[key] = Buffer.from(
          v.buffer,
          v.byteOffset,
          v.byteLength,
        );
    }
  return rows;
};

/** One worker thread that owns one connection, and the calls into it. */
interface Connection {
  query<R extends Record<string, SqlValue>>(
    sql: string,
    params?: readonly SqlValue[],
  ): Promise<R[]>;
  batch(
    statements: readonly SqlStatement[],
  ): Promise<{ changes: readonly number[] }>;
  close(): Promise<void>;
}

function connect(
  path: string,
  role: "writer" | "reader",
  lockTimeoutMs: number | undefined,
): Connection {
  const worker = new Worker(
    new URL("./better-sqlite3-worker.cjs", import.meta.url),
    {
      workerData: { path, role, lockTimeoutMs },
      // A small young generation makes V8 reclaim received messages early.
      resourceLimits: { maxYoungGenerationSizeMb: 2 },
    },
  );
  // An idle worker must not keep the process alive; pending calls re-ref it.
  worker.unref();
  const pending = new Map<
    number,
    { resolve(value: unknown): void; reject(error: Error): void }
  >();
  let nextId = 0;
  let failure: Error | undefined;
  const settle = (id: number, reply: WorkerReply) => {
    const call = pending.get(id);
    if (!call) return;
    pending.delete(id);
    if (pending.size === 0) worker.unref();
    if (reply.ok) return call.resolve(reply.result);
    const { name, message, stack, code } = reply.error!;
    call.reject(Object.assign(new Error(message), { name, stack, code }));
  };
  worker.on("message", (reply: WorkerReply) => settle(reply.id, reply));
  const fail = (error: Error) => {
    failure ??= error;
    for (const [id, call] of pending) {
      pending.delete(id);
      call.reject(error);
    }
  };
  worker.on("error", fail);
  worker.on("exit", (code) => {
    if (!closed) fail(new Error(`sqlite_worker_exited_${code}`));
  });
  let closed = false;
  // A statement's text crosses the thread boundary once; later calls send its
  // id. Messages are handled in order, so the first one has registered the id.
  const statementIds = new Map<string, number>();
  const wire = (statement: SqlStatement): WireStatement => {
    const sid = statementIds.get(statement.sql);
    if (sid !== undefined) return { sid, params: statement.params };
    if (statementIds.size >= MAX_STATEMENT_IDS)
      return { sql: statement.sql, params: statement.params };
    statementIds.set(statement.sql, statementIds.size);
    return {
      sid: statementIds.size - 1,
      sql: statement.sql,
      params: statement.params,
    };
  };
  const call = <T>(message: Record<string, unknown>): Promise<T> => {
    if (failure) return Promise.reject(failure);
    if (closed) return Promise.reject(new Error("sqlite_driver_closed"));
    return new Promise<T>((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      worker.ref();
      worker.postMessage({ id, ...message });
    });
  };
  return {
    async query<R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) {
      return asBuffers(
        await call<R[]>({ op: "query", ...wire({ sql, params }) }),
      );
    },
    batch(statements) {
      return call<{ changes: readonly number[] }>({
        op: "batch",
        statements: statements.map(wire),
      });
    },
    async close() {
      try {
        await call({ op: "close" });
      } finally {
        closed = true;
        await worker.terminate();
      }
    },
  };
}

/**
 * Node and Desktop driver. A worker thread owns the writing connection, so a
 * long `batch` (a synchronous BEGIN IMMEDIATE ... COMMIT) never holds this
 * thread's event loop, and every statement runs in order on one connection.
 *
 * A file database also has `reads`: a second worker thread with a read-only
 * connection to the same WAL file, started on its first read. A read on it
 * waits for no write. `close()` closes both connections.
 *
 * The process holds the file exclusively: a lock file next to the database
 * (see the worker) refuses a second process, as the old
 * `locking_mode=EXCLUSIVE` on the database did. `lockTimeoutMs` is how long a
 * second opener waits for it (default: SQLite's 5 s).
 * `path` is a file path, or `:memory:`, which has no separate read connection.
 */
export function openBetterSqlite3(
  path: string,
  options: { readonly lockTimeoutMs?: number } = {},
): SqlDriver {
  // Read the version here: `info` is synchronous and the worker is not up yet.
  const probe = new Database(":memory:");
  const { v } = probe.prepare("SELECT sqlite_version() AS v").get() as {
    v: string;
  };
  probe.close();

  const persistent = path !== ":memory:";
  const writer = connect(path, "writer", options.lockTimeoutMs);
  let reader: Connection | undefined;
  let closed = false;
  const reads: SqlReader | undefined = persistent
    ? {
        query<R extends Record<string, SqlValue>>(
          sql: string,
          params?: readonly SqlValue[],
        ) {
          if (closed) return Promise.reject(new Error("sqlite_driver_closed"));
          reader ??= connect(path, "reader", undefined);
          return reader.query<R>(sql, params);
        },
      }
    : undefined;

  return {
    info: { sqliteVersion: v, host: "node", persistent },
    query: writer.query,
    batch: writer.batch,
    ...(reads ? { reads } : {}),
    async close() {
      closed = true;
      try {
        await reader?.close();
      } finally {
        await writer.close();
      }
    },
  };
}

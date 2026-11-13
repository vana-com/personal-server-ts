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
  /** The writer's real path and file identity (`dev:ino`). Writer only. */
  identify(): Promise<{ path: string; identity: string }>;
  /** Fails every pending call with `error` and ends the worker. */
  abort(error: Error): Promise<void>;
}

/** Test only: a CommonJS module the workers call at fixed points of the open sequence. */
export interface TestSeam {
  readonly module: string;
  readonly data?: unknown;
}

function connect(
  path: string,
  role: "writer" | "reader",
  options: {
    readonly lockTimeoutMs?: number;
    /** The file the reader may serve: the writer's `dev:ino`. */
    readonly identity?: string;
    readonly testSeam?: TestSeam;
    /** The worker died or errored without `close()`, once. */
    readonly onFailure?: (error: Error) => void;
  } = {},
): Connection {
  const worker = new Worker(
    new URL("./better-sqlite3-worker.cjs", import.meta.url),
    {
      workerData: {
        path,
        role,
        lockTimeoutMs: options.lockTimeoutMs,
        identity: options.identity,
        testSeam: options.testSeam,
      },
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
    const first = failure === undefined;
    failure ??= error;
    for (const [id, call] of pending) {
      pending.delete(id);
      call.reject(error);
    }
    if (first) options.onFailure?.(error);
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
    identify() {
      return call<{ path: string; identity: string }>({ op: "identity" });
    },
    async abort(error) {
      closed = true;
      fail(error);
      await worker.terminate();
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
 * connection to the same WAL file, started on its first read and bound to the
 * file the writer holds. A read on it waits for no write. `close()` closes
 * both connections. If the writer worker dies or errors without `close()`,
 * the read connection is closed and reads fail with `sqlite_writer_failed`.
 *
 * The process holds the file exclusively: a lock file next to the database
 * (see the worker) refuses a second process, as the old
 * `locking_mode=EXCLUSIVE` on the database did. `lockTimeoutMs` is how long a
 * second opener waits for it (default: SQLite's 5 s).
 * `path` is a file path, or `:memory:`, which has no separate read connection.
 */
export function openBetterSqlite3(
  path: string,
  options: {
    readonly lockTimeoutMs?: number;
    /** Test only; see `TestSeam`. */
    readonly testSeam?: TestSeam;
  } = {},
): SqlDriver {
  // Read the version here: `info` is synchronous and the worker is not up yet.
  const probe = new Database(":memory:");
  const { v } = probe.prepare("SELECT sqlite_version() AS v").get() as {
    v: string;
  };
  probe.close();

  const persistent = path !== ":memory:";
  let closed = false;
  let writerFailure: Error | undefined;
  let readerReady: Promise<Connection> | undefined;
  // A reader must not outlive its writer: if the writer worker dies or errors
  // without `close()`, nobody owns the file, so the reader stops answering.
  const onWriterFailure = (cause: Error) => {
    if (closed) return;
    writerFailure = new Error(`sqlite_writer_failed: ${cause.message}`, {
      cause,
    });
    void readerReady
      ?.then((r) => r.abort(writerFailure!))
      .catch(() => undefined);
  };
  const writer = connect(path, "writer", {
    lockTimeoutMs: options.lockTimeoutMs,
    testSeam: options.testSeam,
    onFailure: onWriterFailure,
  });
  // The reader starts on its first read, bound to the file the writer holds:
  // it gets the writer's real path and `dev:ino`. The writer is asked at open
  // (first in its queue), so a first read never waits behind a long write. A
  // writer that failed to open (a second process, say) gives no reader.
  const identified = persistent ? writer.identify() : undefined;
  identified?.catch(() => undefined);
  const startReader = () =>
    identified!.then(({ path: real, identity }) => {
      if (writerFailure) throw writerFailure;
      if (closed) throw new Error("sqlite_driver_closed");
      return connect(real, "reader", { identity, testSeam: options.testSeam });
    });
  const reads: SqlReader | undefined = persistent
    ? {
        async query<R extends Record<string, SqlValue>>(
          sql: string,
          params?: readonly SqlValue[],
        ) {
          if (closed) throw new Error("sqlite_driver_closed");
          if (writerFailure) throw writerFailure;
          readerReady ??= startReader();
          return (await readerReady).query<R>(sql, params);
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
        const reader = await readerReady?.catch(() => undefined);
        await reader?.close();
      } finally {
        await writer.close();
      }
    },
  };
}

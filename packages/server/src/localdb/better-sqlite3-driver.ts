import { Worker } from "node:worker_threads";
import Database from "better-sqlite3";
import type {
  SqlDriver,
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

/**
 * Node and Desktop driver. A worker thread owns the one connection, so a
 * long `batch` (a synchronous BEGIN IMMEDIATE ... COMMIT) never holds this
 * thread's event loop, and every statement runs in order on one connection.
 * The process holds the file exclusively (`locking_mode=EXCLUSIVE`).
 * `path` is a file path, or `:memory:`.
 */
export function openBetterSqlite3(path: string): SqlDriver {
  // Read the version here: `info` is synchronous and the worker is not up yet.
  const probe = new Database(":memory:");
  const { v } = probe.prepare("SELECT sqlite_version() AS v").get() as {
    v: string;
  };
  probe.close();

  const worker = new Worker(
    new URL("./better-sqlite3-worker.cjs", import.meta.url),
    {
      workerData: { path },
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
    info: {
      sqliteVersion: v,
      host: "node",
      persistent: path !== ":memory:",
    },
    async query<R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) {
      return asBuffers(await call<R[]>({ op: "query", sql, params }));
    },
    batch(statements: readonly SqlStatement[]) {
      return call<{ changes: readonly number[] }>({
        op: "batch",
        statements,
      });
    },
    async close() {
      await call({ op: "close" });
      closed = true;
      await worker.terminate();
    },
  };
}

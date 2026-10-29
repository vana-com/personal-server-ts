/**
 * Storage effects: phase logic written once, run by a synchronous host
 * (Node, better-sqlite3) and by an asynchronous one (PS-Lite, a native
 * transaction over a bridge).
 *
 * An effect is a generator. Each value it yields is one storage operation,
 * a function of the host's transaction context. A runner calls the
 * operation and resumes the generator with its result, or throws its error
 * into the generator, so `try`/`catch` inside phase logic works the same on
 * both hosts. The synchronous runner refuses an operation that returns a
 * promise: Node's transactions cannot span an `await`, so a synchronous
 * host must never be handed asynchronous work.
 *
 * Phase logic composes effects with `yield*`. It never awaits inside an
 * effect; I/O happens outside transactions, between effects.
 */

/**
 * One storage operation, run by the host against its transaction context.
 * Contravariant in its context, so an effect over the base context composes
 * into any richer host context.
 */
export type ReplicaOp<C = ReplicaEffectContext> = (context: C) => unknown;

/** A computation over host storage that returns `T`. */
export type ReplicaEffect<T, C = ReplicaEffectContext> = Generator<
  ReplicaOp<C>,
  T,
  unknown
>;

/** The SQLite dialect both hosts run. Parameters never carry large bytes. */
export type ReplicaSqlValue = string | number | bigint | null | Uint8Array;
export type ReplicaSqlRow = Record<string, unknown>;

/**
 * Statement execution in the host's current transaction. Node answers
 * synchronously (better-sqlite3); PS-Lite answers with promises (native
 * SQLite over the bridge). Statements are PS constants, never user input.
 */
export interface ReplicaSql {
  get(
    sql: string,
    params: readonly ReplicaSqlValue[],
  ): ReplicaSqlRow | undefined | Promise<ReplicaSqlRow | undefined>;
  all(
    sql: string,
    params: readonly ReplicaSqlValue[],
  ): ReplicaSqlRow[] | Promise<ReplicaSqlRow[]>;
  run(
    sql: string,
    params: readonly ReplicaSqlValue[],
  ): { changes: number } | Promise<{ changes: number }>;
  /** Run a parameterless script: schema migrations only. */
  exec(sql: string): void | Promise<void>;
}

/** What every host context offers. Hosts extend it with their own handles. */
export interface ReplicaEffectContext {
  readonly sql: ReplicaSql;
}

/** Yield one operation and return its result. */
export function* perform<T, C = ReplicaEffectContext>(
  op: (context: C) => T | Promise<T>,
): ReplicaEffect<T, C> {
  return (yield op as ReplicaOp<C>) as T;
}

const thenable = (value: unknown): value is PromiseLike<unknown> =>
  typeof value === "object" &&
  value !== null &&
  typeof (value as { then?: unknown }).then === "function";

/** Thrown when a synchronous host is handed asynchronous storage work. */
export class ReplicaAsyncEffectError extends Error {
  constructor() {
    super("replica effect returned a promise in a synchronous host");
    this.name = "ReplicaAsyncEffectError";
  }
}

/** Run an effect to completion inside the caller's synchronous transaction. */
export function runEffectSync<T, C>(
  effect: ReplicaEffect<T, C>,
  context: C,
): T {
  let step = effect.next();
  while (!step.done) {
    let value: unknown;
    try {
      value = step.value(context);
      if (thenable(value)) {
        // Never leave the operation's rejection unobserved.
        Promise.resolve(value).catch(() => undefined);
        throw new ReplicaAsyncEffectError();
      }
    } catch (error) {
      step = effect.throw(error);
      continue;
    }
    step = effect.next(value);
  }
  return step.value;
}

/** Run an effect to completion inside the caller's asynchronous transaction. */
export async function runEffectAsync<T, C>(
  effect: ReplicaEffect<T, C>,
  context: C,
): Promise<T> {
  let step = effect.next();
  while (!step.done) {
    let value: unknown;
    try {
      value = await step.value(context);
    } catch (error) {
      step = effect.throw(error);
      continue;
    }
    step = effect.next(value);
  }
  return step.value;
}

/** Statement helpers. Every call is one yielded operation. */
export const sql = {
  get<R = ReplicaSqlRow>(text: string, ...params: ReplicaSqlValue[]) {
    return perform<R | undefined>(
      (context) =>
        context.sql.get(text, params) as R | undefined | Promise<R | undefined>,
    );
  },
  all<R = ReplicaSqlRow>(text: string, ...params: ReplicaSqlValue[]) {
    return perform<R[]>(
      (context) => context.sql.all(text, params) as R[] | Promise<R[]>,
    );
  },
  run(text: string, ...params: ReplicaSqlValue[]) {
    return perform<{ changes: number }>((context) =>
      context.sql.run(text, params),
    );
  },
  exec(text: string) {
    return perform<void>((context) => context.sql.exec(text));
  },
};

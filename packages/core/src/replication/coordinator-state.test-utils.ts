import {
  ReplicaCoordinatorConflict,
  type AsyncReplicaCoordinatorStatePort,
  type ReplicaCoordinatorState,
  type ReplicaCoordinatorStatePort,
  type ReplicaRotation,
} from "./coordinator.js";

type MaybePromise<T> = T | Promise<T>;

/** Sequence without awaiting, so a synchronous harness stays synchronous. */
const then = <T, R>(value: MaybePromise<T>, next: (value: T) => R) =>
  value instanceof Promise ? value.then(next) : next(value);

/**
 * One harness per adapter: Node's synchronous SQLite port and PS-Lite's
 * asynchronous native-transaction port run this same contract. `context` is
 * the port's open transaction, passed to calls made inside a checkpoint; a
 * synchronous port passes `undefined`.
 */
export interface ReplicaCoordinatorContractHarness<C = unknown> {
  port(
    owner: string,
  ): ReplicaCoordinatorStatePort | AsyncReplicaCoordinatorStatePort<C>;
  acquire(owner: string): MaybePromise<void>;
  /** Simulate confirmed loss of the old exclusive owner, not lease expiry. */
  recover(owner: string, context?: C): MaybePromise<void>;
  checkpoint(value: string, context?: C): MaybePromise<void>;
  receipts(): MaybePromise<string[]>;
  failCursorWrites(fail: boolean): MaybePromise<void>;
  close(): MaybePromise<void>;
}

/**
 * The caller injects its test runner's `test` and `expect` so this module stays
 * free of Node built-ins and test-runner imports (core must stay browser-safe).
 */
export interface ReplicaCoordinatorContractRunner {
  test(name: string, run: () => Promise<void>): void;
  expect(actual: unknown): {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
  };
}

export function replicaCoordinatorStateContract<C>(
  { test, expect }: ReplicaCoordinatorContractRunner,
  open: () => MaybePromise<ReplicaCoordinatorContractHarness<C>>,
): void {
  const check = (
    name: string,
    run: (h: ReplicaCoordinatorContractHarness<C>) => Promise<void>,
  ) =>
    test(name, async () => {
      const h = await open();
      try {
        await run(h);
      } finally {
        await h.close();
      }
    });
  /** Expect `run` to throw or reject, optionally with a type or message. */
  async function throws(
    run: () => unknown,
    expected?: string | (abstract new (...args: never[]) => Error),
  ) {
    let thrown: unknown;
    try {
      await run();
    } catch (error) {
      thrown = error ?? new Error("thrown nullish");
    }
    expect(thrown !== undefined).toBe(true);
    if (typeof expected === "string")
      expect(String((thrown as Error).message).includes(expected)).toBe(true);
    else if (expected) expect(thrown instanceof expected).toBe(true);
  }
  /** One commit through either port kind, awaiting what is asynchronous. */
  async function commit<T>(
    port: ReplicaCoordinatorStatePort | AsyncReplicaCoordinatorStatePort<C>,
    expected: ReplicaCoordinatorState,
    next: ReplicaRotation,
    checkpoint: (context: C | undefined) => MaybePromise<T>,
  ) {
    if ("async" in port && port.async)
      return port.commit(expected, next, async (context) =>
        checkpoint(context),
      );
    return (port as ReplicaCoordinatorStatePort).commit(expected, next, () => {
      const result = checkpoint(undefined);
      if (result instanceof Promise)
        throw new Error("synchronous harness returned a promise");
      return result as T;
    });
  }
  const rotation = {
    nextPhase: "import" as const,
    writers: { publish: "writer-a" },
  };

  check(
    "persists cursor, checkpoint and revision together across adapter recreation",
    async (h) => {
      await h.acquire("a");
      const port = h.port("a");
      const initial = await port.load();
      expect(initial.version).toBe(0);
      expect(initial.writers).toEqual({});
      const committed = await commit(port, initial, rotation, (tx) =>
        then(h.checkpoint("one", tx), () => 7),
      );
      expect(committed.result).toBe(7);
      expect(await h.receipts()).toEqual(["one"]);
      expect(await h.port("a").load()).toEqual({
        ...rotation,
        owner: "a",
        version: 1,
      });
      committed.state.writers.publish = "mutated-return";
      expect((await h.port("a").load()).writers.publish).toBe("writer-a");
    },
  );

  check(
    "a throwing checkpoint rolls back both receipt and cursor",
    async (h) => {
      await h.acquire("a");
      const port = h.port("a");
      const initial = await port.load();
      await throws(
        () =>
          commit(port, initial, rotation, (tx) =>
            then(h.checkpoint("lost", tx), () => {
              throw new Error("rollback");
            }),
          ),
        "rollback",
      );
      expect(await h.receipts()).toEqual([]);
      expect(await port.load()).toEqual(initial);
    },
  );

  check("a cursor-write failure cannot leave a durable receipt", async (h) => {
    await h.acquire("a");
    const port = h.port("a");
    const initial = await port.load();
    await h.failCursorWrites(true);
    await throws(() =>
      commit(port, initial, rotation, (tx) => h.checkpoint("lost", tx)),
    );
    expect(await h.receipts()).toEqual([]);
    expect(await port.load()).toEqual(initial);
    await h.failCursorWrites(false);
    await commit(port, initial, rotation, (tx) => h.checkpoint("retry", tx));
    expect(await h.receipts()).toEqual(["retry"]);
    expect((await port.load()).version).toBe(1);
  });

  check("a stale revision never runs a checkpoint", async (h) => {
    await h.acquire("a");
    const port = h.port("a");
    const old = await port.load();
    await commit(port, old, rotation, (tx) => h.checkpoint("new", tx));
    await throws(
      () => commit(port, old, rotation, (tx) => h.checkpoint("stale", tx)),
      ReplicaCoordinatorConflict,
    );
    expect(await h.receipts()).toEqual(["new"]);
  });

  check(
    "active owners contend; a recovered owner rejects old receipts",
    async (h) => {
      await h.acquire("a");
      const old = await h.port("a").load();
      await throws(() => h.acquire("b"));
      await throws(() => h.port("b").load(), ReplicaCoordinatorConflict);
      await h.recover("b");
      const next = h.port("b");
      await commit(next, await next.load(), rotation, (tx) =>
        h.checkpoint("b", tx),
      );
      await throws(
        () =>
          commit(h.port("a"), old, rotation, (tx) =>
            h.checkpoint("late-a", tx),
          ),
        ReplicaCoordinatorConflict,
      );
      expect(await h.receipts()).toEqual(["b"]);
      expect((await next.load()).version).toBe(1);
    },
  );

  check(
    "ownership changed inside a checkpoint rolls back the whole transaction",
    async (h) => {
      await h.acquire("a");
      const port = h.port("a");
      const initial = await port.load();
      await throws(
        () =>
          commit(port, initial, rotation, (tx) =>
            then(h.checkpoint("lost", tx), () => h.recover("b", tx)),
          ),
        ReplicaCoordinatorConflict,
      );
      expect(await h.receipts()).toEqual([]);
      expect(await port.load()).toEqual(initial);
    },
  );
}

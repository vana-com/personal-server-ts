import {
  ReplicaCoordinatorConflict,
  type ReplicaCoordinatorStatePort,
} from "./coordinator.js";

/** A future Lite native adapter must run this same contract on real storage. */
export interface ReplicaCoordinatorContractHarness {
  port(owner: string): ReplicaCoordinatorStatePort;
  acquire(owner: string): void;
  /** Simulate confirmed loss of the old exclusive owner, not lease expiry. */
  recover(owner: string): void;
  checkpoint(value: string): void;
  receipts(): string[];
  failCursorWrites(fail: boolean): void;
  close(): void;
}

/**
 * The caller injects its test runner's `test` and `expect` so this module stays
 * free of Node built-ins and test-runner imports (core must stay browser-safe).
 */
export interface ReplicaCoordinatorContractRunner {
  test(name: string, run: () => void): void;
  expect(actual: unknown): {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
    toThrow(expected?: unknown): void;
  };
}

export function replicaCoordinatorStateContract(
  { test, expect }: ReplicaCoordinatorContractRunner,
  open: () => ReplicaCoordinatorContractHarness,
): void {
  const check = (
    name: string,
    run: (h: ReplicaCoordinatorContractHarness) => void,
  ) =>
    test(name, () => {
      const h = open();
      try {
        run(h);
      } finally {
        h.close();
      }
    });
  const rotation = {
    nextPhase: "import" as const,
    writers: { publish: "writer-a" },
  };

  check(
    "persists cursor, checkpoint and revision together across adapter recreation",
    (h) => {
      h.acquire("a");
      const port = h.port("a");
      const initial = port.load();
      expect(initial.version).toBe(0);
      expect(initial.writers).toEqual({});
      const committed = port.commit(initial, rotation, () => {
        h.checkpoint("one");
        return 7;
      });
      expect(committed.result).toBe(7);
      expect(h.receipts()).toEqual(["one"]);
      expect(h.port("a").load()).toEqual({
        ...rotation,
        owner: "a",
        version: 1,
      });
      committed.state.writers.publish = "mutated-return";
      expect(h.port("a").load().writers.publish).toBe("writer-a");
    },
  );

  check("a throwing checkpoint rolls back both receipt and cursor", (h) => {
    h.acquire("a");
    const port = h.port("a");
    const initial = port.load();
    expect(() =>
      port.commit(initial, rotation, () => {
        h.checkpoint("lost");
        throw new Error("rollback");
      }),
    ).toThrow("rollback");
    expect(h.receipts()).toEqual([]);
    expect(port.load()).toEqual(initial);
  });

  check("a cursor-write failure cannot leave a durable receipt", (h) => {
    h.acquire("a");
    const port = h.port("a");
    const initial = port.load();
    h.failCursorWrites(true);
    expect(() =>
      port.commit(initial, rotation, () => h.checkpoint("lost")),
    ).toThrow();
    expect(h.receipts()).toEqual([]);
    expect(port.load()).toEqual(initial);
    h.failCursorWrites(false);
    port.commit(initial, rotation, () => h.checkpoint("retry"));
    expect(h.receipts()).toEqual(["retry"]);
    expect(port.load().version).toBe(1);
  });

  check("a stale revision never runs a checkpoint", (h) => {
    h.acquire("a");
    const port = h.port("a");
    const old = port.load();
    port.commit(old, rotation, () => h.checkpoint("new"));
    expect(() =>
      port.commit(old, rotation, () => h.checkpoint("stale")),
    ).toThrow(ReplicaCoordinatorConflict);
    expect(h.receipts()).toEqual(["new"]);
  });

  check(
    "active owners contend; a recovered owner rejects old receipts",
    (h) => {
      h.acquire("a");
      const old = h.port("a").load();
      expect(() => h.acquire("b")).toThrow();
      expect(() => h.port("b").load()).toThrow(ReplicaCoordinatorConflict);
      h.recover("b");
      const next = h.port("b");
      next.commit(next.load(), rotation, () => h.checkpoint("b"));
      expect(() =>
        h.port("a").commit(old, rotation, () => h.checkpoint("late-a")),
      ).toThrow(ReplicaCoordinatorConflict);
      expect(h.receipts()).toEqual(["b"]);
      expect(next.load().version).toBe(1);
    },
  );

  check(
    "ownership changed inside a checkpoint rolls back the whole transaction",
    (h) => {
      h.acquire("a");
      const port = h.port("a");
      const initial = port.load();
      expect(() =>
        port.commit(initial, rotation, () => {
          h.checkpoint("lost");
          h.recover("b");
        }),
      ).toThrow(ReplicaCoordinatorConflict);
      expect(h.receipts()).toEqual([]);
      expect(port.load()).toEqual(initial);
    },
  );
}

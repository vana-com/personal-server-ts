/**
 * The one owner of "the legacy import is done" for an Account.
 *
 * The account-mode authority persists `importPending` when the Account is
 * first switched on, refuses ordinary stream commits (503 `IMPORT_PENDING`)
 * while it is set, and clears it when told `importDone(owner)`. The import and
 * its ledger keep NO done flag of their own: they read this port, and tell it
 * once the import is proven and published. This is the narrow port they need,
 * with the authority's own method names; a host binds it to the authority.
 * Owners are lowercase in every call.
 */

/** What the authority decided; only `kind` is read here. */
export interface ImportDecision {
  readonly kind: string;
}

/**
 * The answer to a seed seal: the authority ran the write inside its lock
 * (`streams`, with the write's result), or it could not admit the write and ran
 * nothing (`refuse`).
 */
export type ImportSeal<T> =
  { readonly kind: "streams"; readonly value: T } | { readonly kind: "refuse" };

export interface ImportAuthority {
  /**
   * True from the first On until `importDone(owner)`. REJECTS when the
   * authority does not know the owner: a rejection is "unknown", never
   * "not pending".
   */
  importPending(owner: string): Promise<boolean>;
  /**
   * The import for `owner` is finished. Resolves once the save has landed;
   * the flag counts as cleared only then, so the call is always awaited.
   */
  importDone(owner: string): Promise<ImportDecision>;
  /**
   * The only path the importer's own seed publish may use while the import is
   * pending (ordinary commits answer IMPORT_PENDING). A seal, not a check:
   * the authority runs `write` inside its own lock and answers `streams` with
   * its result, or answers `refuse` and runs nothing when it cannot admit the
   * write. The importer queues its seed publish inside the call. (The registry
   * write that follows is made later by the writer's `publishPending`; the
   * writer's own `importDone` gate stands at the publish that binds
   * generation 1.) A repeat of the same `operationId` (a re-run after a crash)
   * is admitted again. A `write` that throws rejects the call.
   *
   * `write` must NEVER call this authority (`importPending`, `importDone` or
   * `commitImportSeed`): the authority holds its lock for the whole seal, so a
   * nested call waits for the very call it is part of and never returns. Ask
   * the authority only after `commitImportSeed` returns.
   */
  commitImportSeed<T>(
    owner: string,
    operationId: string,
    write: () => Promise<T>,
  ): Promise<ImportSeal<T>>;
}

/** An in-memory authority for tests and hosts with no mode authority yet. */
export interface MemoryImportAuthority extends ImportAuthority {
  /** Owners `importDone` was called for, in order. */
  readonly doneCalls: readonly string[];
  /** Seed publishes asked for, in order. */
  readonly seedCommits: readonly { owner: string; operationId: string }[];
}

export function createMemoryImportAuthority(
  options: {
    readonly pending?: boolean;
    /** The authority does not know the owner: `importPending` rejects. */
    readonly unknown?: boolean;
    /**
     * How long a call may wait behind an open seal before the fake gives it up
     * as a nested call and rejects. A real authority would wait forever; the
     * fake turns that hang into an error a test can see. Default 3000 ms.
     */
    readonly deadlockMs?: number;
  } = {},
): MemoryImportAuthority {
  const initial = options.pending ?? true;
  const done = new Set<string>();
  const doneCalls: string[] = [];
  const seedCommits: { owner: string; operationId: string }[] = [];
  // The fake's lock: one sealed write at a time, as the authority does. Every
  // method waits for it, so a call made from inside a sealed write (a nested
  // call) can never return, exactly as under the real authority. The fake
  // rejects such a call after `deadlockMs` instead of hanging the test.
  let lock: Promise<unknown> = Promise.resolve();
  const deadlockMs = options.deadlockMs ?? 3000;
  const behindSeal = async (): Promise<void> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const blocked = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(
              "authority call blocked by an open seal: a sealed write called the authority",
            ),
          ),
        deadlockMs,
      );
    });
    try {
      await Promise.race([lock, blocked]);
    } finally {
      clearTimeout(timer);
    }
  };
  return {
    doneCalls,
    seedCommits,
    importPending: async (owner) => {
      await behindSeal();
      if (options.unknown) throw new Error("account mode unknown");
      return initial && !done.has(owner.toLowerCase());
    },
    importDone: async (owner) => {
      await behindSeal();
      done.add(owner.toLowerCase());
      doneCalls.push(owner.toLowerCase());
      return { kind: "streams" };
    },
    commitImportSeed: <T>(
      owner: string,
      operationId: string,
      write: () => Promise<T>,
    ): Promise<ImportSeal<T>> => {
      seedCommits.push({ owner: owner.toLowerCase(), operationId });
      if (options.unknown) return Promise.resolve({ kind: "refuse" });
      const run = lock.then(async () => ({
        kind: "streams" as const,
        value: await write(),
      }));
      lock = run.catch(() => undefined);
      return run;
    },
  };
}

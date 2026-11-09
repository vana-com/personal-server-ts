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
   * write. The publish therefore happens inside the call, never after it
   * returns. A repeat of the same `operationId` (a re-run after a crash) is
   * admitted again. A `write` that throws rejects the call.
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
  } = {},
): MemoryImportAuthority {
  const initial = options.pending ?? true;
  const done = new Set<string>();
  const doneCalls: string[] = [];
  const seedCommits: { owner: string; operationId: string }[] = [];
  // The fake's lock: one sealed write at a time, as the authority does.
  let lock: Promise<unknown> = Promise.resolve();
  return {
    doneCalls,
    seedCommits,
    importPending: async (owner) => {
      if (options.unknown) throw new Error("account mode unknown");
      return initial && !done.has(owner.toLowerCase());
    },
    importDone: async (owner) => {
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

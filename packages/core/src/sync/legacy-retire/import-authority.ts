/**
 * The one owner of "the legacy import is done" for an Account.
 *
 * The account-mode authority persists `importPending` when the Account is
 * first switched on, refuses stream commits (503 `IMPORT_PENDING`) while it is
 * set, and clears it when told `importDone(owner)`. The import and its ledger
 * keep NO done flag of their own: they read this port, and tell it once the
 * import is proven and published. This is the narrow port they need; a host
 * binds it to the authority.
 */
export interface ImportAuthority {
  /** True from the first On until `importDone(owner)`. */
  importPending(owner: string): Promise<boolean>;
  /** The import for `owner` is finished; stream commits may go. */
  importDone(owner: string): Promise<void>;
}

/** An in-memory authority for tests and hosts with no mode authority yet. */
export interface MemoryImportAuthority extends ImportAuthority {
  /** Owners `importDone` was called for, in order. */
  readonly doneCalls: readonly string[];
}

export function createMemoryImportAuthority(
  options: { readonly pending?: boolean } = {},
): MemoryImportAuthority {
  const initial = options.pending ?? true;
  const done = new Set<string>();
  const doneCalls: string[] = [];
  return {
    doneCalls,
    importPending: async (owner) => initial && !done.has(owner.toLowerCase()),
    importDone: async (owner) => {
      done.add(owner.toLowerCase());
      doneCalls.push(owner.toLowerCase());
    },
  };
}

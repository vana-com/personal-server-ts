import type { LocalSyncDeps } from "./deps.js";

/** A delete a connector has open, stored in `delete_intents.intent` (shape unchanged from the writer). */
export interface DeleteIntent {
  readonly id?: string;
  readonly pins: readonly { readonly ns: string; readonly version: number }[];
  readonly streams?: readonly {
    readonly ns: string;
    readonly stream: string;
  }[];
  readonly streamsLanded?: true;
}

/** A delete intent that could not be finished on this pass. */
export interface PendingDelete {
  readonly connector: string;
  readonly why: string;
}

/**
 * F.5: the connection delete protocol of #592/#593 on the database: persist
 * the intent in `delete_intents` before the first registry write, post delete
 * heads, then the control tombstone, then `purgeConnection`. Carries #563: a
 * conflicting control post is re-read; a delete superseded by a reconnect
 * throws `ConnectionDeleteSuperseded`; `ConnectorNotVerifiedError` when no
 * stream names are known. Answers as soon as the intent is durable.
 * DELETES USER DATA.
 */
export interface ConnectionDeleter {
  requestConnectionDelete(
    connector: string,
  ): Promise<{ readonly deleteId: string }>;
  /** Finish every open intent; called each cycle. */
  resumeDeletes(): Promise<readonly PendingDelete[]>;
}

export function createConnectionDeleter(
  deps: LocalSyncDeps,
  options: {
    readonly declaredStreams: (connector: string) => readonly string[];
    readonly retainedManifests?: () => readonly string[];
    /** Erases this device's legacy scope files of the connector; idempotent. */
    readonly eraseLegacy?: (connector: string) => Promise<void>;
  },
): ConnectionDeleter {
  void deps;
  void options;
  throw new Error("PS-2: not built");
}

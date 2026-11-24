/** Shared read contracts and owner status helpers for the database model. */
import type {
  ControlState,
  StreamHeadView,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { IncompleteAliasDiagnostic } from "../localdb/resolve.js";
import type {
  RefusedReason,
  DeferredReason,
} from "../stream-sync/publish-plan.js";

export type WithheldReason =
  | RefusedReason
  | DeferredReason
  /** The run replaces the imported base, which grants still read. */
  | "key_reset_pending"
  /** The run's publish merges seed rows the overlay does not hold. */
  | "seed_pending"
  /** The writer will publish the run, but the projector cannot project it to the requested name. */
  | "projection_unavailable"
  /** A foreign control key holds the connection: the writer keeps the run pending. */
  | "key_mismatch";

export type ImportProblem =
  /** The head or the control row was written with another owner key. */
  | "key_mismatch"
  /** A blob the head names is not in storage (yet). Retried each pass. */
  | "blob_missing"
  /** The head is of a format this server does not read. */
  | "unsupported_format"
  /** A blob failed decryption or verification. */
  | "corrupt"
  /** The name cannot be stored locally. */
  | "invalid_name"
  /** Storage or another transient failure. Retried each pass. */
  | "transient";

export interface ImportIssue {
  readonly connector: string;
  readonly ns: string;
  /** `null` for a problem of the whole connection (its control row). */
  readonly stream: string | null;
  readonly problem: ImportProblem;
  /** Registry version the problem is about. */
  readonly version: number;
  readonly detail?: string;
}

/**
 * How far a first load has come when a read serves its rows before the head
 * is complete. A `view` carries it only then; a view without it is complete.
 * The body holds the rows of the applied parts, all of one head and all in
 * the finished result: never rows of another head or generation, and no local
 * row whose part has not applied yet. It can hold rows of parts applied after
 * the counts below were read, never fewer. Owner reads only: a grantee is
 * never served a stream that is still loading.
 *
 * The `cursor` of a partial view is a head and schema pin, not a position in
 * the finished list. When the stream completes, the finished view replaces
 * the partial one: a consumer replaces its rows, never appends to them.
 */
export interface PartialView {
  /**
   * Parts of the head applied when the read began. For a load of the log, the
   * batches (snapshot parts and segments) the stream appears in.
   */
  readonly partsApplied: number;
  /** Parts the head has (a log's batches that name the stream). */
  readonly partsTotal: number;
  /**
   * Records the complete head holds, from the head itself. 0 when it is not
   * known: a load of the log has no count before its fold is complete.
   */
  readonly recordsTotal: number;
  /**
   * Set when the apply stopped before the last part. The load is not going on
   * now and will retry (the next read or sync cycle starts it again), so a
   * screen says "will retry", not "loading". Absent: the load is going on.
   */
  readonly failed?: { readonly code: string };
}

export interface ResolveInput {
  /** Paid reads must bind the body to an accepted connection-log fold. */
  readonly requireRegistered?: boolean;
  /** The request lifetime, including its existing deadline. */
  readonly signal?: AbortSignal;
  readonly scope: string;
  /** `connection=<ns>`; `null` when absent. */
  readonly connection: string | null;
  /** `cursor=` of an earlier response; `null` when absent. */
  readonly cursor: string | null;
  /** The existing path holds a legacy or raw body of `scope`. */
  readonly legacyFile: boolean;
  /** The caller reads as the owner (`isOwnerView`), not as a grantee. */
  readonly isOwnerView: boolean;
  /** Explicit owner inspection only; never enables grantee or paid reads. */
  readonly includeIncomplete?: boolean;
}

/**
 * A local run whose rows the view does not show, and why: the
 * writer's publish plan refuses or defers it, or the read does not show it
 * before it is imported. Carried to the owner only.
 */
export interface WithheldRun {
  readonly runId: string;
  readonly stream: string;
  readonly reason: WithheldReason;
}

/**
 * What only the owner is told of this device's local runs when the answer
 * serves no stream view: the existing path or a refusal answers instead.
 */
export interface OwnerNotes {
  /** Runs the writer will not publish; absent when none. */
  readonly withheld?: readonly WithheldRun[];
  /**
   * A legacy body answers while local runs are not published: `runs` counts
   * distinct runs with a requested stream that has no publish receipt, with
   * or without records, shown or withheld. The legacy body's own time is an
   * ingest stamp, not comparable with a run's, so nothing decides which is
   * newer: the owner is told.
   */
  readonly pending?: { readonly runs: number };
  /**
   * A legacy body answers while published local runs wait for import: the
   * body does not reflect them. `runs` counts distinct runs with a stream the
   * writer published and the reader has not imported yet. Cleared by import
   * coverage, not by the publish receipt.
   */
  readonly awaitingImport?: { readonly runs: number };
  /**
   * A stored body answers while the reader holds a live imported head for a
   * requested stream: a complete head would have served its own view, so the
   * body does not reflect this one (an incomplete head). Derived from the
   * response and the stream's head, not from runs: it outlives import and run
   * retirement. `streams` counts distinct streams.
   */
  readonly notReflected?: { readonly streams: number };
}

export type ReadDecision =
  | { readonly kind: "read_not_registered" }
  | { readonly kind: "read_aborted" }
  | { readonly kind: "invalid_binding" }
  /** Not a stream-sync read: the existing path answers, unchanged. */
  | ({ readonly kind: "pass" } & OwnerNotes)
  /** §2.10 step 3: serve the legacy or raw file through the existing path. */
  | ({ readonly kind: "legacy" } & OwnerNotes)
  | ({
      readonly kind: "unavailable";
      readonly reason: "deleted" | "no_data" | "connection_not_found";
    } & OwnerNotes)
  /** The connector's only connections were written with another owner key. */
  | ({ readonly kind: "key_mismatch" } & OwnerNotes)
  /** The cursor names a version this server no longer holds. */
  | { readonly kind: "cursor_stale" }
  | { readonly kind: "invalid_cursor" }
  | { readonly kind: "invalid_connection" }
  | { readonly kind: "too_large"; readonly bytes: number }
  /**
   * The projection left rows out or served them short of detail. Nothing is
   * served: the flag-off path refuses the same way.
   */
  | {
      readonly kind: "incomplete";
      readonly diagnostics: readonly IncompleteAliasDiagnostic[];
    }
  /**
   * Imports or writer publications into the streams this read touched kept
   * changing under it. Nothing is wrong with the data: ask again.
   */
  | { readonly kind: "busy"; readonly retryAfterSeconds: number }
  /**
   * The owner's partial view, built on this device: the live imported heads,
   * complete or not, and the local runs the writer will publish on them, when
   * no complete view serves (a first run made offline, an incomplete head, a
   * pending key reset). Owner-only, no registry entry to bind: nothing to
   * bill. The body marks the data `"origin":"local-pending"` and says whether
   * it is `"complete"`.
   */
  | {
      readonly kind: "local_pending";
      readonly connector: string;
      readonly ns: string;
      readonly cursor: string;
      /** The view holds everything the writer will publish, and that is complete. */
      readonly complete: boolean;
      /** Owner only; absent when none. */
      readonly withheld?: readonly WithheldRun[];
      readonly body: ReadableStream<Uint8Array>;
    }
  | {
      readonly kind: "view";
      readonly connector: string;
      readonly ns: string;
      /** Pins `(stream → head version)` of every input head. */
      readonly cursor: string;
      /**
       * Receipt identity for the selected body. Paid views name the accepted
       * connection log and the position covering every contributing stream.
       * Free views may name the local stream head. `null` for an
       * owner-only view with an input stream that has no imported head: there
       * is no registry entry to bind or charge.
       */
      readonly served: {
        readonly scope: string;
        readonly version: number;
      } | null;
      /** Owner only; absent when none. */
      readonly withheld?: readonly WithheldRun[];
      /**
       * Present only while a first load is still applying parts: the body is
       * the rows applied so far. An installed incomplete collection instead
       * carries `complete: false`; absence of partial alone is not completeness.
       */
      readonly partial?: PartialView;
      /** False for an explicit owner view of an installed incomplete head. */
      readonly complete?: false;
      /**
       * Absent here, always: this decision's body is memory, so a consumer
       * may read it whole. A body that waits in a file is a `SpooledView`,
       * which no consumer typed `ReadDecision` can receive.
       */
      readonly spooled?: undefined;
      readonly body: ReadableStream<Uint8Array>;
    };

/**
 * A stream view whose body waits in a file, as large as the data. Only a
 * consumer that streams it to a client may hold one: a consumer that reads a
 * body whole (`.text()`, a parse, a block check) takes a `ReadDecision` from
 * `resolve`, never this. `resolveStreaming` is the one source of it.
 */
export type SpooledView = Omit<
  Extract<ReadDecision, { kind: "view" }>,
  "spooled"
> & {
  readonly spooled: true;
};

/** What a consumer that streams the body to a client may receive. */
export type StreamedReadDecision = ReadDecision | SpooledView;

export interface StreamSyncConnectionStatus {
  readonly connector: string;
  readonly ns: string;
  readonly control: ControlState["kind"];
  readonly streams: Readonly<
    Record<
      string,
      StreamHeadView & {
        readonly version: number | null;
        readonly records: number | null;
        /**
         * Present only when the status was asked for with `audit`. SHA-256
         * over the stream's live `(pk_hash, body_sha256)` pairs in `pk_hash`
         * order: equal on two devices that hold the same live records, in
         * whatever order they arrived. `null` unless the head is live and
         * complete (a stream still loading holds a subset by design).
         */
        readonly digest?: string | null;
        /** Set while a first load serves its applied parts; owner diagnostics. */
        readonly partial?: PartialView & { readonly version: number };
      }
    >
  >;
}

export interface StreamSyncReadStatus {
  /** A full Account listing and apply completed in this database runtime. */
  readonly accountHydrated?: boolean;
  readonly listed: boolean;
  readonly connections: readonly StreamSyncConnectionStatus[];
  readonly issues: readonly ImportIssue[];
  /**
   * Present only when the status was asked for with `audit`. The seed imports
   * this database refused for good, from its import ledger: one entry per
   * reason, counting the streams (`seed_skipped`: the seeds of a reset stream were
   * purged). An exclusion that a retry still merges (`WINDOW_CLOSED_REASON`) is
   * not listed. Durable across restarts.
   */
  readonly importExclusions?: readonly {
    readonly reason: string;
    readonly streams: number;
  }[];
}

/**
 * One row per stream the read side knows, for owner diagnostics. `records` is
 * the imported head's record count only while that head is live (§2.4). A
 * pending (unimported), tombstoned, superseded-generation or
 * deleted-connection head counts `null`. Logical connection selection, a
 * legacy-file fallback and rows from the local outbox overlay are outside
 * this count.
 */
export function liveStreamCounts(status: StreamSyncReadStatus): {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly records: number | null;
  /** Only for an audited status; see `StreamSyncConnectionStatus`. */
  readonly digest?: string | null;
}[] {
  return status.connections.flatMap((connection) =>
    Object.entries(connection.streams).map(([stream, head]) => ({
      connector: connection.connector,
      ns: connection.ns,
      stream,
      records: head.live ? head.records : null,
      ...(head.digest === undefined ? {} : { digest: head.digest }),
    })),
  );
}

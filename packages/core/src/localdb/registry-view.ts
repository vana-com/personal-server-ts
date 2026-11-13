import {
  controlScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";

/**
 * What one publish learns about the registry from a single listing, so that
 * the first snapshot of most streams need not read it again.
 *
 * A snapshot reads the control row and its stream's row, one request each, in
 * the connection's slot. A publish of N streams made 2N of those requests.
 * One listing of the connection's rows answers all but the first stream's:
 *
 *  - the stream's row, from the stream's own row in the listing;
 *  - the control row, from the control row in the same listing.
 *
 * A hint is a starting point and never a fence. The commit still reads the
 * control row live before and after its post, and the post is a
 * compare-and-set. A hint that went stale costs a conflict and a retry, never
 * a wrong write. Therefore:
 *
 *  - a hint serves a stream's FIRST snapshot only. A snapshot that repeats (a
 *    retry after an apply, a discarded candidate) reads the registry;
 *  - a control hint is used only while it is an active row of the generation
 *    the connection has. Anything else (absent, deleted, foreign, moved) is
 *    read again before the snapshot acts on it, because absent creates the
 *    row and deleted purges local data;
 *  - a snapshot that would do anything but build a candidate (no work to
 *    publish, so no evidence is written and no result is "noop"; a refused
 *    run) reads the control row and the stream row live first: see
 *    `confirmHints` in publish.ts. A candidate is guarded by the commit's live
 *    control checks and its CAS;
 *  - a listing is never reused after the publish changed local state from the
 *    registry (an apply, a CAS conflict): `invalidate` drops it, a listing
 *    still in flight is not handed out, and the next stream takes a new one.
 *
 * The listing carries what a snapshot's stream read carries: deleted rows are
 * in it (tombstones), and a row is keyed by its exact scope.
 */
export interface RegistryView {
  /**
   * The hints for `scope`'s first snapshot. Later calls for the same scope
   * return none. The first stream to ask gets none: it reads its own rows, and
   * the listing is taken only when the second stream asks, so that nothing but
   * the first stream's reads is in flight before its first upload. The other
   * streams then answer from the one listing.
   */
  firstSnapshot(scope: string): Promise<RegistryHints>;
  /** The publish applied registry state or lost a CAS: hand out no earlier listing. */
  invalidate(): void;
}

export interface RegistryHints {
  readonly stream?: ControlRead;
  readonly control?: ControlRead;
}

/** A view that hints nothing: every read goes to the registry. */
export const NO_VIEW: RegistryView = {
  firstSnapshot: async () => ({}),
  invalidate: () => {},
};

/**
 * One listing replaces a control read and a stream read per stream after the
 * first, so it pays from three streams on. The gateway cannot list by scope:
 * the listing is one request per page of the OWNER's rows, so for a
 * connection of one or two streams it is not worth what it saves.
 */
const MIN_STREAMS_FOR_LISTING = 3;

/**
 * Hand out hints from one listing of the connection's rows, taken when the
 * second stream first needs it. A listing that fails, or a registry that
 * cannot list a connection, is not a failed publish: the snapshots read their
 * rows.
 */
export function openRegistryView(
  deps: LocalSyncDeps,
  connection: { readonly connector: string; readonly ns: string },
  streamCount: number,
): RegistryView {
  if (
    streamCount < MIN_STREAMS_FOR_LISTING ||
    deps.registry.listConnectionRows === undefined
  )
    return NO_VIEW;
  let listing: Promise<Map<string, ControlRead> | null> | undefined;
  let epoch = 0;
  const started = new Set<string>();
  const control = controlScope(connection.connector, connection.ns);
  return {
    async firstSnapshot(scope) {
      if (started.has(scope)) return {};
      const first = started.size === 0;
      started.add(scope);
      if (first) return {};
      // Taken by the second stream's turn, so that the first stream's own
      // reads (the control row, then its row) are the only requests in flight
      // before its first upload.
      listing ??= listRows(deps, connection);
      const taken = epoch;
      const rows = await listing;
      // Applied or lost a CAS while the listing was out: it may predate that.
      if (rows === null || epoch !== taken) return {};
      // The listing is complete (a missing page marker throws), so a stream
      // scope it does not hold has no row. The control row of a connection
      // that has none yet is simply left out: the snapshot reads it itself.
      const controlRow = rows.get(control);
      return {
        stream: rows.get(scope) ?? { found: false },
        ...(controlRow && { control: controlRow }),
      };
    },
    invalidate() {
      epoch += 1;
      listing = undefined;
    },
  };
}

/** The connection's rows by scope, or null when the listing failed. */
async function listRows(
  deps: LocalSyncDeps,
  connection: { readonly connector: string; readonly ns: string },
): Promise<Map<string, ControlRead> | null> {
  try {
    const rows = new Map<string, ControlRead>();
    for (const row of await deps.registry.listConnectionRows!(
      connection.connector,
      connection.ns,
    ))
      rows.set(row.scope, row.read);
    return rows;
  } catch (error) {
    deps.logger.warn(
      { error: String(error) },
      "publish: registry listing failed; reading each stream's row",
    );
    return null;
  }
}

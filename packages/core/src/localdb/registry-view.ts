import {
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";

/**
 * What one publish already knows about the registry, so that the first
 * snapshot of each stream need not read it again.
 *
 * A snapshot reads the control row and its stream's row, one request each, in
 * the connection's slot. A publish of N streams made 2N of those requests.
 * The view answers them from two things the publish already has:
 *
 *  - the stream rows, from ONE listing taken by the second stream's first
 *    snapshot;
 *  - the control row, from the newest read of it any stream made in this
 *    publish (the first snapshot's, or a commit's check around its post).
 *
 * A hint is a starting point and never a fence. The commit reads the stream
 * row itself, live, right before the compare-and-set; it also reads the
 * control row live before and after the post. A hint that went stale makes
 * the commit discard the candidate and the stream snapshot again.
 * Therefore:
 *
 *  - a hint serves a stream's FIRST snapshot only. A snapshot that repeats (a
 *    retry after an apply, a discarded candidate) reads the registry;
 *  - a control hint is used only while it is an active row of the generation
 *    the connection has. Anything else (absent, deleted, foreign, moved) is
 *    read again before the snapshot acts on it, because absent creates the
 *    row and deleted purges local data.
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
  /** Remember a control row this publish read from the registry itself. */
  sawControl(read: ControlRead): void;
}

export interface RegistryHints {
  readonly stream?: ControlRead;
  readonly control?: ControlRead;
}

/** A view that hints nothing: every read goes to the registry. */
export const NO_VIEW: RegistryView = {
  firstSnapshot: async () => ({}),
  sawControl: () => {},
};

/**
 * One listing replaces one stream-row read per stream, so it pays from two
 * streams on. It is also one request per page of the OWNER's rows (the
 * gateway cannot list by scope), so for a connection of one stream it is not
 * worth more than the single read it saves.
 */
const MIN_STREAMS_FOR_LISTING = 2;

/**
 * Hand out hints from one listing of the stream rows of `connector`, taken
 * when the second stream first needs it. A listing that fails is not a failed
 * publish: the snapshots read their rows.
 */
export function openRegistryView(
  deps: LocalSyncDeps,
  connection: { readonly connector: string; readonly ns: string },
  streamCount: number,
): RegistryView {
  if (streamCount < MIN_STREAMS_FOR_LISTING) return NO_VIEW;
  let listing: Promise<Map<string, ControlRead> | null> | undefined;
  const started = new Set<string>();
  let control: ControlRead | undefined;
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
      const rows = await listing;
      if (rows === null) return {};
      // The listing is complete (a missing page marker throws), so a scope it
      // does not hold has no row.
      return {
        stream: rows.get(scope) ?? { found: false },
        ...(control && { control }),
      };
    },
    sawControl(read) {
      control = read;
    },
  };
}

/** The connection's stream rows by scope, or null when the listing failed. */
async function listRows(
  deps: LocalSyncDeps,
  connection: { readonly connector: string; readonly ns: string },
): Promise<Map<string, ControlRead> | null> {
  try {
    const rows = new Map<string, ControlRead>();
    for (const row of await deps.registry.listStreamRows(
      connection.connector,
    )) {
      const scope = parseScope(row.scope);
      if (
        scope?.kind === "stream" &&
        scope.connector === connection.connector &&
        scope.ns === connection.ns
      )
        rows.set(row.scope, row.read);
    }
    return rows;
  } catch (error) {
    deps.logger.warn(
      { error: String(error) },
      "publish: registry listing failed; reading each stream's row",
    );
    return null;
  }
}

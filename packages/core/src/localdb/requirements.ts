import type { LocalSyncDeps } from "./deps.js";
import type { RecordQuery } from "./query.js";

/** Answer of `GET /v1/streams/requirements?connection=`. */
export type RequirementsAnswer =
  | {
      readonly ok: true;
      /** Smallest declared date value (YYYY-MM-DD) over the connection; `null` when none is declared. */
      readonly since: string | null;
    }
  | { readonly ok: false; readonly reason: "malformed_day" };

/**
 * Manifest data port: for a connection, stream name to the name of the
 * date-valued record field that its manifest declares as `history.since_field`.
 * Empty until the manifest carries the field. The Personal Server names no
 * connector; the manifest is the only source.
 */
export interface SinceFieldSource {
  sinceFields(connectionId: string): Promise<Readonly<Record<string, string>>>;
}

/**
 * r5.2 4.1: generic history requirements. Pages `records` through the query
 * port (JSON1 is not available; one page at a time, within the memory gate),
 * takes the minimum declared day, caches by the connection's head versions.
 * No declared field: `{ ok: true, since: null }`.
 */
export interface LocalRequirements {
  requirements(connectionId: string): Promise<RequirementsAnswer>;
}

export function createLocalRequirements(
  deps: LocalSyncDeps,
  options: {
    readonly query: RecordQuery;
    readonly source: SinceFieldSource;
  },
): LocalRequirements {
  void deps;
  void options;
  throw new Error("PS-2: not built");
}

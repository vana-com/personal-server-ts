import type { AdditionsSummary } from "../additions/summary.js";
import type { LocalSyncDeps } from "./deps.js";

/** 404 (`not_found`) and 410 (`deleted`) as the other D.1 reads answer them. */
export type HistoryResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: "not_found" | "deleted" };

/** One `/versions` item: the six fields of the legacy contract. */
export interface HistoryVersionItem {
  /** `stream_versions.head_blob`. */
  readonly fileId: string | null;
  readonly schemaId: null;
  /** ISO string of the writer's `observed_at`, never import or registry time. */
  readonly collectedAt: string;
  readonly version: number;
  readonly producer: null;
  readonly producer_provenance: null;
}

export interface HistoryVersionsPage {
  readonly scope: string;
  readonly versions: readonly HistoryVersionItem[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
}

/** `/lineage` on a switched owner: no sources, by construction (r5.2 1.6). */
export interface HistoryLineage {
  readonly scope: string;
  readonly version: number;
  readonly sources: readonly [];
  /** Shape confirmed against the legacy lineage function (r5.2 Doubt 3). */
  readonly proof: unknown;
}

/**
 * r5.2 1.4-1.6: `/additions`, `/:scope/versions` and `/:scope/lineage` served
 * from the database (`records`, `stream_state`, `stream_versions`,
 * `connections`) before any account switches. Never opens a legacy store and
 * names no connector. Route code calls it after the existing auth.
 */
export interface LocalHistory {
  /** `partial` is always false; rows with unknown `first_o` count in `total` only. */
  additions(input: {
    readonly timezone: string;
    readonly days: number;
  }): Promise<AdditionsSummary>;
  versions(input: {
    readonly scope: string;
    readonly limit: number;
    readonly offset: number;
  }): Promise<HistoryResult<HistoryVersionsPage>>;
  lineage(input: {
    readonly scope: string;
    readonly version?: number;
  }): Promise<HistoryResult<HistoryLineage>>;
}

export function createLocalHistory(
  deps: LocalSyncDeps,
  options: {
    /** The `olderVersionReads` server config value, read at each call (default true). */
    readonly olderVersionReads: () => boolean;
  },
): LocalHistory {
  void deps;
  void options;
  throw new Error("PS-2: not built");
}

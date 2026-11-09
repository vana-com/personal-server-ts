/**
 * The production legacy import source: this device's own canonical PDPP
 * rows, mapped to stream-sync streams through verified connector
 * declarations.
 *
 * What it imports is decided by the data, not by a table of connector names:
 * a connector is the key of a declared source with a live connection, a
 * stream is a declared stream with a primary key, and a row is a row whose
 * every key field holds a value. A row that points at a blob is imported as
 * data; the blob bytes stay in this device's blob store and do not travel.
 *
 * A stream holds one account's data (R23: no connection dimension), and a
 * legacy body "is one account's data" (`resolveCanonicalConnection`), so a
 * connector with several live connections imports the most recently active
 * one and counts the rest as `other_connection`. Everything the import leaves
 * behind is counted by reason in `excluded()`, and the ledger keeps it.
 *
 * Owner: the record store is this server's own (`bootstrap.ts` opens
 * `index.db` under the server's storage root, and `pdpp-connections.ts`
 * refuses any subject but the one owner), and a connection id is not
 * guaranteed to name its owner (`isConnectionId`), so the source does not
 * filter by owner. `owner` binds the pass to the ledger of the same Account.
 */

import type { DeclarationSnapshot } from "../../pdpp/types.js";
import { legacyConnectorKey } from "../../storage/canonical-legacy-projection.js";
import {
  ImportSourceUnavailableError,
  type ImportExclusion,
  type ImportStream,
  type LegacyImportSource,
} from "./import.js";

type MaybeAsync<T> = T | Promise<T>;

/** The part of the canonical record store the import reads. */
export interface CanonicalImportStore {
  listConnections(
    sourceId: string,
  ): MaybeAsync<readonly { instance: string; deletedAt: string | null }[]>;
  listStreams(instanceIds: string[]): MaybeAsync<
    readonly {
      stream: string;
      recordCount: number;
      lastUpdated?: string | null;
    }[]
  >;
  listRecords(
    stream: string,
    options: {
      instanceIds: string[];
      limit: number;
      cursor?: string;
      order: "asc" | "desc";
    },
  ): MaybeAsync<{
    data: readonly { data: Record<string, unknown> }[];
    hasMore: boolean;
    nextCursor?: string;
  }>;
}

export interface CanonicalImportDeps {
  readonly store: CanonicalImportStore;
  readonly declarations: readonly DeclarationSnapshot[];
}

/**
 * A host with no canonical record store (PDPP is off): it holds no
 * stream-shaped rows, so the import completes with nothing to stage.
 */
export const NO_CANONICAL_ROWS: CanonicalImportDeps = {
  store: {
    listConnections: () => [],
    listStreams: () => [],
    listRecords: () => ({ data: [], hasMore: false }),
  },
  declarations: [],
};

export interface CanonicalImportSourceOptions {
  readonly owner: string;
  /** The host's stores, or null while it has not opened them yet. */
  readonly deps: () => CanonicalImportDeps | null;
  readonly pageSize?: number;
}

const DEFAULT_PAGE_SIZE = 500;

const isKeyValue = (value: unknown): boolean =>
  (typeof value === "string" && value !== "") ||
  (typeof value === "number" && Number.isFinite(value));

type RowVerdict = "import" | "unkeyed_row";

const judge = (
  row: Record<string, unknown>,
  primaryKey: readonly string[],
): RowVerdict => {
  if (!primaryKey.every((field) => isKeyValue(row[field]))) {
    return "unkeyed_row";
  }
  return "import";
};

interface Scan {
  readonly streams: readonly ImportStream[];
  readonly excluded: readonly ImportExclusion[];
}

export function createCanonicalImportSource(
  options: CanonicalImportSourceOptions,
): LegacyImportSource {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const scans = new Map<string, Scan>();

  const need = (): CanonicalImportDeps => {
    const deps = options.deps();
    if (!deps) throw new ImportSourceUnavailableError();
    return deps;
  };

  /** Declared sources by connector key; two sources under one key are ambiguous. */
  const sourcesOf = (deps: CanonicalImportDeps) => {
    const byKey = new Map<string, DeclarationSnapshot[]>();
    for (const declaration of deps.declarations) {
      if (declaration.source_kind !== "connector") continue;
      const key = legacyConnectorKey(declaration.source_id);
      byKey.set(key, [...(byKey.get(key) ?? []), declaration]);
    }
    return byKey;
  };

  /** Every live connection of the connector, with the declaration of its source. */
  const liveConnections = async (
    deps: CanonicalImportDeps,
    declarations: readonly DeclarationSnapshot[],
  ): Promise<{ instance: string; declaration: DeclarationSnapshot }[]> => {
    const found: { instance: string; declaration: DeclarationSnapshot }[] = [];
    for (const declaration of declarations) {
      for (const connection of await deps.store.listConnections(
        declaration.source_id,
      )) {
        if (connection.deletedAt === null) {
          found.push({ instance: connection.instance, declaration });
        }
      }
    }
    return found;
  };

  async function* pages(
    store: CanonicalImportStore,
    instance: string,
    stream: string,
  ): AsyncGenerator<Record<string, unknown>> {
    let cursor: string | undefined;
    for (;;) {
      const page = await store.listRecords(stream, {
        instanceIds: [instance],
        limit: pageSize,
        order: "asc",
        ...(cursor === undefined ? {} : { cursor }),
      });
      for (const row of page.data) yield row.data;
      if (!page.hasMore || page.nextCursor === undefined) return;
      cursor = page.nextCursor;
    }
  }

  async function scan(connector: string): Promise<Scan> {
    const deps = need();
    const live = await liveConnections(
      deps,
      sourcesOf(deps).get(connector) ?? [],
    );
    if (live.length === 0) return { streams: [], excluded: [] };
    // The most recently active connection is the account this device shows.
    const looked = await Promise.all(
      live.map(async (connection) => {
        const listed = await deps.store.listStreams([connection.instance]);
        const latest = listed.reduce(
          (max, s) =>
            (s.lastUpdated ?? "") > max ? (s.lastUpdated ?? "") : max,
          "",
        );
        return {
          ...connection,
          listed,
          latest,
          rows: listed.reduce((sum, s) => sum + s.recordCount, 0),
        };
      }),
    );
    looked.sort(
      (a, b) =>
        b.latest.localeCompare(a.latest) ||
        a.instance.localeCompare(b.instance),
    );
    const [chosen, ...others] = looked as [
      (typeof looked)[number],
      ...(typeof looked)[number][],
    ];
    const otherRows = others.reduce((sum, o) => sum + o.rows, 0);
    const instance = chosen.instance;
    const listed = chosen.listed;
    const declared = new Map(
      chosen.declaration.streams.map((s) => [s.name, s.primary_key]),
    );
    const streamLevel: ImportExclusion[] = [];
    const rowLevel: ImportExclusion[] = [];
    const streams: ImportStream[] = [];
    for (const { stream, recordCount } of listed) {
      const primaryKey = declared.get(stream);
      if (primaryKey === undefined) {
        streamLevel.push({
          stream,
          reason: "unmapped_stream",
          rows: recordCount,
        });
        continue;
      }
      if (primaryKey.length === 0) {
        streamLevel.push({
          stream,
          reason: "no_primary_key",
          rows: recordCount,
        });
        continue;
      }
      const counts = { import: 0, unkeyed_row: 0 };
      for await (const row of pages(deps.store, instance, stream)) {
        counts[judge(row, primaryKey)] += 1;
      }
      if (counts.unkeyed_row > 0) {
        rowLevel.push({
          stream,
          reason: "unkeyed_row",
          rows: counts.unkeyed_row,
        });
      }
      if (counts.import === 0) continue;
      streams.push({
        stream,
        primaryKey,
        profile: { key: null, version: "0.0.0" },
        async *records() {
          for await (const row of pages(deps.store, instance, stream)) {
            if (judge(row, primaryKey) === "import") yield row;
          }
        },
      });
    }
    const otherConnections: ImportExclusion[] =
      otherRows > 0
        ? [{ stream: null, reason: "other_connection", rows: otherRows }]
        : [];
    return {
      streams,
      excluded: [...streamLevel, ...rowLevel, ...otherConnections],
    };
  }

  return {
    owner: options.owner,
    async connectors() {
      const deps = need();
      const connectors: string[] = [];
      for (const [key, declarations] of sourcesOf(deps)) {
        if ((await liveConnections(deps, declarations)).length > 0) {
          connectors.push(key);
        }
      }
      return connectors;
    },
    async streams(connector) {
      const found = await scan(connector);
      scans.set(connector, found);
      return found.streams;
    },
    async excluded(connector) {
      return scans.get(connector)?.excluded ?? [];
    },
  };
}

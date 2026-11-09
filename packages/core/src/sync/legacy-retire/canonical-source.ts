/**
 * The production legacy import source: this device's own canonical PDPP
 * rows, mapped to stream-sync streams through verified connector
 * declarations.
 *
 * What it imports is decided by the data, not by a table of connector names:
 * a connector is the key of a declared source with exactly one live
 * connection, a stream is a declared stream with a primary key, and a row is
 * a row whose every key field holds a value and that points at no blob (blob
 * bytes cannot travel in a seed). Everything else stays in the legacy file,
 * and `excluded()` counts it by reason so the ledger can show why.
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
  listStreams(
    instanceIds: string[],
  ): MaybeAsync<readonly { stream: string; recordCount: number }[]>;
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

export interface CanonicalImportSourceOptions {
  readonly owner: string;
  /** The host's stores, or null while it has not opened them yet. */
  readonly deps: () => CanonicalImportDeps | null;
  readonly pageSize?: number;
}

const DEFAULT_PAGE_SIZE = 500;
const MAX_BLOB_DEPTH = 8;

const isKeyValue = (value: unknown): boolean =>
  (typeof value === "string" && value !== "") ||
  (typeof value === "number" && Number.isFinite(value));

function pointsAtBlob(value: unknown, depth = 0): boolean {
  if (depth > MAX_BLOB_DEPTH || typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.blob_id === "string" &&
    record.blob_id.startsWith("sha256:")
  ) {
    return true;
  }
  return Object.values(record).some((child) => pointsAtBlob(child, depth + 1));
}

type RowVerdict = "import" | "unkeyed_row" | "blob_reference";

const judge = (
  row: Record<string, unknown>,
  primaryKey: readonly string[],
): RowVerdict => {
  if (!primaryKey.every((field) => isKeyValue(row[field]))) {
    return "unkeyed_row";
  }
  return pointsAtBlob(row) ? "blob_reference" : "import";
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

  const liveInstances = async (
    deps: CanonicalImportDeps,
    declarations: readonly DeclarationSnapshot[],
  ): Promise<string[]> => {
    const instances: string[] = [];
    for (const declaration of declarations) {
      for (const connection of await deps.store.listConnections(
        declaration.source_id,
      )) {
        if (connection.deletedAt === null) instances.push(connection.instance);
      }
    }
    return instances;
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
    const declarations = sourcesOf(deps).get(connector) ?? [];
    const instances = await liveInstances(deps, declarations);
    if (instances.length === 0) return { streams: [], excluded: [] };
    const listed = await deps.store.listStreams(instances);
    if (declarations.length !== 1 || instances.length !== 1) {
      const rows = listed.reduce((sum, s) => sum + s.recordCount, 0);
      return {
        streams: [],
        excluded: [{ stream: null, reason: "ambiguous_connection", rows }],
      };
    }
    const instance = instances[0]!;
    const declared = new Map(
      declarations[0]!.streams.map((s) => [s.name, s.primary_key]),
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
      const counts = { import: 0, unkeyed_row: 0, blob_reference: 0 };
      for await (const row of pages(deps.store, instance, stream)) {
        counts[judge(row, primaryKey)] += 1;
      }
      for (const reason of ["unkeyed_row", "blob_reference"] as const) {
        if (counts[reason] > 0) {
          rowLevel.push({ stream, reason, rows: counts[reason] });
        }
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
    return { streams, excluded: [...streamLevel, ...rowLevel] };
  }

  return {
    owner: options.owner,
    async connectors() {
      const deps = need();
      const connectors: string[] = [];
      for (const [key, declarations] of sourcesOf(deps)) {
        if ((await liveInstances(deps, declarations)).length > 0) {
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

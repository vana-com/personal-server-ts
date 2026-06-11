import type {
  DataStorageEntryLookup,
  DataStorageListOptions,
  DataStoragePort,
  DataStorageScopeListOptions,
} from "@opendatalabs/personal-server-ts-core/ports";
import type {
  IndexEntry,
  ScopeSummary,
} from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
export { previewEnvelopeValue } from "@opendatalabs/personal-server-ts-core/storage/preview";

export function sortEntries(entries: IndexEntry[]): IndexEntry[] {
  return [...entries].sort((a, b) =>
    b.collectedAt.localeCompare(a.collectedAt),
  );
}

function paginate<T>(
  items: T[],
  options: DataStorageListOptions | DataStorageScopeListOptions,
): T[] {
  const offset = options.offset ?? 0;
  const limit = options.limit ?? items.length;
  return items.slice(offset, offset + limit);
}

function listScopes(
  entries: Iterable<Pick<IndexEntry, "scope" | "collectedAt">>,
  options: DataStorageScopeListOptions,
): {
  scopes: ScopeSummary[];
  total: number;
} {
  const scopes = summarizeScopes(entries, options);
  return {
    scopes: paginate(scopes, options),
    total: scopes.length,
  };
}

function findEntryInScope(
  entries: IndexEntry[],
  lookup: DataStorageEntryLookup,
): IndexEntry | undefined {
  if (lookup.fileId) {
    return entries.find((entry) => entry.fileId === lookup.fileId);
  }
  if (lookup.at) {
    return entries.find((entry) => entry.collectedAt === lookup.at);
  }
  return entries[0];
}

export function createStorageReadMethods(
  entries: () => Iterable<Pick<IndexEntry, "scope" | "collectedAt">>,
  entriesForScope: (scope: string) => IndexEntry[],
): Pick<
  DataStoragePort,
  "listScopes" | "listVersions" | "countVersions" | "findEntry"
> {
  return {
    listScopes(options) {
      return listScopes(entries(), options);
    },

    listVersions(scope, options) {
      return paginate(entriesForScope(scope), options);
    },

    countVersions(scope) {
      return entriesForScope(scope).length;
    },

    findEntry(lookup) {
      return findEntryInScope(entriesForScope(lookup.scope), lookup);
    },
  };
}

export function readEnvelopeFromMap(
  envelopes: ReadonlyMap<string, DataFileEnvelope>,
  key: string,
): DataFileEnvelope {
  const envelope = envelopes.get(key);
  if (!envelope) {
    throw new Error("Envelope not found");
  }
  return envelope;
}

function summarizeScopes(
  entries: Iterable<Pick<IndexEntry, "scope" | "collectedAt">>,
  options: Pick<DataStorageScopeListOptions, "scopePrefix">,
): ScopeSummary[] {
  const summaries = new Map<string, ScopeSummary>();
  for (const entry of entries) {
    if (options.scopePrefix && !entry.scope.startsWith(options.scopePrefix)) {
      continue;
    }
    const existing = summaries.get(entry.scope);
    summaries.set(entry.scope, {
      scope: entry.scope,
      latestCollectedAt:
        existing &&
        existing.latestCollectedAt.localeCompare(entry.collectedAt) > 0
          ? existing.latestCollectedAt
          : entry.collectedAt,
      versionCount: (existing?.versionCount ?? 0) + 1,
    });
  }
  return Array.from(summaries.values()).sort((a, b) =>
    a.scope.localeCompare(b.scope),
  );
}

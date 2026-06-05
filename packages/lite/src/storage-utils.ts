import type {
  DataStorageEntryLookup,
  DataStorageListOptions,
  DataStoragePort,
  DataStorageScopeListOptions,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type {
  IndexEntry,
  ScopeSummary,
} from "@opendatalabs/personal-server-ts-core/storage/index";

const PREVIEW_NODE_BUDGET = 15_000;

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

export function previewEnvelopeValue(
  envelope: DataFileEnvelope,
  maxBytes: number,
): { text: string; truncated: boolean } {
  const textBudget = Math.max(0, maxBytes);
  const chunks: string[] = [];
  const stack: unknown[] = [envelope];
  let chars = 0;
  let truncated = false;
  let nodes = 0;

  while (stack.length > 0) {
    if (chars >= textBudget || nodes >= PREVIEW_NODE_BUDGET) {
      truncated = true;
      break;
    }

    const current = stack.pop();
    nodes += 1;
    if (typeof current === "string") {
      const remaining = textBudget - chars;
      chunks.push(current.slice(0, remaining));
      chars += Math.min(current.length, remaining);
      truncated = truncated || current.length > remaining;
      continue;
    }

    if (
      typeof current === "number" ||
      typeof current === "boolean" ||
      typeof current === "bigint"
    ) {
      const text = String(current);
      const remaining = textBudget - chars;
      chunks.push(text.slice(0, remaining));
      chars += Math.min(text.length, remaining);
      truncated = truncated || text.length > remaining;
      continue;
    }

    if (Array.isArray(current)) {
      for (let index = current.length - 1; index >= 0; index -= 1) {
        stack.push(current[index]);
      }
      continue;
    }

    if (typeof current === "object" && current !== null) {
      const entries = Object.entries(current as Record<string, unknown>);
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const [key, value] = entries[index]!;
        stack.push(value);
        stack.push(key);
      }
    }
  }

  const encoded = new TextEncoder().encode(chunks.join("\n"));
  const clipped = encoded.slice(0, maxBytes);
  return {
    text: new TextDecoder().decode(clipped),
    truncated: truncated || encoded.length > maxBytes,
  };
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

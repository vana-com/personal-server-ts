import { manifestArtifact } from "../stream-sync/artifacts.js";
import type { DataStoragePort } from "../ports/index.js";
import type { FoldLayer } from "./legacy-fold.js";
import type {
  LegacySeedStore,
  LegacySeedStream,
} from "./legacy-seed-producer.js";

/**
 * A `LegacySeedStore` over a host's own scope storage: the stored envelopes
 * `<source>.<stream>` whose body is `{records: [row, …]}` (one PDPP stream per
 * scope, as `withLegacyProjection` reads them).
 *
 * Which connector and stream a scope is comes from `targets`, which the host
 * derives from the legacy bindings (this layer names no connector); its
 * primary key and artifact version come from the verified manifest documents.
 * Nothing is guessed: a scope that cannot be tied to exactly one declared
 * stream is left out and reported through `onExcluded`, by reason:
 *
 * - `no_binding`: no binding names the scope as a stream scope.
 * - `no_declaration`: no verified manifest declares the stream.
 * - `ambiguous_connector`: more than one verified connector fits.
 * - `unknown_source`: the rows carry a `$pdpp.sourceId` that no declared
 *   connector of the scope claims. Rows are never imported under another
 *   connector.
 * - `source_conflict`: the stored versions carry more than one source id.
 *   The whole scope is excluded (not split by identity: one stream has one
 *   connector, and a mixed history cannot be told apart safely).
 * - `ambiguous_declaration`: several verified manifest versions fit.
 * - `shadowed_alias`: the stream also has a canonical `<source>.<stream>`
 *   scope, which is the one read; this alias scope was not offered.
 * - `not_stream_rows`: the newest stored version is not `{records}` of plain
 *   rows (an app-shaped legacy body, or rows tagged with another stream), so
 *   it cannot be folded into stream rows.
 *
 * - `unreadable_scope`: a stored envelope required to admit this scope could not be read.
 *
 * Versions are the layers, newest first. Reads are lazy and one version at a
 * time; the storage is only read, never written.
 */
export type LegacyScopeExclusionReason =
  | "no_binding"
  | "no_declaration"
  | "ambiguous_connector"
  | "unknown_source"
  | "source_conflict"
  | "ambiguous_declaration"
  | "shadowed_alias"
  | "not_stream_rows"
  | "unreadable_scope";

export interface LegacyScopeExclusion {
  readonly scope: string;
  readonly reason: LegacyScopeExclusionReason;
}

export type LegacyScopeStorage = Pick<
  DataStoragePort,
  "listScopes" | "listVersions" | "readEnvelope"
>;

export interface LegacyScopeStoreOptions {
  readonly storage: LegacyScopeStorage;
  /** Verified manifest documents, read at each `streams()` call. */
  readonly manifests: () => Iterable<string>;
  /** The stream scopes the host knows, each with the connector streams it may
   * hold. A scope with one target is stored under its own name. */
  readonly targets: ReadonlyMap<string, readonly LegacyScopeTarget[]>;
  readonly onExcluded?: (exclusion: LegacyScopeExclusion) => void;
  /** Checked before each stored body or version list is read, so a stop does
   * not wait for the scan of excluded scopes. */
  readonly signal?: AbortSignal;
  /** Asked before a stream's stored versions are read. `final`: the host
   * already holds the stream's final receipt, so its history is not read now.
   * `leave`: the host does not want the stream this time; it is not yielded.
   * Absent or `open`: the stream is read in full. */
  readonly receipt?: (
    connector: string,
    stream: string,
  ) => Promise<"open" | "final" | "leave">;
}

export type LegacyScopeStore = LegacySeedStore;

const PAGE = 200;

export interface LegacyScopeTarget {
  readonly connector: string;
  readonly stream: string;
  /** The `$pdpp.sourceId` this connector's stored rows carry. Rows tagged
   * with another id are never imported under this connector. */
  readonly sourceId?: string;
}
type Target = LegacyScopeTarget;

type Declaration = { version: string; primaryKey: readonly string[] };

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** `{records: [...]}` of plain rows, ignoring the server's stamps. */
function plainRows(body: unknown): unknown[] | null {
  if (!isObject(body)) return null;
  const keys = Object.keys(body).filter(
    (key) => key !== "$writtenBy" && key !== "$lineage",
  );
  if (keys.length !== 1 || keys[0] !== "records") return null;
  const rows = body.records;
  if (!Array.isArray(rows)) return null;
  const tagged = (row: unknown) =>
    isObject(row) && typeof row.stream === "string" && isObject(row.data);
  return rows.some(tagged) ? null : rows;
}

/** The `$pdpp.sourceId` values of a body's rows. */
function sourceIdsOf(body: unknown, into: Set<string>): void {
  for (const row of plainRows(body) ?? []) {
    const meta = isObject(row) ? row["$pdpp"] : undefined;
    const id = isObject(meta) ? meta.sourceId : undefined;
    if (typeof id === "string" && id.length > 0) into.add(id);
  }
}

function versionsNewestFirst(
  storage: LegacyScopeStorage,
  scope: string,
): { collectedAt: string; id: number }[] {
  const all: { collectedAt: string; id: number }[] = [];
  for (let offset = 0; ; offset += PAGE) {
    const page = storage.listVersions(scope, { limit: PAGE, offset });
    for (const entry of page)
      all.push({ collectedAt: entry.collectedAt, id: entry.id });
    if (page.length < PAGE) break;
  }
  return all.sort(
    (a, b) =>
      Date.parse(b.collectedAt) - Date.parse(a.collectedAt) || b.id - a.id,
  );
}

function listAllScopes(storage: LegacyScopeStorage): string[] {
  const scopes: string[] = [];
  for (let offset = 0; ; offset += PAGE) {
    const page = storage.listScopes({ limit: PAGE, offset });
    for (const entry of page.scopes) scopes.push(entry.scope);
    if (page.scopes.length < PAGE) break;
  }
  return scopes;
}

export function createLegacyScopeStore(
  options: LegacyScopeStoreOptions,
): LegacyScopeStore {
  const { storage, signal } = options;
  /** Every storage read goes through here, so each one is a stop point. */
  const readBody = async (scope: string, collectedAt: string) => {
    signal?.throwIfAborted();
    return (await storage.readEnvelope(scope, collectedAt)).data;
  };
  // Admission reads may exclude a whole scope. Keep layer reads strict:
  // a failure once folding has begun must never masquerade as partial success.
  const unreadable = Symbol("unreadable legacy scope");
  const admissionBody = async (
    scope: string,
    collectedAt: string,
  ): Promise<{ body: unknown } | typeof unreadable> => {
    try {
      return { body: await readBody(scope, collectedAt) };
    } catch {
      signal?.throwIfAborted();
      return unreadable;
    }
  };
  const versionsOf = (scope: string) => {
    signal?.throwIfAborted();
    return versionsNewestFirst(storage, scope);
  };
  const exclude = (scope: string, reason: LegacyScopeExclusionReason) =>
    options.onExcluded?.({ scope, reason });
  const { targets } = options;

  /** The verified declarations, indexed once per `streams()` call, so every
   * decision of one enumeration reads one snapshot. */
  function indexDeclarations(): (
    connector: string,
    stream: string,
  ) => Declaration | LegacyScopeExclusionReason {
    const index = new Map<string, Declaration[]>();
    for (const document of options.manifests()) {
      const artifact = manifestArtifact(document);
      if (!artifact) continue;
      const { connector, version } = artifact.declarations;
      for (const declared of artifact.declarations.streams) {
        const key = `${connector}\0${declared.name}`;
        const list = index.get(key) ?? [];
        list.push({ version, primaryKey: declared.primaryKey });
        index.set(key, list);
      }
    }
    return (connector, stream) => {
      const found = index.get(`${connector}\0${stream}`) ?? [];
      if (found.length === 0) return "no_declaration";
      if (found.length > 1) return "ambiguous_declaration";
      // `manifestArtifact` rejects a manifest with a keyless stream whole, so a
      // declaration always has a primary key.
      return found[0]!;
    };
  }

  return {
    async *streams() {
      const declare = indexDeclarations();
      /** The source ids of a scope's newest stored version. */
      const newestSources = async (
        scope: string,
      ): Promise<Set<string> | typeof unreadable> => {
        const ids = new Set<string>();
        const newest = versionsOf(scope)[0];
        if (newest) {
          const read = await admissionBody(scope, newest.collectedAt);
          if (read === unreadable) return unreadable;
          sourceIdsOf(read.body, ids);
        }
        return ids;
      };
      /** The one target of a scope, or why there is none. A connector with no
       * declaration for the stream is no candidate. One candidate is taken as
       * is (its rows are checked against it before they are read in). Several
       * are told apart by the source id the stored rows carry. */
      const scopeTarget = async (
        scope: string,
      ): Promise<Target | LegacyScopeExclusionReason> => {
        const candidates = targets.get(scope) ?? [];
        if (candidates.length === 0) return "no_binding";
        const declared = candidates.filter(
          (t) => declare(t.connector, t.stream) !== "no_declaration",
        );
        if (declared.length === 0) return "no_declaration";
        if (declared.length === 1) return declared[0]!;
        const ids = await newestSources(scope);
        if (ids === unreadable) return "unreadable_scope";
        if (ids.size === 0) return "ambiguous_connector";
        if (ids.size > 1) return "source_conflict";
        const [id] = ids;
        const matching = declared.filter((t) => t.sourceId === id);
        if (matching.length === 0) return "unknown_source";
        return matching.length === 1 ? matching[0]! : "ambiguous_connector";
      };
      // A stream stored under several scope names (its own and an alias)
      // is read from its canonical `<source>.<stream>` scope when it exists.
      const byStream = new Map<
        string,
        {
          target: Target;
          declaration: Declaration | LegacyScopeExclusionReason;
          scopes: string[];
        }
      >();
      for (const scope of listAllScopes(storage)) {
        const target = await scopeTarget(scope);
        if (typeof target === "string") {
          exclude(scope, target);
          continue;
        }
        const key = `${target.connector}\0${target.stream}`;
        const entry = byStream.get(key) ?? {
          target,
          declaration: declare(target.connector, target.stream),
          scopes: [],
        };
        entry.scopes.push(scope);
        byStream.set(key, entry);
      }
      streams: for (const {
        target,
        declaration,
        scopes,
      } of byStream.values()) {
        const canonical = scopes.filter(
          (scope) => scope.slice(scope.indexOf(".") + 1) === target.stream,
        );
        const chosen = canonical.length === 1 ? canonical : scopes;
        if (chosen.length !== 1) {
          for (const scope of scopes) exclude(scope, "ambiguous_connector");
          continue;
        }
        const scope = chosen[0]!;
        for (const other of scopes)
          if (other !== scope) exclude(other, "shadowed_alias");
        if (typeof declaration === "string") {
          exclude(scope, declaration);
          continue;
        }
        const state =
          (await options.receipt?.(target.connector, target.stream)) ?? "open";
        if (state === "leave") continue;
        const versions = versionsOf(scope);
        const newest = versions[0];
        if (!newest) continue;
        // The producer reads no history of a stream with a final receipt, and
        // neither does this. Otherwise the newest body alone decides whether
        // the scope is importable: an app-shaped newest body is left out
        // without reading any older version.
        let sourceId: string | undefined;
        if (state !== "final") {
          const latest = await admissionBody(scope, newest.collectedAt);
          if (latest === unreadable) {
            exclude(scope, "unreadable_scope");
            continue;
          }
          if (plainRows(latest.body) === null) {
            exclude(scope, "not_stream_rows");
            continue;
          }
          // Every stored layer must name the one source the connector claims.
          const ids = new Set<string>();
          sourceIdsOf(latest.body, ids);
          for (const version of versions.slice(1)) {
            const read = await admissionBody(scope, version.collectedAt);
            if (read === unreadable) {
              exclude(scope, "unreadable_scope");
              continue streams;
            }
            sourceIdsOf(read.body, ids);
          }
          if (ids.size > 1) {
            exclude(scope, "source_conflict");
            continue;
          }
          [sourceId] = ids;
          if (sourceId !== undefined && sourceId !== target.sourceId) {
            exclude(scope, "unknown_source");
            continue;
          }
        }
        const layers: FoldLayer[] = versions.map((version) => ({
          async *records() {
            const rows = plainRows(await readBody(scope, version.collectedAt));
            if (rows) yield* rows;
          },
        }));
        const stream: LegacySeedStream = {
          connector: target.connector,
          stream: target.stream,
          primaryKey: declaration.primaryKey,
          version: declaration.version,
          layers,
          ...(sourceId === undefined ? {} : { sourceId }),
        };
        yield stream;
      }
    },
  };
}

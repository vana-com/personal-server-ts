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
 * - `ambiguous_declaration`: several verified manifest versions fit.
 * - `no_primary_key`: the declaration has no primary key.
 * - `not_stream_rows`: the newest stored version is not `{records}` of plain
 *   rows (an app-shaped legacy body, or rows tagged with another stream), so
 *   it cannot be folded into stream rows.
 *
 * Versions are the layers, newest first. Reads are lazy and one version at a
 * time; the storage is only read, never written.
 */
export type LegacyScopeExclusionReason =
  | "no_binding"
  | "no_declaration"
  | "ambiguous_connector"
  | "ambiguous_declaration"
  | "no_primary_key"
  | "not_stream_rows";

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
}

export interface LegacyScopeStore extends LegacySeedStore {
  /** The one scope `streams()` read a stream from, once it has yielded it.
   * Only that scope's versions were offered for import. */
  scopeOf(connector: string, stream: string): string | undefined;
  /** How many stored versions of the scope `streams()` read a stream from are
   * not plain `{records}` and so were not offered for import. Retiring that
   * scope would erase them. Undefined until the stream has been yielded. */
  skippedVersions(connector: string, stream: string): number | undefined;
}

const PAGE = 200;

export interface LegacyScopeTarget {
  readonly connector: string;
  readonly stream: string;
}
type Target = LegacyScopeTarget;

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
  const { storage } = options;
  const exclude = (scope: string, reason: LegacyScopeExclusionReason) =>
    options.onExcluded?.({ scope, reason });
  const { targets } = options;
  const read = new Map<string, string>();
  const skipped = new Map<string, number>();

  /** The one verified declaration of a stream, or why there is none. */
  function declare(
    connector: string,
    stream: string,
  ):
    | { version: string; primaryKey: readonly string[] }
    | LegacyScopeExclusionReason {
    const found = [...options.manifests()].flatMap((document) => {
      const artifact = manifestArtifact(document);
      if (artifact?.declarations.connector !== connector) return [];
      const declared = artifact.declarations.streams.find(
        (s) => s.name === stream,
      );
      return declared
        ? [{ version: artifact.declarations.version, declared }]
        : [];
    });
    if (found.length === 0) return "no_declaration";
    if (found.length > 1) return "ambiguous_declaration";
    const { version, declared } = found[0]!;
    if (declared.primaryKey.length === 0) return "no_primary_key";
    return { version, primaryKey: declared.primaryKey };
  }

  const scopeTarget = (scope: string): Target | LegacyScopeExclusionReason => {
    const candidates = targets.get(scope) ?? [];
    if (candidates.length === 0) return "no_binding";
    // The host's verified manifests decide between connectors that share a
    // scope; a connector with no declaration for the stream is no candidate.
    const declared = candidates.filter(
      (t) => declare(t.connector, t.stream) !== "no_declaration",
    );
    if (declared.length === 0) return "no_declaration";
    return declared.length === 1 ? declared[0]! : "ambiguous_connector";
  };

  return {
    scopeOf: (connector, stream) =>
      read.get(JSON.stringify([connector, stream])),
    skippedVersions: (connector, stream) =>
      skipped.get(JSON.stringify([connector, stream])),
    async *streams() {
      // A stream stored under several scope names (its own and an alias)
      // is read from its canonical `<source>.<stream>` scope when it exists.
      const byStream = new Map<string, { target: Target; scopes: string[] }>();
      for (const scope of listAllScopes(storage)) {
        const target = scopeTarget(scope);
        if (typeof target === "string") {
          exclude(scope, target);
          continue;
        }
        const key = `${target.connector}\0${target.stream}`;
        const entry = byStream.get(key) ?? { target, scopes: [] };
        entry.scopes.push(scope);
        byStream.set(key, entry);
      }
      for (const { target, scopes } of byStream.values()) {
        const canonical = scopes.filter(
          (scope) => scope.slice(scope.indexOf(".") + 1) === target.stream,
        );
        const chosen = canonical.length === 1 ? canonical : scopes;
        if (chosen.length !== 1) {
          for (const scope of scopes) exclude(scope, "ambiguous_connector");
          continue;
        }
        const scope = chosen[0]!;
        const declaration = declare(target.connector, target.stream);
        if (typeof declaration === "string") {
          exclude(scope, declaration);
          continue;
        }
        const versions = versionsNewestFirst(storage, scope);
        const newest = versions[0];
        if (!newest) continue;
        // Every version is checked now, so the host knows before it retires
        // the scope which stored versions were never offered.
        const importableVersions: boolean[] = [];
        for (const version of versions)
          importableVersions.push(
            plainRows(
              (await storage.readEnvelope(scope, version.collectedAt)).data,
            ) !== null,
          );
        if (!importableVersions[0]) {
          exclude(scope, "not_stream_rows");
          continue;
        }
        const skippedCount = importableVersions.filter((ok) => !ok).length;
        const layers: FoldLayer[] = versions.map((version) => ({
          async *records() {
            const rows = plainRows(
              (await storage.readEnvelope(scope, version.collectedAt)).data,
            );
            if (rows) yield* rows;
          },
        }));
        const stream: LegacySeedStream = {
          connector: target.connector,
          stream: target.stream,
          primaryKey: declaration.primaryKey,
          version: declaration.version,
          layers,
        };
        const key = JSON.stringify([target.connector, target.stream]);
        read.set(key, scope);
        skipped.set(key, skippedCount);
        yield stream;
      }
    },
  };
}

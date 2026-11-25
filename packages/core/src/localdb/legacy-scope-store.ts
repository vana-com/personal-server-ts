import { ProtocolError } from "../errors/catalog.js";
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
 *   rows (an app-shaped legacy body, or rows tagged with another stream, as a
 *   `{stream, data}` wrapper or a `$pdpp.stream.name` marker), so it cannot be
 *   folded into stream rows.
 *
 * The source id a stream's rows must carry is the one its verified manifest
 * names (`source.id`); a target's own `sourceId` is the fallback for a
 * manifest that names none.
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
  /** Asked when a stored envelope has vanished since it was listed (the
   * host's delete path erases legacy scopes). `true`: the connector was
   * deleted, so its stream is offered as refused-deleted and the scan goes
   * on. `false`: the read fails, as any other fault. */
  readonly connectorDeleted?: (connector: string) => Promise<boolean>;
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

type Declaration = {
  version: string;
  primaryKey: readonly string[];
  /** The `source.id` of the verified manifest, when it names one. */
  sourceId?: string;
};

/** Reading a deleted connector's stream: the producer refuses it as deleted. */
function connectorDeletedRecords(): never {
  throw new ProtocolError(
    410,
    "CONNECTION_DELETED",
    "The connection was deleted",
  );
}

const isEnvelopeMissing = (error: unknown) =>
  error instanceof Error && error.message.includes("Envelope not found");

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** `{records: [...]}` of plain rows, ignoring the server's stamps. With
 * `stream`, a row whose `$pdpp.stream.name` names another stream is not plain
 * either: the fold quarantines it, so it cannot make the scope importable. */
function plainRows(body: unknown, stream?: string): unknown[] | null {
  if (!isObject(body)) return null;
  const keys = Object.keys(body).filter(
    (key) => key !== "$writtenBy" && key !== "$lineage",
  );
  if (keys.length !== 1 || keys[0] !== "records") return null;
  const rows = body.records;
  if (!Array.isArray(rows)) return null;
  const tagged = (row: unknown) => {
    if (!isObject(row)) return false;
    if (typeof row.stream === "string" && isObject(row.data)) return true;
    if (stream === undefined) return false;
    const meta = Object.hasOwn(row, "$pdpp") ? row["$pdpp"] : undefined;
    const marker =
      isObject(meta) && Object.hasOwn(meta, "stream") ? meta.stream : undefined;
    const name =
      isObject(marker) && Object.hasOwn(marker, "name")
        ? marker.name
        : undefined;
    return name !== undefined && name !== stream;
  };
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

/** The `source.id` a verified manifest document names, if any. */
function manifestSourceId(document: string): string | undefined {
  const parsed: unknown = JSON.parse(document);
  const source = isObject(parsed) ? parsed.source : undefined;
  const id = isObject(source) ? source.id : undefined;
  return typeof id === "string" && id !== "" ? id : undefined;
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
  const versionsOf = (scope: string) => {
    signal?.throwIfAborted();
    return versionsNewestFirst(storage, scope);
  };
  const exclude = (scope: string, reason: LegacyScopeExclusionReason) =>
    options.onExcluded?.({ scope, reason });
  const { targets } = options;
  /** A read that found its envelope gone, while the host says its connector
   * was deleted. */
  const vanishedWithConnector = async (error: unknown, connector: string) =>
    isEnvelopeMissing(error) &&
    (await options.connectorDeleted?.(connector)) === true;

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
      const sourceId = manifestSourceId(document);
      for (const declared of artifact.declarations.streams) {
        const key = `${connector}\0${declared.name}`;
        const list = index.get(key) ?? [];
        list.push({
          version,
          primaryKey: declared.primaryKey,
          ...(sourceId === undefined ? {} : { sourceId }),
        });
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
      /** The source id a target's rows must carry: the verified manifest's
       * own, else the target's. */
      const expectedSource = (t: Target): string | undefined => {
        const declaration = declare(t.connector, t.stream);
        return typeof declaration === "string"
          ? t.sourceId
          : (declaration.sourceId ?? t.sourceId);
      };
      /** The source ids of a scope's newest stored version. */
      const newestSources = async (scope: string): Promise<Set<string>> => {
        const ids = new Set<string>();
        const newest = versionsOf(scope)[0];
        if (newest) sourceIdsOf(await readBody(scope, newest.collectedAt), ids);
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
        if (ids.size === 0) return "ambiguous_connector";
        if (ids.size > 1) return "source_conflict";
        const [id] = ids;
        const matching = declared.filter((t) => expectedSource(t) === id);
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
      for (const { target, declaration, scopes } of byStream.values()) {
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
          try {
            if (
              plainRows(
                await readBody(scope, newest.collectedAt),
                target.stream,
              ) === null
            ) {
              exclude(scope, "not_stream_rows");
              continue;
            }
            // Every stored layer must name the one source the connector claims.
            const ids = new Set<string>();
            for (const version of versions)
              sourceIdsOf(await readBody(scope, version.collectedAt), ids);
            if (ids.size > 1) {
              exclude(scope, "source_conflict");
              continue;
            }
            [sourceId] = ids;
            if (sourceId !== undefined && sourceId !== expectedSource(target)) {
              exclude(scope, "unknown_source");
              continue;
            }
          } catch (error) {
            // An envelope erased since it was listed: if its connector was
            // deleted, the producer refuses this stream as deleted and the
            // scan goes on; any other fault stops the scan.
            if (!(await vanishedWithConnector(error, target.connector)))
              throw error;
            yield {
              connector: target.connector,
              stream: target.stream,
              primaryKey: declaration.primaryKey,
              version: declaration.version,
              layers: [{ records: connectorDeletedRecords }],
            };
            continue;
          }
        }
        const layers: FoldLayer[] = versions.map((version) => ({
          async *records() {
            let body: unknown;
            try {
              body = await readBody(scope, version.collectedAt);
            } catch (error) {
              if (await vanishedWithConnector(error, target.connector))
                connectorDeletedRecords();
              throw error;
            }
            const rows = plainRows(body);
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

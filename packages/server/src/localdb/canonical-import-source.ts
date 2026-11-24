import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  foldLayers,
  type FoldLayer,
  type ImportInventoryEntry,
  type ImportSource,
  type ImportTarget,
  type ImportProjectionPort,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2/F.4: bounded page port implemented privately by legacy-access; no store opened here. */
export interface CanonicalImportPageReader {
  /** Declarations retained and verified by the existing authority, not caller manifests. */
  readonly declarations: readonly DeclarationSnapshot[];
  /** Complete stored inventory independent of declarations, keyset paged by the
   * implementation. Includes unknown source ids, unbound instances and streams.
   * Bound to options.revision; mutation/incomplete inventory must throw. */
  inventory(revision: string): AsyncIterable<{
    readonly sourceId: string | null;
    readonly instance: string;
    readonly stream: string;
    readonly rows: number;
  }>;
  /** Check the entire snapshot, not just one stream; call before/after each
   * inventory and records pass. Source quiescence is owned by legacy-access. */
  assertRevision(revision: string): Promise<void>;
  connections(
    sourceId: string,
  ): Promise<
    readonly { instance: string; deleted: boolean; lastActive: number }[]
  >;
  /** Live rows of a stream, for the report of a source that merges instances.
   * Optional: a reader without it leaves the merged source's count unset. */
  rows?(instance: string, stream: string, revision: string): Promise<number>;
  /** Record keys of the rows a stream deleted, keyset paged like `page`. A
   * newer instance's deletion keeps an older instance's copy out. Optional:
   * a reader without it names no deletions. */
  deletedKeys?(
    instance: string,
    stream: string,
    after: string | null,
    limit: number,
    revision: string,
  ): Promise<{
    readonly keys: readonly string[];
    readonly next: string | null;
  }>;
  page(
    instance: string,
    stream: string,
    after: string | null,
    limit: number,
    /** Page byte target. A single larger record travels alone, as in intake. */
    maxBytes: number,
    revision: string,
  ): Promise<{
    /** Stored rows as parsed. A row that is not a JSON object (or not JSON) is
     * `null`: the import counts it out (`not_an_object`), it does not stop. */
    readonly rows: readonly unknown[];
    readonly next: string | null;
  }>;
}

/**
 * F.2/F.3: adapt canonical pdpp_records via verified declarations and LIMIT
 * pages (byte bound too). Immutable revision, explicit exclusions; older
 * instances or missing declarations are counted, not imported. Derive
 * connector/stream/key from declarations, never connector-id literals. Do not
 * invert legacy projected JSON or add transition tables. Record acceptance follows run intake; no import-only size limit. Factory returns descriptors lazily.
 * incremental defaults true as in IntakeStreamDeclaration; it is not inferred
 * from semantics or a new declaration field. Most recently active live instance wins (stable instance tie break).
 * Unknown inventory yields ImportExclusion; never invent declaration/key/target.
 *
 * Older live instances of the same source id merge into the newest one's
 * stream (`olderInstances: "merge"`, the default): one source per stream, its
 * layers the live instances by rank, newest first, so the newest body of a
 * key wins whatever order anything reads or submits in (`foldLayers`). A
 * deleted instance (the person removed the connection) is never merged: its
 * rows stay excluded as `deleted_instance`. `"exclude"` keeps the newest
 * instance only, as before.
 */
export async function* createCanonicalImportSource(options: {
  readonly owner: string;
  readonly network: string;
  readonly revision: string;
  readonly bindings: ImportProjectionPort["bindings"];
  readonly reader: CanonicalImportPageReader;
  /** What becomes of the live instances that are not the newest of their
   * source id. Default `"merge"`. */
  readonly olderInstances?: "merge" | "exclude";
  /** Same authenticated connection authority as host uploads; null excludes.
   * Never turn a legacy instance/install id into a new sync namespace. */
  readonly resolveTarget: (
    sourceId: string,
    instance: string,
    stream: string,
  ) => Promise<ImportTarget | null>;
}): AsyncIterable<ImportInventoryEntry> {
  const { owner, network, revision, reader, resolveTarget } = options;
  const merge = (options.olderInstances ?? "merge") === "merge";
  const check = () => reader.assertRevision(revision);
  await check();
  for await (const entry of reader.inventory(revision)) {
    await check();
    const source = JSON.stringify([entry.instance, entry.sourceId, revision]);
    const exclude = (reason: string) => ({
      kind: "excluded" as const,
      source,
      revision,
      reason,
      rows: entry.rows,
    });
    const declarations = reader.declarations.filter(
      (d) => d.source_id === entry.sourceId,
    );
    if (declarations.length !== 1) {
      yield exclude(
        declarations.length === 0
          ? "undeclared_source"
          : "ambiguous_declaration",
      );
      continue;
    }
    const streams = declarations[0]!.streams.filter(
      (s) => s.name === entry.stream,
    );
    if (streams.length !== 1) {
      yield exclude("undeclared_stream");
      continue;
    }
    const stream = streams[0]!;
    if (stream.primary_key.length === 0) {
      yield exclude("unkeyed_stream");
      continue;
    }
    const live = (await reader.connections(entry.sourceId!)).filter(
      (c) => !c.deleted,
    );
    live.sort(
      (a, b) =>
        b.lastActive - a.lastActive || a.instance.localeCompare(b.instance),
    );
    const rank = live.findIndex((c) => c.instance === entry.instance);
    if (rank < 0) {
      yield exclude("deleted_instance");
      continue;
    }
    // An older live instance is a layer of the newest one's source, below.
    if (rank > 0) {
      if (merge) continue;
      yield exclude("older_instance");
      continue;
    }
    const resolved = await resolveTarget(
      entry.sourceId!,
      entry.instance,
      entry.stream,
    );
    if (
      !resolved ||
      !resolved.connectionId ||
      !resolved.connector ||
      resolved.stream !== entry.stream
    ) {
      yield exclude("unknown_identity");
      continue;
    }
    if (
      ![...options.bindings.values()].some(
        (b) =>
          b.connector === resolved.connector &&
          b.streams.includes(entry.stream),
      )
    ) {
      yield exclude("unbound_store");
      continue;
    }
    const target = Object.freeze({
      ...resolved,
      primaryKey: Object.freeze([...stream.primary_key]),
      semantics: stream.semantics ?? "mutable_state",
    });
    // Capture scalars, not mutable inventory objects from the adapter.
    const streamName = entry.stream;
    const instances = merge ? live.map((c) => c.instance) : [entry.instance];
    const layers = instances.map((instance) =>
      layerOf(reader, revision, check, instance, streamName),
    );
    const base: Omit<ImportSource, "records" | "deletions"> = {
      source,
      owner,
      network,
      revision,
      target,
      exclusions: [],
      rows: entry.rows,
    };
    if (instances.length === 1) {
      yield { ...base, records: layers[0]!.records };
      continue;
    }
    // Several live instances: one source, named for the merge, over their layers.
    let rows: number | undefined = entry.rows;
    if (reader.rows)
      for (const instance of instances.slice(1))
        rows += await reader.rows(instance, streamName, revision);
    else rows = undefined;
    yield foldLayers(
      {
        ...base,
        source: JSON.stringify(["merged", entry.sourceId, revision]),
        ...(rows === undefined ? {} : { rows }),
      },
      layers,
    );
  }
  await check();
}

/** One instance's stream as a layer: its rows, and the keys it deleted. */
function layerOf(
  reader: CanonicalImportPageReader,
  revision: string,
  check: () => Promise<void>,
  instance: string,
  streamName: string,
): FoldLayer {
  return {
    async *records() {
      await check();
      let cursor: string | null = null;
      do {
        await check();
        let page:
          Awaited<ReturnType<CanonicalImportPageReader["page"]>> | undefined =
          await reader.page(
            instance,
            streamName,
            cursor,
            128,
            4 * 1024 * 1024,
            revision,
          );
        await check();
        if (page.rows.length > 128) throw new Error("invalid_page_size");
        if (
          page.next !== null &&
          (page.next === cursor || page.rows.length === 0)
        ) {
          throw new Error("invalid_page_cursor");
        }
        // A row with no full key is the import's to count, not this reader's
        // to refuse: one bad row must not hide the rest of its stream.
        for (const record of page.rows) yield record;
        cursor = page.next;
        // A suspended generator keeps locals rooted. Drop the consumed page
        // before the host handoff and the next decoded page allocation.
        page = undefined;
        // A native reader can resolve every page synchronously. Let host
        // tasks and collection run before allocating the next decoded page.
        if (cursor !== null)
          await new Promise<void>((resolve) => setTimeout(resolve, 0));
      } while (cursor !== null);
      await check();
    },
    async *deletedRecordKeys() {
      if (!reader.deletedKeys) return;
      let cursor: string | null = null;
      do {
        await check();
        const page: Awaited<
          ReturnType<NonNullable<typeof reader.deletedKeys>>
        > = await reader.deletedKeys(
          instance,
          streamName,
          cursor,
          1024,
          revision,
        );
        await check();
        if (
          page.next !== null &&
          (page.next === cursor || page.keys.length === 0)
        )
          throw new Error("invalid_page_cursor");
        yield* page.keys;
        cursor = page.next;
      } while (cursor !== null);
    },
  };
}

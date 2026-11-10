import { computeRecordKeyFromData } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  ImportInventoryEntry,
  ImportTarget,
  ImportProjectionPort,
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
  page(
    instance: string,
    stream: string,
    after: string | null,
    limit: number,
    /** Page byte target. A single larger record travels alone, as in intake. */
    maxBytes: number,
    revision: string,
  ): Promise<{
    readonly rows: readonly Record<string, unknown>[];
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
 */
export async function* createCanonicalImportSource(options: {
  readonly owner: string;
  readonly network: string;
  readonly revision: string;
  readonly bindings: ImportProjectionPort["bindings"];
  readonly reader: CanonicalImportPageReader;
  /** Same authenticated connection authority as host uploads; null excludes.
   * Never turn a legacy instance/install id into a new sync namespace. */
  readonly resolveTarget: (
    sourceId: string,
    instance: string,
    stream: string,
  ) => Promise<ImportTarget | null>;
}): AsyncIterable<ImportInventoryEntry> {
  const { owner, network, revision, reader, resolveTarget } = options;
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
    if (!live.length || live[0]!.instance !== entry.instance) {
      yield exclude(live.length ? "older_instance" : "deleted_instance");
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
    const instance = entry.instance;
    const streamName = entry.stream;
    yield {
      source,
      owner,
      network,
      revision,
      target,
      exclusions: [],
      async *records() {
        await check();
        let cursor: string | null = null;
        do {
          await check();
          const page = await reader.page(
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
          for (const record of page.rows) {
            try {
              computeRecordKeyFromData(record, [...target.primaryKey]);
            } catch {
              throw new Error("invalid_record");
            }
            yield record;
          }
          cursor = page.next;
        } while (cursor !== null);
        await check();
      },
    };
  }
  await check();
}

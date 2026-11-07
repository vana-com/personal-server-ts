/**
 * Durable mirror of the owner's stream-sync registry rows (control and stream
 * scopes), fed by the download worker's deletion-aware listing.
 *
 * The listing is incremental (it resumes at the sync cursor), so the mirror is
 * the only place that remembers every physical row. It is written before the
 * download worker advances its cursor, so a crash never loses a row. A host
 * that turns reads on with an existing cursor gets one full listing first
 * (`needsFullListing`).
 */

import {
  parseScope,
  type ControlRead,
  type ParsedScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncReadFiles } from "./ports.js";

/** One physical registry row as last listed. */
export interface MirrorRow {
  readonly scope: string;
  readonly version: number;
  readonly dataHash: string;
  readonly metadataHash: string;
  readonly deleted: boolean;
  /** Registry time of this version (`addedAt`), ms since the epoch, or null. */
  readonly addedAtMs: number | null;
}

/** The row shape the download feed lists. */
export interface MirrorFeedRow {
  readonly scope: string;
  readonly dataHash: string;
  readonly metadataHash: string;
  readonly expectedVersion: string;
  readonly addedAt?: string | null;
  readonly deletedAt?: string | null;
}

export interface ConnectorRows {
  /** ns → control row. */
  readonly controls: ReadonlyMap<string, MirrorRow>;
  /** ns → stream → stream row. */
  readonly streams: ReadonlyMap<string, ReadonlyMap<string, MirrorRow>>;
}

interface MirrorFile {
  readonly format: 1;
  /** A listing from the start of the registry has reached its last page. */
  readonly listed: boolean;
  readonly rows: Record<string, MirrorRow>;
  /**
   * Stream scope → highest tombstoned version observed. Absent in files
   * written before the floor existed.
   */
  readonly deletionFloors?: Record<string, number>;
}

/** True when the row marks its stream deleted, by either encoding. */
export type TombstoneTest = (row: MirrorRow) => boolean;

const PATH = "mirror.json";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toControlRead(row: MirrorRow | undefined): ControlRead {
  if (!row) return { found: false };
  return {
    found: true,
    version: row.version,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
    deleted: row.deleted,
  };
}

function rowFromFeed(feed: MirrorFeedRow): MirrorRow | null {
  const version = Number(feed.expectedVersion);
  if (!Number.isSafeInteger(version) || version < 1) return null;
  const addedAtMs =
    typeof feed.addedAt === "string" ? Date.parse(feed.addedAt) : NaN;
  return {
    scope: feed.scope,
    version,
    dataHash: feed.dataHash.toLowerCase(),
    metadataHash: feed.metadataHash.toLowerCase(),
    deleted: typeof feed.deletedAt === "string" && feed.deletedAt !== "",
    addedAtMs: Number.isFinite(addedAtMs) ? addedAtMs : null,
  };
}

/** Newer version wins; the same version may only gain a deletion. */
function replaces(next: MirrorRow, current: MirrorRow | undefined): boolean {
  if (!current) return true;
  if (next.version !== current.version) return next.version > current.version;
  return next.deleted && !current.deleted;
}

export class RegistryMirror {
  private pending: Promise<void> = Promise.resolve();

  private constructor(
    private readonly files: StreamSyncReadFiles,
    private rows: Map<string, MirrorRow>,
    private listed: boolean,
    private fullListingStarted: boolean,
    private floors: Map<string, number>,
    private readonly isTombstone: TombstoneTest,
  ) {}

  /**
   * `isTombstone` is the one stream-row rule of the stream-sync package. It
   * lets the mirror remember a deletion after a later live row replaces the
   * tombstone row (see `deletionFloor`).
   */
  static async open(
    files: StreamSyncReadFiles,
    isTombstone: TombstoneTest = (row) => row.deleted,
  ): Promise<RegistryMirror> {
    const bytes = await files.read(PATH);
    if (!bytes) {
      return new RegistryMirror(
        files,
        new Map(),
        false,
        false,
        new Map(),
        isTombstone,
      );
    }
    const parsed = JSON.parse(decoder.decode(bytes)) as MirrorFile;
    if (parsed.format !== 1) {
      throw new Error("unsupported stream-sync mirror format");
    }
    return new RegistryMirror(
      files,
      new Map(Object.entries(parsed.rows)),
      parsed.listed,
      false,
      new Map(Object.entries(parsed.deletionFloors ?? {})),
      isTombstone,
    );
  }

  /**
   * The highest version of the stream scope seen tombstoned, or 0. A view at
   * or below it holds records the owner deleted, so it is never served or
   * imported, even after a later live row replaces the tombstone row.
   */
  deletionFloor(scope: string): number {
    return this.floors.get(scope) ?? 0;
  }

  /** True until one listing from the start of the registry has completed. */
  needsFullListing(): boolean {
    return !this.listed;
  }

  /** The next listing must start at the registry's first page. */
  wantsListingFromStart(): boolean {
    return !this.listed && !this.fullListingStarted;
  }

  /**
   * Record listed rows. `fromStart` is true when the page was listed from no
   * cursor; `lastPage` when the listing has no further pages. Persists
   * before returning; the caller advances its cursor only after.
   */
  async observe(
    rows: readonly MirrorFeedRow[],
    page: { readonly fromStart: boolean; readonly lastPage: boolean },
  ): Promise<string[]> {
    const observation = this.pending.then(() => this.observePage(rows, page));
    // A failed write rejects its caller without preventing the next replay.
    this.pending = observation.then(
      () => undefined,
      () => undefined,
    );
    return observation;
  }

  private async observePage(
    rows: readonly MirrorFeedRow[],
    page: { readonly fromStart: boolean; readonly lastPage: boolean },
  ): Promise<string[]> {
    const nextRows = new Map(this.rows);
    const nextFloors = new Map(this.floors);
    const raise = (row: MirrorRow): boolean => {
      if (
        parseScope(row.scope)?.kind !== "stream" ||
        !this.isTombstone(row) ||
        row.version <= (nextFloors.get(row.scope) ?? 0)
      ) {
        return false;
      }
      nextFloors.set(row.scope, row.version);
      return true;
    };
    const fullListingStarted = this.fullListingStarted || page.fromStart;
    const changed = new Set<string>();
    for (const feed of rows) {
      const parsed = parseScope(feed.scope);
      if (!parsed) continue;
      const row = rowFromFeed(feed);
      if (!row) continue;
      const current = nextRows.get(feed.scope);
      // The floor is the highest tombstone ever observed, whatever row the
      // mirror keeps. A file written before floors existed may hold the
      // tombstone row only, so the kept row counts too.
      let floorRaised = current ? raise(current) : false;
      floorRaised = raise(row) || floorRaised;
      const replaced = replaces(row, current);
      if (replaced) nextRows.set(feed.scope, row);
      if (replaced || floorRaised) changed.add(parsed.connector);
    }
    const nowListed = !this.listed && fullListingStarted && page.lastPage;
    const listed = this.listed || nowListed;
    if (changed.size > 0 || nowListed) {
      await this.persist(nextRows, nextFloors, listed);
    }
    this.rows = nextRows;
    this.floors = nextFloors;
    this.fullListingStarted = fullListingStarted;
    this.listed = listed;
    return [...changed];
  }

  connectors(): string[] {
    const out = new Set<string>();
    for (const scope of this.rows.keys()) {
      const parsed = parseScope(scope);
      if (parsed) out.add(parsed.connector);
    }
    return [...out].sort();
  }

  rowsFor(connector: string): ConnectorRows {
    const controls = new Map<string, MirrorRow>();
    const streams = new Map<string, Map<string, MirrorRow>>();
    for (const [scope, row] of this.rows) {
      const parsed: ParsedScope | null = parseScope(scope);
      if (!parsed || parsed.connector !== connector) continue;
      if (parsed.kind === "control") {
        controls.set(parsed.ns, row);
      } else {
        let byStream = streams.get(parsed.ns);
        if (!byStream) streams.set(parsed.ns, (byStream = new Map()));
        byStream.set(parsed.stream, row);
      }
    }
    return { controls, streams };
  }

  private async persist(
    rows: Map<string, MirrorRow>,
    floors: Map<string, number>,
    listed: boolean,
  ): Promise<void> {
    const file: MirrorFile = {
      format: 1,
      listed,
      rows: Object.fromEntries(rows),
      deletionFloors: Object.fromEntries(floors),
    };
    await this.files.write(PATH, encoder.encode(JSON.stringify(file)));
  }
}

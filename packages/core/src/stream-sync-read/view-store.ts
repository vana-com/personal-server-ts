/**
 * Imported stream views (§2.9): per `(connector, ns, stream)`, the clear
 * head of the last imported live version and its verified clear parts.
 *
 * A new version replaces the current one atomically: its head and any new
 * parts are written first, then the `current` pointer. Reads lease the
 * versions they read (§2.9 pinned joins), so an import never removes a
 * version under a running read. Retain the latest complete head as well as
 * the current head and leased versions, so an incomplete publish cannot hide
 * previously complete data. A request that names a retired version is stale.
 *
 * Parts are stored by their SHA-256, shared between versions of a stream,
 * so an import fetches only the parts it does not hold yet.
 */

import { sha256 as hashPart } from "@noble/hashes/sha2";
import {
  decodeHead,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncReadFiles } from "./ports.js";

export interface ViewKey {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
}

export interface ImportedVersion {
  /** Registry version of the stream row. */
  readonly version: number;
  readonly dataHash: string;
  readonly head: Head;
}

export interface ViewLease {
  readonly key: ViewKey;
  readonly version: ImportedVersion;
  release(): void;
}

interface CurrentFile {
  readonly version: number;
  readonly dataHash: string;
  readonly completeVersion?: number;
  readonly completeDataHash?: string;
}

/** What an import may do while it holds the stream's lock. */
export interface ImportTransaction {
  /**
   * Whether an intact copy of the part is stored. A stored copy that does not
   * match its hash (or `expectedBytes`) is removed and reported as missing.
   */
  hasPart(sha256: string, expectedBytes?: number): Promise<boolean>;
  putPart(sha256: string, clear: Uint8Array): Promise<void>;
  /**
   * Make `version` current. Every part of `head` must be stored first.
   * `lastComplete` is the complete head an incomplete `head` replaced, when
   * this store has not seen it: its parts must be stored too.
   */
  commit(
    version: number,
    dataHash: string,
    headBytes: Uint8Array,
    head: Head,
    lastComplete?: LastCompleteHead,
  ): Promise<void>;
  /**
   * Keep `lastComplete` as the complete head when the current head cannot be
   * imported. Its parts must be stored first. It becomes current only when
   * this store has no current view; nothing is acknowledged for the unread one.
   */
  commitComplete(lastComplete: LastCompleteHead): Promise<void>;
}

export interface LastCompleteHead {
  readonly version: number;
  readonly dataHash: string;
  readonly headBytes: Uint8Array;
  readonly head: Head;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Part names hash the clear bytes, not the encrypted storage blob. */
function matchesPart(
  bytes: Uint8Array,
  sha256: string,
  expectedBytes?: number,
): boolean {
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    return false;
  }
  const hash = Array.from(hashPart(bytes), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  return hash === sha256;
}

/** Safe as one path segment: no separators, no dot segments. */
function segment(value: string): string {
  if (
    value === "" ||
    value === "." ||
    value === ".." ||
    /[/\\\0]/.test(value)
  ) {
    throw new Error("name is not usable as a path segment");
  }
  return value;
}

export function viewKeyId(key: ViewKey): string {
  return `${key.connector}\n${key.ns}\n${key.stream}`;
}

function dir(key: ViewKey): string {
  return `views/${segment(key.connector)}/${key.ns === "" ? "_" : segment(key.ns)}/${segment(key.stream)}`;
}

export function isUsableViewKey(key: ViewKey): boolean {
  try {
    dir(key);
    return true;
  } catch {
    return false;
  }
}

export class ViewStore {
  private readonly current = new Map<string, ImportedVersion>();
  private readonly complete = new Map<string, ImportedVersion>();
  /**
   * Per connector and stream: how many imports changed a current version of
   * it, whatever the namespace. A read records the revisions of the streams it
   * touches and compares them when it has paired a base with a plan.
   */
  private readonly importRevisions = new Map<string, number>();
  /** id → version → lease count. */
  private readonly leases = new Map<string, Map<number, number>>();
  /** id → versions on disk that are not current. */
  private readonly retained = new Map<string, Map<number, ImportedVersion>>();
  private readonly keys = new Map<string, ViewKey>();
  /**
   * id → tail of the stream's lock queue. Imports and collections of one
   * stream run one at a time, so a collection never works from keep-sets
   * that an import has since outdated.
   */
  private readonly locks = new Map<string, Promise<void>>();

  private constructor(private readonly files: StreamSyncReadFiles) {}

  static async open(files: StreamSyncReadFiles): Promise<ViewStore> {
    const store = new ViewStore(files);
    for (const path of await files.list("views")) {
      if (!path.endsWith("/current.json")) continue;
      const parts = path.split("/");
      if (parts.length !== 5) continue;
      const key: ViewKey = {
        connector: parts[1]!,
        ns: parts[2] === "_" ? "" : parts[2]!,
        stream: parts[3]!,
      };
      const pointer = JSON.parse(
        decoder.decode((await files.read(path))!),
      ) as CurrentFile;
      const id = viewKeyId(key);
      // The complete pointer stands on its own: load it before a damaged
      // current view is discarded, so a lost incomplete cache hides nothing.
      const fallback = await store.loadComplete(key, pointer);
      const current = await store.loadCurrent(key, pointer);
      // A restore can bring back a pointer without all its parts. With no
      // complete head to keep either, drop the pointer so the stream imports
      // again; surviving parts stay reusable.
      if (!current && !fallback) {
        await files.remove(path);
        continue;
      }
      if (current || fallback) store.keys.set(id, key);
      if (current) store.current.set(id, current);
      if (fallback) store.complete.set(id, fallback);
      else if (current?.head.complete) store.complete.set(id, current);
      // Versions left behind by a crash between pointer write and cleanup.
      await store.collect(key);
    }
    return store;
  }

  /** The head at `version`, when it is intact with all its parts. */
  private async loadIntact(
    key: ViewKey,
    version: number,
    dataHash: string,
    mustBeComplete: boolean,
  ): Promise<ImportedVersion | null> {
    const bytes = await this.files.read(`${dir(key)}/heads/${version}.json`);
    if (!bytes) return null;
    const decoded = decodeHead(bytes);
    if (decoded.kind !== "ok") return null;
    if (mustBeComplete && !decoded.head.complete) return null;
    for (const part of decoded.head.parts) {
      if (!(await this.partExists(key, part.hash))) return null;
    }
    return { version, dataHash, head: decoded.head };
  }

  private loadCurrent(key: ViewKey, pointer: CurrentFile) {
    return this.loadIntact(key, pointer.version, pointer.dataHash, false);
  }

  /** The complete head the pointer names, if the current head is not it. */
  private async loadComplete(
    key: ViewKey,
    pointer: CurrentFile,
  ): Promise<ImportedVersion | null> {
    if (
      pointer.completeVersion === undefined ||
      !pointer.completeDataHash ||
      pointer.completeVersion === pointer.version
    )
      return null;
    return this.loadIntact(
      key,
      pointer.completeVersion,
      pointer.completeDataHash,
      true,
    );
  }

  /** The import revision of one stream of one connector (all namespaces). */
  revision(connector: string, stream: string): number {
    return this.importRevisions.get(`${connector}\n${stream}`) ?? 0;
  }

  get(key: ViewKey): ImportedVersion | null {
    return this.current.get(viewKeyId(key)) ?? null;
  }

  getComplete(key: ViewKey): ImportedVersion | null {
    return this.complete.get(viewKeyId(key)) ?? null;
  }

  views(): { key: ViewKey; version: ImportedVersion }[] {
    return [...this.current].map(([id, version]) => ({
      key: this.keys.get(id)!,
      version,
    }));
  }

  private async partExists(key: ViewKey, sha256: string): Promise<boolean> {
    return (await this.files.read(`${dir(key)}/parts/${sha256}`)) !== null;
  }

  private async hasPart(
    key: ViewKey,
    sha256: string,
    expectedBytes?: number,
  ): Promise<boolean> {
    const path = `${dir(key)}/parts/${sha256}`;
    const bytes = await this.files.read(path);
    if (bytes === null) return false;
    if (matchesPart(bytes, sha256, expectedBytes)) return true;
    // Treat a damaged cache entry like a missing part so the import repairs it.
    await this.files.remove(path);
    return false;
  }

  /** Run `body` while holding the stream's lock. */
  private exclusive<T>(key: ViewKey, body: () => Promise<T>): Promise<T> {
    const id = viewKeyId(key);
    const previous = this.locks.get(id) ?? Promise.resolve();
    const run = previous.then(body);
    const tail = run.then(
      () => undefined,
      () => undefined,
    );
    this.locks.set(id, tail);
    void tail.then(() => {
      if (this.locks.get(id) === tail) this.locks.delete(id);
    });
    return run;
  }

  /**
   * Import one version of a stream. The stream's lock is held from the first
   * part to the commit, so no collection runs against a half-written import.
   */
  withImport<T>(
    key: ViewKey,
    body: (tx: ImportTransaction) => Promise<T>,
  ): Promise<T> {
    return this.exclusive(key, () =>
      body({
        hasPart: (sha256, expectedBytes) =>
          this.hasPart(key, sha256, expectedBytes),
        putPart: (sha256, clear) => this.putPart(key, sha256, clear),
        commit: (version, dataHash, headBytes, head, lastComplete) =>
          this.commit(key, version, dataHash, headBytes, head, lastComplete),
        commitComplete: (lastComplete) =>
          this.commitComplete(key, lastComplete),
      }),
    );
  }

  private async putPart(
    key: ViewKey,
    sha256: string,
    clear: Uint8Array,
  ): Promise<void> {
    await this.files.write(`${dir(key)}/parts/${sha256}`, clear);
  }

  /** Install a complete head without a newer current view (see `ImportTransaction`). */
  private async commitComplete(
    key: ViewKey,
    lastComplete: LastCompleteHead,
  ): Promise<void> {
    const known = this.getComplete(key);
    if (known && known.version >= lastComplete.version) return;
    const id = viewKeyId(key);
    const base = dir(key);
    await this.files.write(
      `${base}/heads/${lastComplete.version}.json`,
      lastComplete.headBytes,
    );
    const complete: ImportedVersion = {
      version: lastComplete.version,
      dataHash: lastComplete.dataHash,
      head: lastComplete.head,
    };
    const current = this.current.get(id) ?? complete;
    const pointer: CurrentFile = {
      version: current.version,
      dataHash: current.dataHash,
      completeVersion: complete.version,
      completeDataHash: complete.dataHash,
    };
    await this.files.write(
      `${base}/current.json`,
      encoder.encode(JSON.stringify(pointer)),
    );
    this.keys.set(id, key);
    this.current.set(id, current);
    this.complete.set(id, complete);
    const touched = `${key.connector}\n${key.stream}`;
    this.importRevisions.set(
      touched,
      (this.importRevisions.get(touched) ?? 0) + 1,
    );
    await this.collectLocked(key);
  }

  /** Make `version` current. Every part of `head` must be stored first. */
  private async commit(
    key: ViewKey,
    version: number,
    dataHash: string,
    headBytes: Uint8Array,
    head: Head,
    lastComplete?: LastCompleteHead,
  ): Promise<void> {
    const base = dir(key);
    await this.files.write(`${base}/heads/${version}.json`, headBytes);
    const known = this.getComplete(key);
    let complete: ImportedVersion | null;
    if (head.complete) complete = { version, dataHash, head };
    else if (lastComplete && (!known || known.version < lastComplete.version)) {
      await this.files.write(
        `${base}/heads/${lastComplete.version}.json`,
        lastComplete.headBytes,
      );
      complete = {
        version: lastComplete.version,
        dataHash: lastComplete.dataHash,
        head: lastComplete.head,
      };
    } else complete = known;
    const pointer: CurrentFile = {
      version,
      dataHash,
      ...(complete
        ? {
            completeVersion: complete.version,
            completeDataHash: complete.dataHash,
          }
        : {}),
    };
    await this.files.write(
      `${base}/current.json`,
      encoder.encode(JSON.stringify(pointer)),
    );
    const id = viewKeyId(key);
    const previous = this.current.get(id);
    this.keys.set(id, key);
    this.current.set(id, { version, dataHash, head });
    if (complete) this.complete.set(id, complete);
    const touched = `${key.connector}\n${key.stream}`;
    this.importRevisions.set(
      touched,
      (this.importRevisions.get(touched) ?? 0) + 1,
    );
    if (previous && previous.version !== version) {
      let retained = this.retained.get(id);
      if (!retained) this.retained.set(id, (retained = new Map()));
      retained.set(previous.version, previous);
    }
    await this.collectLocked(key);
  }

  /**
   * Lease the current version, or `at` when given. `null` when there is no
   * such version: nothing imported, or `at` was retired. Only a caller that
   * reads stream heads exclusively (`includeComplete`) may lease the retained
   * complete head; for everyone else it retires like any older version.
   */
  lease(key: ViewKey, at?: number, includeComplete = false): ViewLease | null {
    const id = viewKeyId(key);
    const current = this.current.get(id);
    let version: ImportedVersion | undefined;
    if (at === undefined || current?.version === at) version = current;
    else
      version =
        includeComplete && this.complete.get(id)?.version === at
          ? this.complete.get(id)
          : this.retained.get(id)?.get(at);
    if (!version) return null;
    let counts = this.leases.get(id);
    if (!counts) this.leases.set(id, (counts = new Map()));
    counts.set(version.version, (counts.get(version.version) ?? 0) + 1);
    let released = false;
    const leased = version;
    return {
      key,
      version: leased,
      release: () => {
        if (released) return;
        released = true;
        const n = (counts!.get(leased.version) ?? 1) - 1;
        if (n <= 0) counts!.delete(leased.version);
        else counts!.set(leased.version, n);
        void this.collect(key).catch(() => undefined);
      },
    };
  }

  /** Clear part bytes of a leased version. */
  async readPart(
    key: ViewKey,
    sha256: string,
    expectedBytes?: number,
  ): Promise<Uint8Array> {
    const bytes = await this.files.read(`${dir(key)}/parts/${sha256}`);
    if (!bytes) throw new Error("imported part is missing");
    if (!matchesPart(bytes, sha256, expectedBytes)) {
      throw new Error("corrupt imported part: size or SHA-256 mismatch");
    }
    return bytes;
  }

  /** Remove versions that are neither current nor leased, and unreferenced parts. */
  private collect(key: ViewKey): Promise<void> {
    return this.exclusive(key, () => this.collectLocked(key));
  }

  /** The caller holds the stream's lock; keep-sets are read here, under it. */
  private async collectLocked(key: ViewKey): Promise<void> {
    const id = viewKeyId(key);
    const base = dir(key);
    const current = this.current.get(id);
    const counts = this.leases.get(id);
    const retained =
      this.retained.get(id) ?? new Map<number, ImportedVersion>();
    for (const version of [...retained.keys()]) {
      if ((counts?.get(version) ?? 0) === 0) retained.delete(version);
    }
    const keep = new Set<number>(retained.keys());
    if (current) keep.add(current.version);
    const complete = this.complete.get(id);
    if (complete) keep.add(complete.version);
    const referenced = new Set<string>();
    for (const version of keep) {
      const imported =
        version === current?.version
          ? current
          : version === complete?.version
            ? complete
            : retained.get(version)!;
      for (const part of imported.head.parts) referenced.add(part.hash);
    }
    for (const path of await this.files.list(`${base}/heads`)) {
      const name = path.slice(path.lastIndexOf("/") + 1);
      const version = Number(name.replace(/\.json$/, ""));
      if (!keep.has(version)) await this.files.remove(path);
    }
    for (const path of await this.files.list(`${base}/parts`)) {
      const name = path.slice(path.lastIndexOf("/") + 1);
      if (!referenced.has(name)) await this.files.remove(path);
    }
  }
}

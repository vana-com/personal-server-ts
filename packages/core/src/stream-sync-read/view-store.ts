/**
 * Imported stream views (§2.9): per `(connector, ns, stream)`, the clear
 * head of the last imported live version and its verified clear parts.
 *
 * A new version replaces the current one atomically: its head and any new
 * parts are written first, then the `current` pointer. Reads lease the
 * versions they read (§2.9 pinned joins), so an import never removes a
 * version under a running read; a version is retired once it is neither
 * current nor leased. A request that names a retired version is stale.
 *
 * Parts are stored by their SHA-256, shared between versions of a stream,
 * so an import fetches only the parts it does not hold yet.
 */

import { sha256 as hashPart } from "@noble/hashes/sha2";
import {
  decodeHead,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { ConnectorRevisions } from "./connector-revisions.js";
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
}

/** What an import may do while it holds the stream's lock. */
export interface ImportTransaction {
  /**
   * Whether an intact copy of the part is stored. A stored copy that does not
   * match its hash (or `expectedBytes`) is removed and reported as missing.
   */
  hasPart(sha256: string, expectedBytes?: number): Promise<boolean>;
  putPart(sha256: string, clear: Uint8Array): Promise<void>;
  /** Make `version` current. Every part of `head` must be stored first. */
  commit(
    version: number,
    dataHash: string,
    headBytes: Uint8Array,
    head: Head,
  ): Promise<void>;
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
  /**
   * Per connector and stream: how many imports changed a current version of
   * it, whatever the namespace. A read records the revisions of the streams it
   * touches and compares them when it has paired a base with a plan. Only
   * these stream-scoped counts serve that basis: an import of a stream the
   * read does not touch never restarts it.
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

  private constructor(
    private readonly files: StreamSyncReadFiles,
    private readonly revisions: ConnectorRevisions,
  ) {}

  static async open(
    files: StreamSyncReadFiles,
    revisions: ConnectorRevisions = new ConnectorRevisions(),
  ): Promise<ViewStore> {
    const store = new ViewStore(files, revisions);
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
      const headBytes = await files.read(
        `${dir(key)}/heads/${pointer.version}.json`,
      );
      if (!headBytes) {
        await files.remove(path);
        continue;
      }
      const decoded = decodeHead(headBytes);
      if (decoded.kind !== "ok") continue;
      // A restore can bring back a pointer without all its parts. Drop the
      // pointer so the stream imports again; surviving parts stay reusable.
      let complete = true;
      for (const part of decoded.head.parts) {
        if (!(await store.partExists(key, part.hash))) {
          complete = false;
          break;
        }
      }
      if (!complete) {
        await files.remove(path);
        continue;
      }
      const id = viewKeyId(key);
      store.keys.set(id, key);
      store.current.set(id, {
        version: pointer.version,
        dataHash: pointer.dataHash,
        head: decoded.head,
      });
      // Versions left behind by a crash between pointer write and cleanup.
      await store.collect(key);
    }
    return store;
  }

  /** The import revision of one stream of one connector (all namespaces). */
  revision(connector: string, stream: string): number {
    return this.importRevisions.get(`${connector}\n${stream}`) ?? 0;
  }

  get(key: ViewKey): ImportedVersion | null {
    return this.current.get(viewKeyId(key)) ?? null;
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
        commit: (version, dataHash, headBytes, head) =>
          this.commit(key, version, dataHash, headBytes, head),
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

  /** Make `version` current. Every part of `head` must be stored first. */
  private async commit(
    key: ViewKey,
    version: number,
    dataHash: string,
    headBytes: Uint8Array,
    head: Head,
  ): Promise<void> {
    const base = dir(key);
    await this.files.write(`${base}/heads/${version}.json`, headBytes);
    const pointer: CurrentFile = { version, dataHash };
    await this.files.write(
      `${base}/current.json`,
      encoder.encode(JSON.stringify(pointer)),
    );
    const id = viewKeyId(key);
    const previous = this.current.get(id);
    this.keys.set(id, key);
    this.current.set(id, { version, dataHash, head });
    const touched = `${key.connector}\n${key.stream}`;
    this.importRevisions.set(
      touched,
      (this.importRevisions.get(touched) ?? 0) + 1,
    );
    this.revisions.bump(key.connector);
    if (previous && previous.version !== version) {
      let retained = this.retained.get(id);
      if (!retained) this.retained.set(id, (retained = new Map()));
      retained.set(previous.version, previous);
    }
    await this.collectLocked(key);
  }

  /**
   * Lease the current version, or `at` when given. `null` when there is no
   * such version: nothing imported, or `at` was retired.
   */
  lease(key: ViewKey, at?: number): ViewLease | null {
    const id = viewKeyId(key);
    const current = this.current.get(id);
    let version: ImportedVersion | undefined;
    if (at === undefined || current?.version === at) version = current;
    else version = this.retained.get(id)?.get(at);
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
    const referenced = new Set<string>();
    for (const version of keep) {
      const imported =
        version === current?.version ? current : retained.get(version)!;
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

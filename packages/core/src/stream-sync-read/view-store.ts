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
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
  /** id → version → lease count. */
  private readonly leases = new Map<string, Map<number, number>>();
  /** id → versions on disk that are not current. */
  private readonly retained = new Map<string, Map<number, ImportedVersion>>();
  private readonly keys = new Map<string, ViewKey>();
  /** id → parts an import is writing, kept until it commits or gives up. */
  private readonly staged = new Map<string, Set<string>>();

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
      const headBytes = await files.read(
        `${dir(key)}/heads/${pointer.version}.json`,
      );
      if (!headBytes) continue;
      const decoded = decodeHead(headBytes);
      if (decoded.kind !== "ok") continue;
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

  get(key: ViewKey): ImportedVersion | null {
    return this.current.get(viewKeyId(key)) ?? null;
  }

  views(): { key: ViewKey; version: ImportedVersion }[] {
    return [...this.current].map(([id, version]) => ({
      key: this.keys.get(id)!,
      version,
    }));
  }

  async hasPart(key: ViewKey, sha256: string): Promise<boolean> {
    return (await this.files.read(`${dir(key)}/parts/${sha256}`)) !== null;
  }

  /** Keep the parts of `head` while an import writes them. */
  stage(key: ViewKey, head: Head): () => void {
    const id = viewKeyId(key);
    const hashes = new Set(head.parts.map((p) => p.hash));
    this.staged.set(id, hashes);
    return () => {
      if (this.staged.get(id) === hashes) this.staged.delete(id);
    };
  }

  async putPart(
    key: ViewKey,
    sha256: string,
    clear: Uint8Array,
  ): Promise<void> {
    await this.files.write(`${dir(key)}/parts/${sha256}`, clear);
  }

  /** Make `version` current. Every part of `head` must be stored first. */
  async commit(
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
    if (previous && previous.version !== version) {
      let retained = this.retained.get(id);
      if (!retained) this.retained.set(id, (retained = new Map()));
      retained.set(previous.version, previous);
    }
    await this.collect(key);
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
  async readPart(key: ViewKey, sha256: string): Promise<Uint8Array> {
    const bytes = await this.files.read(`${dir(key)}/parts/${sha256}`);
    if (!bytes) throw new Error("imported part is missing");
    return bytes;
  }

  /** Remove versions that are neither current nor leased, and unreferenced parts. */
  private async collect(key: ViewKey): Promise<void> {
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
    const referenced = new Set<string>(this.staged.get(id) ?? []);
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

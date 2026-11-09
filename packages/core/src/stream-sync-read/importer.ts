/**
 * §2.9 import: every live, verified stream head in the mirror becomes the
 * imported view of its `(connector, ns, stream)`, replaced atomically.
 *
 * The local outbox plays no part here: a pending or permanently failed
 * entry never blocks import (its rows are a read-time overlay).
 *
 * Problems are kept per stream and shown in status. A blob that is not in
 * storage yet is retried on the next pass; every other problem is retried
 * when the registry row changes.
 */

import { deleteMetadataHash } from "../stream-sync/delete-metadata.js";

import {
  canonicalBytes32,
  classifyControl,
  classifyStreamRow,
  parseScope,
  checkPartBytes,
  decodePart,
  headBlobName,
  partBlobName,
  streamScope,
  verifyHead,
  type ControlHashes,
  type Head,
  type LastComplete,
  type ControlState,
  type StreamRow,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  toControlRead,
  type MirrorRow,
  type RegistryMirror,
} from "./mirror.js";
import type {
  StreamSyncBlobReader,
  StreamSyncImportedCoverage,
  StreamSyncReadKeys,
  StreamSyncReadLogger,
} from "./ports.js";
import {
  isUsableViewKey,
  viewKeyId,
  type LastCompleteHead,
  type ViewKey,
  type ViewStore,
} from "./view-store.js";

export type ImportProblem =
  /** The head or the control row was written with another owner key. */
  | "key_mismatch"
  /** A blob the head names is not in storage (yet). Retried each pass. */
  | "blob_missing"
  /** The head is of a format this server does not read. */
  | "unsupported_format"
  /** A blob failed decryption or verification. */
  | "corrupt"
  /** The name cannot be stored locally. */
  | "invalid_name"
  /** Storage or another transient failure. Retried each pass. */
  | "transient";

export interface ImportIssue {
  readonly connector: string;
  readonly ns: string;
  /** `null` for a problem of the whole connection (its control row). */
  readonly stream: string | null;
  readonly problem: ImportProblem;
  /** Registry version the problem is about. */
  readonly version: number;
  readonly detail?: string;
}

const RETRIED: ReadonlySet<ImportProblem> = new Set([
  "blob_missing",
  "transient",
]);

class Problem extends Error {
  constructor(
    readonly problem: ImportProblem,
    detail: string,
  ) {
    super(detail);
  }
}

export class StreamSyncImporter {
  private readonly issues = new Map<string, ImportIssue>();
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly options: {
      readonly mirror: RegistryMirror;
      readonly views: ViewStore;
      readonly blobs: StreamSyncBlobReader;
      readonly keys: StreamSyncReadKeys;
      readonly controlHashes: ControlHashes;
      readonly logger: StreamSyncReadLogger;
      /**
       * Called after a durable commit with what is now installed. Set only
       * when the read files are durable. A failure is logged and retried at
       * the next commit or start: it never fails the import.
       */
      readonly acknowledge?: (
        coverage: StreamSyncImportedCoverage,
      ) => Promise<void>;
    },
  ) {}

  /** Report one durable current view; never throws. */
  async acknowledge(
    key: ViewKey,
    installed: { version: number; dataHash: string; generation: number },
  ): Promise<void> {
    if (!this.options.acknowledge) return;
    try {
      await this.options.acknowledge({
        connector: key.connector,
        ns: key.ns,
        stream: key.stream,
        generation: installed.generation,
        registryVersion: installed.version,
        dataHash: canonicalBytes32(installed.dataHash),
      });
    } catch (error) {
      this.options.logger.warn(
        { connector: key.connector, stream: key.stream },
        `stream-sync acknowledgment failed: ${(error as Error).message}`,
      );
    }
  }

  controlState(row: MirrorRow | undefined): ControlState {
    return classifyControl(toControlRead(row), this.options.controlHashes);
  }

  /** Absent, present or tombstoned, by the rule the writer uses. */
  /** Versions read and found not live (another generation), by stream. */
  private readonly notLive = new Map<string, number>();

  /**
   * The newest registry version of the stream this device has read: imported,
   * or read and found not live. A row above it is a head not yet read.
   */
  latestReadVersion(key: ViewKey): number {
    return Math.max(
      this.options.views.get(key)?.version ?? 0,
      this.notLive.get(viewKeyId(key)) ?? 0,
    );
  }

  streamRowKind(row: MirrorRow): StreamRow {
    if (
      row.scope &&
      row.metadataHash.toLowerCase() ===
        deleteMetadataHash(row.scope, row.version)
    )
      return "tombstoned";
    const parsed = row.scope ? parseScope(row.scope) : null;
    const imported =
      parsed?.kind === "stream"
        ? this.options.views.get({
            connector: parsed.connector,
            ns: parsed.ns,
            stream: parsed.stream,
          })
        : null;
    if (
      imported?.version === row.version &&
      imported.head.lastDeleteVersion === row.version &&
      imported.head.recordCount === 0
    )
      return "tombstoned";
    return classifyStreamRow(toControlRead(row), this.options.controlHashes);
  }

  /**
   * The imported view of a stream, unless it is at or below the stream's
   * deletion floor: a later live row replaced the tombstone row, but the view
   * still holds records the owner deleted. Every read of an imported view goes
   * through here, whether or not the mirror still has a row for the stream.
   */
  servableView(key: ViewKey, completeOnly = false) {
    const imported = completeOnly
      ? this.options.views.getComplete(key)
      : this.options.views.get(key);
    const scope = streamScope(key.connector, key.ns, key.stream);
    return imported &&
      imported.version > this.options.mirror.deletionFloor(scope)
      ? imported
      : null;
  }

  listIssues(): ImportIssue[] {
    return [...this.issues.values()];
  }

  /** Connectors with a problem the next pass retries. */
  retryConnectors(): string[] {
    const out = new Set<string>();
    for (const issue of this.issues.values()) {
      if (RETRIED.has(issue.problem)) out.add(issue.connector);
    }
    return [...out];
  }

  /** Import the connectors, one pass at a time. */
  run(connectors: readonly string[]): Promise<void> {
    const pass = this.queue.then(async () => {
      for (const connector of connectors) {
        await this.importConnector(connector);
      }
    });
    this.queue = pass.catch(() => undefined);
    return pass;
  }

  private async importConnector(connector: string): Promise<void> {
    const rows = this.options.mirror.rowsFor(connector);
    const namespaces = new Set([
      ...rows.controls.keys(),
      ...rows.streams.keys(),
    ]);
    for (const ns of namespaces) {
      const control = this.controlState(rows.controls.get(ns));
      const connectionId = issueId(connector, ns, null);
      if (control.kind === "foreign") {
        this.issues.set(connectionId, {
          connector,
          ns,
          stream: null,
          problem: "key_mismatch",
          version: control.version,
        });
        continue;
      }
      this.issues.delete(connectionId);
      if (control.kind !== "active" && control.kind !== "absent") continue;
      for (const [stream, row] of rows.streams.get(ns) ?? []) {
        const key: ViewKey = { connector, ns, stream };
        const id = issueId(connector, ns, stream);
        if (this.streamRowKind(row) === "tombstoned") {
          this.issues.delete(id);
          continue;
        }
        const imported = this.servableView(key);
        if (
          imported &&
          imported.version >= row.version &&
          !this.missesLastComplete(key, imported.head, imported.version)
        ) {
          this.issues.delete(id);
          continue;
        }
        const previous = this.issues.get(id);
        if (
          previous &&
          previous.version === row.version &&
          !RETRIED.has(previous.problem)
        ) {
          continue;
        }
        try {
          await this.importHead(
            key,
            row,
            control.kind === "active" ? control.generation : null,
          );
          this.issues.delete(id);
        } catch (error) {
          const problem =
            error instanceof Problem ? error.problem : ("transient" as const);
          const detail = (error as Error).message;
          this.issues.set(id, {
            connector,
            ns,
            stream,
            problem,
            version: row.version,
            detail,
          });
          this.options.logger.warn(
            { connector, stream, problem, version: row.version },
            "stream-sync import did not complete",
          );
        }
      }
    }
  }

  private async importHead(
    key: ViewKey,
    row: MirrorRow,
    generation: number | null,
  ): Promise<void> {
    if (!isUsableViewKey(key)) {
      throw new Problem("invalid_name", "name is not usable as a path");
    }
    const { blobs, keys, views } = this.options;
    const scope = streamScope(key.connector, key.ns, key.stream);
    const cipher = await blobs.get(`${scope}/${headBlobName(row.dataHash)}`);
    if (!cipher) throw new Problem("blob_missing", "head blob not found");
    const clear = await decrypt(keys, scope, cipher);
    const verified = await verifyHead(keys.hashes.keccak256, clear, {
      dataHash: row.dataHash,
      connector: key.connector,
      ns: key.ns,
      stream: key.stream,
      keyCheck: keys.keyCheck,
    });
    switch (verified.kind) {
      case "ok":
        break;
      case "key_mismatch":
        throw new Problem("key_mismatch", "head was written with another key");
      case "unsupported_format":
        throw new Problem("unsupported_format", "unsupported head format");
      default:
        throw new Problem("corrupt", `head ${verified.kind}`);
    }
    const head = verified.head;
    // A head of another generation is not live (§2.4); nothing to import.
    const deleted =
      head.lastDeleteVersion === row.version && head.recordCount === 0;
    if ((head.lastDeleteVersion ?? 0) > 0)
      await this.options.mirror.recordDelete(scope, head.lastDeleteVersion!);
    if (!deleted && head.generation !== generation) {
      // Read and judged: this version is not live and never will be. Remember
      // it, so a reader does not take the row for a head still to import.
      this.notLive.set(viewKeyId(key), row.version);
      return;
    }
    let currentProblem: Problem | null = null;
    let fallbackProblem: Problem | null = null;
    await views.withImport(key, async (tx) => {
      const storeParts = async (h: Head) => {
        for (const part of h.parts) {
          if (await tx.hasPart(part.hash, part.bytes)) continue;
          const partCipher = await blobs.get(
            `${scope}/${partBlobName(h.generation, part.hash)}`,
          );
          if (!partCipher)
            throw new Problem("blob_missing", "part blob not found");
          const partClear = await decrypt(keys, scope, partCipher);
          try {
            if (h.format === 1) {
              await decodePart(
                keys.hashes.sha256,
                partClear,
                part,
                h.primaryKey,
              );
            } else {
              // Format 2: the part hash commits to the bytes. Frame structure
              // spans parts, so it is checked as the view is read.
              await checkPartBytes(keys.hashes.sha256, partClear, part);
            }
          } catch (error) {
            throw new Problem("corrupt", `part: ${(error as Error).message}`);
          }
          await tx.putPart(part.hash, partClear);
        }
      };
      const asProblem = (error: unknown) =>
        error instanceof Problem
          ? error
          : new Problem("transient", (error as Error).message);
      try {
        await storeParts(head);
      } catch (error) {
        currentProblem = asProblem(error);
      }
      // This device may never have seen the complete head an incomplete one
      // replaced. Fetch it by the name the head records, whether or not the
      // incomplete head's own parts are readable: the complete head stands on
      // its own. A failure here never blocks the current head; it is reported
      // and the next pass retries.
      let lastComplete: LastCompleteHead | undefined;
      if (
        this.missesLastComplete(key, head, row.version) &&
        head.lastComplete
      ) {
        try {
          const found = await this.fetchLastComplete(
            scope,
            key,
            head,
            head.lastComplete,
            row.version,
            generation,
          );
          if (found) {
            await storeParts(found.head);
            lastComplete = found;
          }
        } catch (error) {
          fallbackProblem = asProblem(error);
        }
      }
      if (!currentProblem) {
        await tx.commit(row.version, row.dataHash, clear, head, lastComplete);
      } else if (lastComplete) {
        // The current view is unreadable; keep the complete head it replaced.
        await tx.commitComplete(lastComplete);
      }
    });
    if (currentProblem) throw currentProblem;
    // The current pointer is durable: tell the overlay source what it holds.
    await this.acknowledge(key, {
      version: row.version,
      dataHash: row.dataHash,
      generation: head.generation,
    });
    if (fallbackProblem) throw fallbackProblem;
  }

  /**
   * An incomplete head at registry `version` names the complete head it
   * replaced; true while this store holds no complete head at or after it that
   * is still servable. A name at or after `version` is not a replaced head: it
   * can collide with this store's own versions, so it is never followed.
   */
  private missesLastComplete(
    key: ViewKey,
    head: Head,
    version: number,
  ): boolean {
    const last = head.lastComplete;
    if (head.complete || !last) return false;
    if (last.version >= version) return false;
    const scope = streamScope(key.connector, key.ns, key.stream);
    if (last.version <= this.options.mirror.deletionFloor(scope)) return false;
    return (this.options.views.getComplete(key)?.version ?? 0) < last.version;
  }

  /** The verified complete head `last` names, or `null` when it is not usable. */
  private async fetchLastComplete(
    scope: string,
    key: ViewKey,
    current: Head,
    last: LastComplete,
    currentVersion: number,
    generation: number | null,
  ): Promise<LastCompleteHead | null> {
    if (!(last.version > 0 && last.version < currentVersion)) return null;
    const { blobs, keys } = this.options;
    const cipher = await blobs.get(`${scope}/${headBlobName(last.dataHash)}`);
    if (!cipher)
      throw new Problem("blob_missing", "last complete head not found");
    const clear = await decrypt(keys, scope, cipher);
    const verified = await verifyHead(keys.hashes.keccak256, clear, {
      dataHash: last.dataHash,
      connector: key.connector,
      ns: key.ns,
      stream: key.stream,
      keyCheck: keys.keyCheck,
    });
    if (verified.kind !== "ok")
      throw new Problem("corrupt", `last complete head ${verified.kind}`);
    const head = verified.head;
    if (!head.complete || head.generation !== generation) return null;
    // The complete head must not predate the deletion the current head
    // records: its bytes may hold records that deletion removed, and the
    // version the current head claims for it is not authenticated.
    if ((head.lastDeleteVersion ?? 0) < (current.lastDeleteVersion ?? 0))
      return null;
    return {
      version: last.version,
      dataHash: last.dataHash,
      headBytes: clear,
      head,
    };
  }
}

function issueId(connector: string, ns: string, stream: string | null): string {
  return stream === null
    ? `${connector}\n${ns}`
    : viewKeyId({ connector, ns, stream });
}

async function decrypt(
  keys: StreamSyncReadKeys,
  scope: string,
  cipher: Uint8Array,
): Promise<Uint8Array> {
  try {
    return await keys.decrypt(scope, cipher);
  } catch (error) {
    // The control row says this key owns the connection, so a blob it
    // cannot open is damaged, not foreign (§2.3).
    throw new Problem("corrupt", `decrypt: ${(error as Error).message}`);
  }
}

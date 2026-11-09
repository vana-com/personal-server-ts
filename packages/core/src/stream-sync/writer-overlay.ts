/** Pinned intake logs from the existing, exclusively owned writer home. */
import {
  pkHash,
  sha256Hex,
  type JsonObject,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  StreamSyncOverlayRun,
  StreamSyncOverlaySnapshot,
  StreamSyncOverlaySnapshotSource,
} from "../stream-sync-read/ports.js";
import { streamSyncHashes } from "./crypto.js";
import {
  planStream,
  type PlanHead,
  type PlanRun,
  type StreamFloor,
} from "./publish-plan.js";
import type { StreamSyncFiles } from "./ports.js";
import { readSpool, type SpoolEntry } from "./spool.js";
import type { StreamSyncWriter } from "./writer.js";

export function createWriterOverlaySource(
  writer: StreamSyncWriter,
): StreamSyncOverlaySnapshotSource {
  return {
    observeDeletes: (observations) => writer.observeDeletes(observations),
    snapshot: (connector) => writer.snapshotOverlay(connector),
    planInputs: (listener) => writer.onPlanInputs(listener),
    connectors: () => writer.overlayConnectors(),
    acknowledge: (coverage) => writer.acknowledgeOverlay(coverage),
  };
}

/** Metadata copied under the writer lifecycle lock; bytes remain immutable while pinned. */
export interface WriterOverlayLog {
  readonly path: string;
  readonly bytes: number;
  readonly primaryKey: readonly string[];
}

/** What the plan of one stream reads, copied under the writer lifecycle lock. */
export interface WriterOverlayPlan {
  readonly floor: StreamFloor;
  readonly runs: readonly PlanRun[];
}

export function overlayPlanKey(ns: string, stream: string): string {
  return JSON.stringify([ns, stream]);
}

export function pinnedWriterSnapshot(
  files: StreamSyncFiles,
  runs: readonly StreamSyncOverlayRun[],
  logs: ReadonlyMap<
    StreamSyncOverlayRun,
    ReadonlyMap<string, WriterOverlayLog>
  >,
  unpin: () => void,
  plans: ReadonlyMap<string, WriterOverlayPlan> = new Map(),
): StreamSyncOverlaySnapshot {
  let released = false;
  return Object.freeze({
    runs,
    plan(
      ns: string,
      stream: string,
      head: PlanHead | null,
      ids: readonly string[],
    ) {
      const facts = plans.get(overlayPlanKey(ns, stream));
      if (!facts) return [];
      const wanted = new Set(ids);
      return planStream(
        head,
        facts.floor,
        facts.runs.filter((r) => wanted.has(r.runId)),
      );
    },
    async *lines(run: StreamSyncOverlayRun, stream: string) {
      const log = logs.get(run)?.get(stream);
      if (released || !log)
        throw new Error("stream is not in this live overlay snapshot");
      let bytes = 0;
      for await (const entry of readSpool(files, log.path)) {
        if (released) throw new Error("overlay snapshot was released");
        const { envelope } = entry;
        // This consumer needs an object, so it holds a whole body: the
        // spool chunks, their join, the decoded text and the parsed value are
        // alive together (about 3x the record). It is not a streaming path.
        const v = await parseBody(files, entry);
        const line: Line = { o: envelope.o, r: envelope.r, v };
        if (
          line.o !== run.observedAt ||
          line.r !== run.runId ||
          (await pkHash(streamSyncHashes.sha256, line.v, log.primaryKey)) !==
            envelope.k
        ) {
          throw new Error("overlay spool integrity mismatch");
        }
        bytes += entry.size;
        yield line;
      }
      if (bytes !== log.bytes)
        throw new Error("missing or truncated overlay spool log");
    },
    release() {
      if (released) return;
      released = true;
      unpin();
    },
  });
}

/**
 * The body the entry's envelope describes. The envelope names the body's
 * length (`n`) and SHA-256 (`h`); a body that differs, whether the file was
 * damaged or replaced, fails the read before any record is built from it.
 */
async function parseBody(
  files: StreamSyncFiles,
  entry: SpoolEntry,
): Promise<JsonObject> {
  let bytes: Uint8Array;
  if (entry.body.kind === "inline") {
    bytes = new TextEncoder().encode(entry.body.text);
  } else {
    const chunks: Uint8Array[] = [];
    for await (const chunk of files.readChunks(entry.body.path)) {
      chunks.push(chunk);
    }
    bytes = await joinChunks(chunks);
  }
  const { envelope } = entry;
  if (
    bytes.length !== envelope.n ||
    (await sha256Hex(streamSyncHashes.sha256, bytes)) !== envelope.h
  ) {
    throw new Error("overlay spool integrity mismatch");
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as JsonObject;
}

async function joinChunks(chunks: readonly Uint8Array[]): Promise<Uint8Array> {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

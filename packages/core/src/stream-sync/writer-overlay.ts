/** Pinned intake logs from the existing, exclusively owned writer home. */
import {
  decodeLine,
  pkHash,
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
import { readSpool } from "./spool.js";
import type { StreamSyncWriter } from "./writer.js";

export function createWriterOverlaySource(
  writer: StreamSyncWriter,
): StreamSyncOverlaySnapshotSource {
  return {
    snapshot: (connector) => writer.snapshotOverlay(connector),
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
      for await (const raw of readSpool(files, log.path)) {
        if (released) throw new Error("overlay snapshot was released");
        const line = decodeLine(raw.text);
        if (
          line.o !== run.observedAt ||
          line.r !== run.runId ||
          (await pkHash(streamSyncHashes.sha256, line.v, log.primaryKey)) !==
            raw.pkHash
        ) {
          throw new Error("overlay spool integrity mismatch");
        }
        bytes += new TextEncoder().encode(raw.text).length + 1;
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

/**
 * The records of one stream view, part by part in pkHash order, with the
 * local overlay merged by the package rule (§2.6, §2.9).
 *
 * The base is the leased imported view, or nothing when the stream has no
 * imported head (an overlay-only view). Without overlay rows a read holds one
 * part at a time. Overlay winners are held in memory: they are the rows of
 * local runs the imported view does not cover yet.
 */

import {
  compareStamp,
  pkHash,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  StreamSyncOverlayRun,
  StreamSyncOverlaySnapshot,
  StreamSyncReadKeys,
} from "./ports.js";
import type { ViewLease, ViewStore } from "./view-store.js";

const decoder = new TextDecoder();

export interface OverlayWinners {
  /** pkHash → winning line. */
  readonly winners: Map<string, Line>;
  /** Overlay rows without one of the primary-key fields; not overlaid. */
  readonly skipped: number;
  /** Greatest `o` among the winners, or null. */
  readonly newestObservedAt: number | null;
}

export const NO_OVERLAY: OverlayWinners = {
  winners: new Map(),
  skipped: 0,
  newestObservedAt: null,
};

/**
 * Overlay winners of one stream: the lines of `runs` in the pinned
 * `snapshot`. The caller has already decided which runs may contribute.
 */
export async function overlayWinners(
  snapshot: StreamSyncOverlaySnapshot,
  keys: StreamSyncReadKeys,
  input: {
    readonly runs: readonly StreamSyncOverlayRun[];
    readonly stream: string;
    readonly primaryKey: readonly string[];
  },
): Promise<OverlayWinners> {
  const winners = new Map<string, Line>();
  let skipped = 0;
  let newest: number | null = null;
  for (const run of input.runs) {
    for await (const line of snapshot.lines(run, input.stream)) {
      let hash: string;
      try {
        hash = await pkHash(keys.hashes.sha256, line.v, input.primaryKey);
      } catch {
        skipped++;
        continue;
      }
      const current = winners.get(hash);
      // Equal stamps: the later line wins (§2.6).
      if (current && compareStamp(line, current) < 0) continue;
      winners.set(hash, line);
      if (newest === null || line.o > newest) newest = line.o;
    }
  }
  return { winners, skipped, newestObservedAt: newest };
}

async function* partLines(
  views: ViewStore,
  lease: ViewLease,
): AsyncGenerator<{ readonly text: string; readonly line: Line }> {
  for (const part of lease.version.head.parts) {
    const text = decoder.decode(
      await views.readPart(lease.key, part.hash, part.bytes),
    );
    let start = 0;
    while (start < text.length) {
      const end = text.indexOf("\n", start);
      if (end === -1) {
        throw new Error("corrupt imported part: missing final newline");
      }
      const lineText = text.slice(start, end);
      start = end + 1;
      // Verified at import (`decodePart`); parsed, not re-verified.
      yield { text: lineText, line: JSON.parse(lineText) as Line };
    }
  }
}

/**
 * Every record of the stream merged with `overlay`, in pkHash order. `base`
 * is the leased imported view, or null when the stream has none: then the
 * sorted overlay winners are the whole answer.
 */
export async function* viewLines(
  views: ViewStore,
  keys: StreamSyncReadKeys,
  base: ViewLease | null,
  overlay: OverlayWinners,
  primaryKey: readonly string[],
): AsyncGenerator<Line> {
  if (!base) {
    for (const hash of [...overlay.winners.keys()].sort()) {
      yield overlay.winners.get(hash)!;
    }
    return;
  }
  if (overlay.winners.size === 0) {
    for await (const { line } of partLines(views, base)) yield line;
    return;
  }
  const pending = [...overlay.winners.keys()].sort();
  let next = 0;
  for await (const { line } of partLines(views, base)) {
    const hash = await pkHash(keys.hashes.sha256, line.v, primaryKey);
    while (next < pending.length && pending[next]! < hash) {
      yield overlay.winners.get(pending[next++]!)!;
    }
    if (next < pending.length && pending[next] === hash) {
      const local = overlay.winners.get(pending[next++]!)!;
      // The overlay is fed after the base: it wins ties.
      yield compareStamp(local, line) >= 0 ? local : line;
      continue;
    }
    yield line;
  }
  while (next < pending.length) {
    yield overlay.winners.get(pending[next++]!)!;
  }
}

/**
 * The records of one leased stream view, part by part in pkHash order, with
 * the local outbox overlay merged by the package rule (§2.6, §2.9).
 *
 * Without overlay rows a read holds one part at a time. Overlay winners are
 * held in memory: they are the rows of local runs that have not committed.
 */

import {
  compareStamp,
  pkHash,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncOverlaySource, StreamSyncReadKeys } from "./ports.js";
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

/** Overlay winners of `(connector, ns, stream)`; rows of unattributed runs are not included. */
export async function overlayWinners(
  source: StreamSyncOverlaySource | undefined,
  keys: StreamSyncReadKeys,
  lease: ViewLease,
): Promise<OverlayWinners> {
  const winners = new Map<string, Line>();
  let skipped = 0;
  let newest: number | null = null;
  if (!source) return { winners, skipped, newestObservedAt: newest };
  const { connector, ns, stream } = lease.key;
  const primaryKey = lease.version.head.primaryKey;
  for (const entry of await source.entries(connector)) {
    if (entry.ns !== ns || !entry.streams.includes(stream)) continue;
    for await (const line of entry.lines(stream)) {
      let hash: string;
      try {
        hash = await pkHash(keys.hashes.sha256, line.v, primaryKey);
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

/** Every record of the leased view merged with `overlay`, in pkHash order. */
export async function* viewLines(
  views: ViewStore,
  keys: StreamSyncReadKeys,
  lease: ViewLease,
  overlay: OverlayWinners,
): AsyncGenerator<Line> {
  if (overlay.winners.size === 0) {
    for await (const { line } of partLines(views, lease)) yield line;
    return;
  }
  const primaryKey = lease.version.head.primaryKey;
  const pending = [...overlay.winners.keys()].sort();
  let next = 0;
  for await (const { line } of partLines(views, lease)) {
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

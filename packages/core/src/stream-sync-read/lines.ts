/**
 * The records of one leased stream view, part by part in pkHash order, with
 * the local outbox overlay merged by the package rule (§2.6, §2.9).
 *
 * Without overlay rows a read holds one part at a time. Overlay winners are
 * held in memory: they are the rows of local runs that have not committed.
 *
 * Accounting (`budget`, optional): a live part is charged as imported bytes
 * plus decoded text; overlay winners as entries and, in measured mode, their
 * serialized size. Nothing is refused for exceeding a budget (see budget.ts).
 */

import {
  compareStamp,
  pkHash,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  READ_BUDGET,
  retainedBytes,
  textCharge,
  type ReadBudget,
} from "./budget.js";
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
  /** Return the budget this overlay charged. Idempotent. */
  readonly release: () => void;
}

/** Overlay winners of `(connector, ns, stream)`; rows of unattributed runs are not included. */
export async function overlayWinners(
  source: StreamSyncOverlaySource | undefined,
  keys: StreamSyncReadKeys,
  lease: ViewLease,
  budget?: ReadBudget,
): Promise<OverlayWinners> {
  const winners = new Map<string, Line>();
  // Measured mode only: the serialized charge of each winner, to subtract on replacement.
  const charges = budget ? new Map<string, number>() : null;
  let charged = 0;
  let skipped = 0;
  let newest: number | null = null;
  let released = false;
  const release = () => {
    if (released || !budget) return;
    released = true;
    budget.release("overlayWinners", winners.size);
    budget.release("overlayPayload", charged);
  };
  if (!source) {
    return { winners, skipped, newestObservedAt: newest, release };
  }
  const { connector, ns, stream } = lease.key;
  const primaryKey = lease.version.head.primaryKey;
  try {
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
        if (budget && charges) {
          const size = textCharge(JSON.stringify(line));
          const before = charges.get(hash);
          if (before === undefined) budget.acquire("overlayWinners", 1);
          else budget.release("overlayPayload", before);
          budget.acquire("overlayPayload", size);
          charges.set(hash, size);
          charged += size - (before ?? 0);
        }
        if (newest === null || line.o > newest) newest = line.o;
      }
    }
  } catch (error) {
    release();
    throw error;
  }
  return { winners, skipped, newestObservedAt: newest, release };
}

async function* partLines(
  views: ViewStore,
  lease: ViewLease,
  budget?: ReadBudget,
): AsyncGenerator<{ readonly text: string; readonly line: Line }> {
  for (const part of lease.version.head.parts) {
    const bytes = await views.readPart(lease.key, part.hash, part.bytes);
    const importedCharge = budget ? retainedBytes(bytes) : 0;
    budget?.acquire("importedPart", importedCharge);
    const text = decoder.decode(bytes);
    const textBytes = budget ? textCharge(text) : 0;
    budget?.acquire("decodedPart", textBytes);
    try {
      let start = 0;
      while (start < text.length) {
        const end = text.indexOf("\n", start);
        if (end === -1) {
          throw new Error("corrupt imported part: missing final newline");
        }
        const lineText = text.slice(start, end);
        start = end + 1;
        if (budget && textCharge(lineText) > READ_BUDGET.ordinaryRecordBytes) {
          budget.noteOversizeRecord();
        }
        // Verified at import (`decodePart`); parsed, not re-verified.
        yield { text: lineText, line: JSON.parse(lineText) as Line };
      }
    } finally {
      budget?.release("decodedPart", textBytes);
      budget?.release("importedPart", importedCharge);
    }
  }
}

/** Every record of the leased view merged with `overlay`, in pkHash order. */
export async function* viewLines(
  views: ViewStore,
  keys: StreamSyncReadKeys,
  lease: ViewLease,
  overlay: OverlayWinners,
  budget?: ReadBudget,
): AsyncGenerator<Line> {
  if (overlay.winners.size === 0) {
    for await (const { line } of partLines(views, lease, budget)) yield line;
    return;
  }
  const primaryKey = lease.version.head.primaryKey;
  const pending = [...overlay.winners.keys()].sort();
  budget?.acquire("overlayPendingKeys", pending.length);
  let next = 0;
  try {
    for await (const { line } of partLines(views, lease, budget)) {
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
  } finally {
    budget?.release("overlayPendingKeys", pending.length);
  }
}

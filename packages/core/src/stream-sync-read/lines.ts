/**
 * The records of one stream view, part by part in pkHash order, with the
 * local overlay merged by the package rule (§2.6, §2.9).
 *
 * The base is the leased imported view, or nothing when the stream has no
 * imported head (an overlay-only view). Without overlay rows a read holds one
 * part at a time. Overlay winners are held in memory, whole and parsed: they
 * are the rows of local runs the imported view does not cover yet, so an
 * overlay record costs a multiple of its size.
 */

import {
  canonicalJsonChunks,
  compareStamp,
  framesOfParts,
  linesOfParts,
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
  keys: StreamSyncReadKeys,
  lease: ViewLease,
): AsyncGenerator<{ readonly line: Line }> {
  const head = lease.version.head;
  const read = (part: { hash: string; bytes: number }) =>
    views.readPart(lease.key, part.hash, part.bytes);
  if (head.format === 2) {
    // The store verified each part; frame structure is checked as it is read.
    for await (const line of linesOfParts(keys.hashes.sha256, head, read, {
      verify: false,
    })) {
      yield { line };
    }
    return;
  }
  for (const part of head.parts) {
    const text = decoder.decode(await read(part));
    let start = 0;
    while (start < text.length) {
      const end = text.indexOf("\n", start);
      if (end === -1) {
        throw new Error("corrupt imported part: missing final newline");
      }
      const lineText = text.slice(start, end);
      start = end + 1;
      // Verified at import (`decodePart`); parsed, not re-verified.
      yield { line: JSON.parse(lineText) as Line };
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
    for await (const { line } of partLines(views, keys, base)) yield line;
    return;
  }
  const pending = [...overlay.winners.keys()].sort();
  let next = 0;
  for await (const { line } of partLines(views, keys, base)) {
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

/** One record of a view as its stamp and key plus the body in pieces. */
export interface ViewBody {
  /** pkHash of the record's primary key. */
  readonly k: string;
  readonly o: number;
  readonly r: string;
  /** Canonical JSON of the record, one bounded piece at a time. */
  body(): AsyncGenerator<Uint8Array>;
}

const encoder = new TextEncoder();

async function* chunksOfValue(value: unknown): AsyncGenerator<Uint8Array> {
  for (const text of canonicalJsonChunks(value)) yield encoder.encode(text);
}

async function* partBodies(
  views: ViewStore,
  keys: StreamSyncReadKeys,
  lease: ViewLease,
  primaryKey: readonly string[],
): AsyncGenerator<ViewBody> {
  const head = lease.version.head;
  const read = (part: { hash: string; bytes: number }) =>
    views.readPart(lease.key, part.hash, part.bytes);
  if (head.format === 2) {
    for await (const frame of framesOfParts(
      keys.hashes.sha256,
      head.parts,
      (part) => read(part),
      { verify: false },
    )) {
      yield {
        k: frame.envelope.k,
        o: frame.envelope.o,
        r: frame.envelope.r,
        body: () => frame.body(),
      };
    }
    return;
  }
  for await (const { line } of partLines(views, keys, lease)) {
    yield {
      k: await pkHash(keys.hashes.sha256, line.v, primaryKey),
      o: line.o,
      r: line.r,
      body: () => chunksOfValue(line.v),
    };
  }
}

/**
 * The same records and order as `viewLines`, but each body stays unparsed:
 * the caller reads it in pieces and forwards or hashes it. Merge decisions use
 * the key and stamp only. A base body costs one part in memory at a time; an
 * overlay body is already held as an object.
 */
export async function* viewBodies(
  views: ViewStore,
  keys: StreamSyncReadKeys,
  base: ViewLease | null,
  overlay: OverlayWinners,
  primaryKey: readonly string[],
): AsyncGenerator<ViewBody> {
  const fromLine = (hash: string, line: Line): ViewBody => ({
    k: hash,
    o: line.o,
    r: line.r,
    body: () => chunksOfValue(line.v),
  });
  const pending = [...overlay.winners.keys()].sort();
  let next = 0;
  if (base) {
    for await (const body of partBodies(views, keys, base, primaryKey)) {
      while (next < pending.length && pending[next]! < body.k) {
        const hash = pending[next++]!;
        yield fromLine(hash, overlay.winners.get(hash)!);
      }
      if (next < pending.length && pending[next] === body.k) {
        const hash = pending[next++]!;
        const local = overlay.winners.get(hash)!;
        // The overlay is fed after the base: it wins ties.
        yield compareStamp(local, body) >= 0 ? fromLine(hash, local) : body;
        continue;
      }
      yield body;
    }
  }
  while (next < pending.length) {
    const hash = pending[next++]!;
    yield fromLine(hash, overlay.winners.get(hash)!);
  }
}

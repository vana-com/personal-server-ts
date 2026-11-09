/**
 * Synthetic stream-sync scenarios for the bounded-memory oracle (lane P3).
 *
 * Pure and browser-safe: no Node imports, so the same generator drives the
 * Node oracle and the on-device harness. Every record is generated from its
 * sequence number, so the expected output is computed without holding the
 * records or the expected winners in memory: winners are a closed form of
 * (kind, records, seq), and the expected output is an order-independent
 * digest (XOR of per-line SHA-256) plus a count.
 */

import { sha256 } from "@noble/hashes/sha2";

export const MiB = 1024 * 1024;
export const T0 = 1_700_000_000_000;
export const RUN_ID = "run-1";
export const CONNECTOR = "p3-synthetic";
export const STREAM = "s";

export type ScenarioKind =
  /** Unique keys, fixed 1 KiB bodies. */
  | "uniform"
  /** Unique keys, heavy-tailed sizes: 120 B, 10 KiB and 512 KiB bodies. */
  | "skewed"
  /** 1000 keys written over and over; only the last version of each wins. */
  | "repeated"
  /** Unique keys, ~70-byte lines: the entry-count stress. */
  | "tiny"
  /** One record just under the 8 MiB line limit, one just over (excluded). */
  | "big8";

export const REPEATED_KEYS = 1000;
export const BIG8_LIMIT_LINE_BYTES = 8 * MiB;

export interface ScenarioSpec {
  readonly kind: ScenarioKind;
  /** Records appended. `big8` uses the first two as the oversized pair. */
  readonly records: number;
}

export interface SyntheticRecord {
  readonly body: string;
  readonly id: string;
  readonly seq: number;
}

/**
 * Bodies are slices of a fixed, incompressible block (base64 of a SHA-256
 * chain), so encoded parts are not near-zero after compression. A constant
 * body would hide any path that holds whole parts in memory.
 */
const BLOCK_BYTES = 64 * 1024;
const BLOCK = (() => {
  const out: string[] = [];
  let h = new TextEncoder().encode("p3-synthetic-block");
  let total = 0;
  while (total < BLOCK_BYTES) {
    h = sha256(h);
    const chunk = btoa(String.fromCharCode(...h));
    out.push(chunk);
    total += chunk.length;
  }
  return out.join("").slice(0, BLOCK_BYTES);
})();

/** Deterministic body of `length` characters for sequence number `seq`. */
function filled(length: number, seq: number): string {
  const pieces: string[] = [];
  let offset = (seq * 7919) % BLOCK_BYTES;
  let remaining = length;
  while (remaining > 0) {
    const piece = BLOCK.slice(
      offset,
      offset + Math.min(remaining, BLOCK_BYTES - offset),
    );
    pieces.push(piece);
    remaining -= piece.length;
    offset = 0;
  }
  return pieces.join("");
}

/** The record with sequence number `seq`. Keys are sorted, as canonical JSON. */
export function recordAt(spec: ScenarioSpec, seq: number): SyntheticRecord {
  switch (spec.kind) {
    case "uniform":
      return { body: filled(1024, seq), id: `u${seq}`, seq };
    case "skewed": {
      const size =
        seq % 100 === 0 ? 512 * 1024 : seq % 11 === 0 ? 10 * 1024 : 120;
      return { body: filled(size, seq), id: `k${seq}`, seq };
    }
    case "repeated":
      return {
        body: filled(1024, seq),
        id: `r${seq % REPEATED_KEYS}`,
        seq,
      };
    case "tiny":
      return { body: "", id: `t${seq}`, seq };
    case "big8":
      if (seq === 0) {
        // Line = 2 + body + ~75 bytes of envelope, so this is 8 MiB - 1 KiB.
        return {
          body: filled(BIG8_LIMIT_LINE_BYTES - 1024 - 80, seq),
          id: "big-0",
          seq,
        };
      }
      if (seq === 1) return { body: filled(9 * MiB, seq), id: "big-1", seq };
      return { body: filled(1024, seq), id: `n${seq}`, seq };
  }
}

/** Whether `seq` is an output line of the stream (not excluded, not superseded). */
export function isWinner(spec: ScenarioSpec, seq: number): boolean {
  if (spec.kind === "repeated") {
    return seq >= spec.records - REPEATED_KEYS;
  }
  if (spec.kind === "big8") return seq !== 1;
  return true;
}

/** How many lines the output holds. */
export function expectedCount(spec: ScenarioSpec): number {
  if (spec.kind === "repeated") return Math.min(REPEATED_KEYS, spec.records);
  if (spec.kind === "big8") return spec.records - 1;
  return spec.records;
}

/** Canonical output line of a winner, without the terminator. */
export function outputLine(o: number, r: string, v: unknown): string {
  return `{"o":${o},"r":${JSON.stringify(r)},"v":${JSON.stringify(v)}}`;
}

export function hexOf(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** XOR-accumulates per-line SHA-256 digests; order-independent. */
export class SetDigest {
  private readonly acc = new Uint8Array(32);
  count = 0;

  add(line: string): void {
    const h = sha256(new TextEncoder().encode(line));
    for (let i = 0; i < 32; i += 1) this.acc[i]! ^= h[i]!;
    this.count += 1;
  }

  hex(): string {
    return hexOf(this.acc);
  }
}

/** The expected digest and count of a scenario's output. */
export function expectedDigest(spec: ScenarioSpec): {
  digest: string;
  count: number;
} {
  const d = new SetDigest();
  for (let seq = 0; seq < spec.records; seq += 1) {
    if (!isWinner(spec, seq)) continue;
    d.add(outputLine(T0, RUN_ID, recordAt(spec, seq)));
  }
  return { digest: d.hex(), count: d.count };
}

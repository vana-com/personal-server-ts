/**
 * Byte budgets and live-memory accounting of the stream-sync read side.
 *
 * Step 1 is measurement only. A budget here is an observation threshold:
 * crossing it increments `exceedances` and changes nothing else. No read
 * refuses, truncates or reorders because of a budget. A later step adds a
 * typed failure per budget, and only where the protocol already has one.
 *
 * Accounting rules:
 * - A byte charge is the retained allocation, not the view. A `Uint8Array`
 *   charges `buffer.byteLength` (see {@link retainedBytes}).
 * - Decoded text is charged `2 × length` (conservative UTF-16 accounting).
 * - Counters are scalars in typed arrays. Updating them allocates nothing.
 * - `totalBytesPeak` is the peak of the sum of byte categories that are live
 *   at the same instant. It is not the sum of each category's own peak.
 * - Acquire on ownership, release when the owner lets go, including on
 *   error and cancel. Releasing more than was acquired throws.
 */

import {
  DEFAULT_PART_TARGET_BYTES,
  PART_LIMIT_BYTES,
  RECORD_LINE_LIMIT_BYTES,
  SHARD_COUNT,
} from "@opendatalabs/personal-server-ts-stream-sync";

const KiB = 1024;
const MiB = 1024 * KiB;

/**
 * Budgets, with the reason for each value. Values that come from the
 * protocol cite the constant. Values we chose are a starting point for
 * measurement, not proven limits; `exceedances` tells us where they are wrong.
 */
export const READ_BUDGET = {
  /** Read chunk. The adapter chunk size (`memory-files`) and the stream adapter's 64 KiB batch. */
  chunkBytes: 64 * KiB,
  /** Writer default per part (protocol `DEFAULT_PART_TARGET_BYTES`). Reader expects parts this size. */
  partTargetBytes: DEFAULT_PART_TARGET_BYTES,
  /** Protocol decode limit of one clear part (`PART_LIMIT_BYTES`). Hard ceiling of one live part. */
  partLimitBytes: PART_LIMIT_BYTES,
  /**
   * Ordinary record: one canonical line above this is "oversize". Chosen
   * well below the protocol publish cap (`RECORD_LINE_LIMIT_BYTES`) so that
   * one record fits a few chunks. Chosen, not measured. Steps 2 to 7 decide
   * the large-value path; step 1 only counts oversize lines.
   */
  ordinaryRecordBytes: 256 * KiB,
  /** Winning overlay rows held at once, in charged bytes. One decodable part's worth. */
  overlayPayloadBytes: PART_LIMIT_BYTES,
  /** Winning overlay rows held at once (distinct primary keys). */
  overlayWinnerEntries: 1024,
  /** Pending keys sorted for the overlay merge. Equal to the winner bound. */
  overlayPendingKeys: 1024,
  /** Projection spool flush threshold (the existing `SPOOL_FLUSH_BYTES`). */
  spoolFlushBytes: 4 * MiB,
  /** Spool text buffered before a flush, charged at 2 × characters. Bounded by flush + one record. */
  spoolBufferBytes: 2 * (4 * MiB + 256 * KiB),
  /** Spool bytes read for one shard. Not yet bounded by any step-1 rule; the full-shard gate is red. */
  shardPayloadBytes: 4 * MiB,
  /** Rows (parents and children) read for one shard. */
  shardRows: 4096,
  /** Rows of the non-window streams. No budget yet (step 4+): reported, never judged. */
  otherRows: Number.POSITIVE_INFINITY,
  /** Merge cursors, one per shard (protocol `SHARD_COUNT`). */
  mergeCursors: SHARD_COUNT,
  /** One spool chunk per merge cursor. */
  mergeChunkBytes: SHARD_COUNT * 64 * KiB,
  /** Output staged in the body stream: one chunk, plus the one record that may overrun it. */
  outputStagingBytes: 64 * KiB + 256 * KiB,
  /** Clear plus cipher bytes of one part during import (decrypt output and ciphertext). */
  importPartBytes: 2 * PART_LIMIT_BYTES,
  /** Array projector input: the existing `DEFAULT_ARRAY_BUDGET`, refused with `too_large` above it. */
  arrayProjectionBytes: 64 * MiB,
} as const;

/** Protocol publish cap of one canonical line. Not a read budget; recorded for the step-7 contract. */
export const PUBLISH_LINE_CAP_BYTES = RECORD_LINE_LIMIT_BYTES;

export const READ_CATEGORIES = [
  "importedPart",
  "decodedPart",
  "overlayPayload",
  "overlayWinners",
  "overlayPendingKeys",
  "spoolBuffer",
  "shardPayload",
  "shardRows",
  "otherRows",
  "mergeCursors",
  "mergeChunk",
  "outputStaging",
  "importPart",
] as const;

export type BudgetCategory = (typeof READ_CATEGORIES)[number];

const LIMIT: Readonly<Record<BudgetCategory, number>> = {
  importedPart: READ_BUDGET.partLimitBytes,
  decodedPart: 2 * READ_BUDGET.partLimitBytes,
  overlayPayload: READ_BUDGET.overlayPayloadBytes,
  overlayWinners: READ_BUDGET.overlayWinnerEntries,
  overlayPendingKeys: READ_BUDGET.overlayPendingKeys,
  spoolBuffer: READ_BUDGET.spoolBufferBytes,
  shardPayload: READ_BUDGET.shardPayloadBytes,
  shardRows: READ_BUDGET.shardRows,
  otherRows: READ_BUDGET.otherRows,
  mergeCursors: READ_BUDGET.mergeCursors,
  mergeChunk: READ_BUDGET.mergeChunkBytes,
  outputStaging: READ_BUDGET.outputStagingBytes,
  importPart: READ_BUDGET.importPartBytes,
};

/** Byte categories count toward `totalBytesPeak`; the others count entries or rows. */
const IS_BYTES: Readonly<Record<BudgetCategory, boolean>> = {
  importedPart: true,
  decodedPart: true,
  overlayPayload: true,
  overlayWinners: false,
  overlayPendingKeys: false,
  spoolBuffer: true,
  shardPayload: true,
  shardRows: false,
  otherRows: false,
  mergeCursors: false,
  mergeChunk: true,
  outputStaging: true,
  importPart: true,
};

const INDEX = Object.fromEntries(
  READ_CATEGORIES.map((c, i) => [c, i]),
) as Record<BudgetCategory, number>;
const N = READ_CATEGORIES.length;

/** The bytes a retained view keeps alive: its whole underlying buffer. */
export function retainedBytes(bytes: Uint8Array): number {
  return bytes.buffer.byteLength;
}

/** Conservative UTF-16 charge of decoded text. */
export function textCharge(text: string): number {
  return 2 * text.length;
}

export interface CategorySnapshot {
  readonly unit: "bytes" | "count";
  readonly budget: number;
  readonly current: number;
  readonly peak: number;
  /** Acquisitions (allocations) since creation. */
  readonly allocations: number;
  /** Sum of acquired amounts since creation. */
  readonly allocated: number;
  /** Acquisitions that left the category above its budget. */
  readonly exceedances: number;
}

export interface ReadBudgetSnapshot {
  readonly categories: Readonly<Record<BudgetCategory, CategorySnapshot>>;
  /** Live byte categories summed, now. Zero after release. */
  readonly totalBytesCurrent: number;
  /** Peak of that sum at one instant. */
  readonly totalBytesPeak: number;
  /** Oversize ordinary records (one canonical line above `ordinaryRecordBytes`). */
  readonly oversizeRecords: number;
}

/**
 * Live accounting of one read or one import. One instance per operation, so
 * a peak never mixes two operations.
 */
export class ReadBudget {
  private readonly current = new Float64Array(N);
  private readonly peak = new Float64Array(N);
  private readonly allocations = new Float64Array(N);
  private readonly allocated = new Float64Array(N);
  private readonly exceedances = new Float64Array(N);
  private totalBytes = 0;
  private totalBytesPeak = 0;
  private oversize = 0;

  acquire(category: BudgetCategory, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new Error(`budget amount must be finite and >= 0: ${category}`);
    }
    const i = INDEX[category];
    const next = this.current[i]! + amount;
    this.current[i] = next;
    if (next > this.peak[i]!) this.peak[i] = next;
    this.allocations[i]! += 1;
    this.allocated[i]! += amount;
    if (next > LIMIT[category]) this.exceedances[i]! += 1;
    if (IS_BYTES[category]) {
      this.totalBytes += amount;
      if (this.totalBytes > this.totalBytesPeak) {
        this.totalBytesPeak = this.totalBytes;
      }
    }
  }

  release(category: BudgetCategory, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new Error(`budget amount must be finite and >= 0: ${category}`);
    }
    const i = INDEX[category];
    const next = this.current[i]! - amount;
    if (next < 0) {
      throw new Error(`released more than acquired: ${category}`);
    }
    this.current[i] = next;
    if (IS_BYTES[category]) this.totalBytes -= amount;
  }

  /** Count one ordinary record above the limit. Counts only; nothing refuses it. */
  noteOversizeRecord(): void {
    this.oversize += 1;
  }

  snapshot(): ReadBudgetSnapshot {
    const categories = {} as Record<BudgetCategory, CategorySnapshot>;
    for (const category of READ_CATEGORIES) {
      const i = INDEX[category];
      categories[category] = {
        unit: IS_BYTES[category] ? "bytes" : "count",
        budget: LIMIT[category],
        current: this.current[i]!,
        peak: this.peak[i]!,
        allocations: this.allocations[i]!,
        allocated: this.allocated[i]!,
        exceedances: this.exceedances[i]!,
      };
    }
    return {
      categories,
      totalBytesCurrent: this.totalBytes,
      totalBytesPeak: this.totalBytesPeak,
      oversizeRecords: this.oversize,
    };
  }
}

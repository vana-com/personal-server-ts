/**
 * Read-side memory estimates and observation thresholds.
 *
 * Every number here is an ACCOUNTING ESTIMATE of what a read is known to
 * hold, charged by the code at its bookkeeping calls. It is not measured
 * memory. A reader that retains data the estimator never charges (for example
 * a list of parsed lines kept across a read) is invisible to these counters.
 * Real memory bounds need an independent high-water instrument (the shared
 * child-process helper, PS #565 `test/stream-sync-p1-bounded`).
 *
 * A threshold is an observation: crossing it increments `thresholdExceedances`
 * and changes nothing else. No read refuses, truncates or reorders because of
 * a threshold. A later step adds a typed failure per threshold, and only where
 * the protocol already has one.
 *
 * Charging rules:
 * - A byte charge is the retained allocation, not the view. A `Uint8Array`
 *   charges `buffer.byteLength` (see {@link retainedBytes}).
 * - Decoded text is charged `2 × length` (conservative UTF-16 accounting, see
 *   {@link textCharge}). This is a memory charge, not a size.
 * - Record size is canonical UTF-8 bytes (see {@link utf8Bytes}). That is the
 *   unit the protocol and `ordinaryRecordBytes` use.
 * - `estimatedBytesPeak` is the peak of the sum of byte categories that are
 *   live at the same instant. It is not the sum of each category's own peak.
 * - Acquire on ownership, release when the owner lets go, including on error
 *   and cancel. Releasing more than was acquired throws.
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
 * Observation thresholds, with the reason for each value. Values that come
 * from the protocol cite the constant. Values we chose are a starting point
 * for measurement, not proven limits; `thresholdExceedances` shows where they
 * are wrong. They are not refusal limits.
 */
export const READ_THRESHOLDS = {
  /** Read chunk. The adapter chunk size (`memory-files`) and the stream adapter's 64 KiB batch. */
  chunkBytes: 64 * KiB,
  /** Writer default per part (protocol `DEFAULT_PART_TARGET_BYTES`). Reader expects parts this size. */
  partTargetBytes: DEFAULT_PART_TARGET_BYTES,
  /** Protocol decode limit of one clear part (`PART_LIMIT_BYTES`). Hard ceiling of one live part. */
  partLimitBytes: PART_LIMIT_BYTES,
  /**
   * Ordinary record: one canonical line whose UTF-8 size is above this is
   * counted as oversize. Chosen, not measured, and NOT the protocol record
   * limit: legal records up to `RECORD_LINE_LIMIT_BYTES` (8 MiB) must still
   * read. Until this threshold agrees with that limit, it must not be enforced.
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
  /** Rows of the non-window streams. No threshold yet (step 4+): reported, never judged. */
  otherRows: Number.POSITIVE_INFINITY,
  /** Merge cursors, one per shard (protocol `SHARD_COUNT`). */
  mergeCursors: SHARD_COUNT,
  /** One spool chunk per merge cursor. */
  mergeChunkBytes: SHARD_COUNT * 64 * KiB,
  /** Output staged in the body stream: one chunk, plus the one record that may overrun it. */
  outputStagingBytes: 64 * KiB + 256 * KiB,
  /** Clear plus cipher bytes of one part during import (decrypt output and ciphertext). Omits framing overhead and decoded objects. */
  importPartBytes: 2 * PART_LIMIT_BYTES,
  /** Array projector input: the existing `DEFAULT_ARRAY_BUDGET`, refused with `too_large` above it. */
  arrayProjectionBytes: 64 * MiB,
} as const;

/** Protocol publish cap of one canonical line. Not a read threshold; recorded for the step-7 contract. */
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

export type EstimateCategory = (typeof READ_CATEGORIES)[number];

const THRESHOLD: Readonly<Record<EstimateCategory, number>> = {
  importedPart: READ_THRESHOLDS.partLimitBytes,
  decodedPart: 2 * READ_THRESHOLDS.partLimitBytes,
  overlayPayload: READ_THRESHOLDS.overlayPayloadBytes,
  overlayWinners: READ_THRESHOLDS.overlayWinnerEntries,
  overlayPendingKeys: READ_THRESHOLDS.overlayPendingKeys,
  spoolBuffer: READ_THRESHOLDS.spoolBufferBytes,
  shardPayload: READ_THRESHOLDS.shardPayloadBytes,
  shardRows: READ_THRESHOLDS.shardRows,
  otherRows: READ_THRESHOLDS.otherRows,
  mergeCursors: READ_THRESHOLDS.mergeCursors,
  mergeChunk: READ_THRESHOLDS.mergeChunkBytes,
  outputStaging: READ_THRESHOLDS.outputStagingBytes,
  importPart: READ_THRESHOLDS.importPartBytes,
};

/** Byte categories count toward `estimatedBytesPeak`; the others count entries or rows. */
const IS_BYTES: Readonly<Record<EstimateCategory, boolean>> = {
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
) as Record<EstimateCategory, number>;
const N = READ_CATEGORIES.length;

/** The bytes a retained view keeps alive: its whole underlying buffer. */
export function retainedBytes(bytes: Uint8Array): number {
  return bytes.buffer.byteLength;
}

/** Conservative UTF-16 memory charge of decoded text. Not a size: see {@link utf8Bytes}. */
export function textCharge(text: string): number {
  return 2 * text.length;
}

/**
 * Canonical UTF-8 size of a string, without encoding it. Matches
 * `new TextEncoder().encode(text).byteLength`, including lone surrogates
 * (each encodes as U+FFFD, three bytes). ASCII is 1 byte, BMP code units
 * above U+007F are 2 or 3 bytes, and a surrogate pair (one astral code
 * point) is 4 bytes.
 */
export function utf8Bytes(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) {
      bytes += 1;
    } else if (c < 0x800) {
      bytes += 2;
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

export interface CategoryEstimate {
  readonly unit: "bytes" | "count";
  readonly threshold: number;
  readonly estimatedCurrent: number;
  readonly estimatedPeak: number;
  /** Charges (acquire calls) since creation. */
  readonly acquisitions: number;
  /** Sum of charged amounts since creation. */
  readonly estimatedAcquired: number;
  /** Charges that left the category above its threshold. */
  readonly thresholdExceedances: number;
}

export interface ReadMemoryEstimate {
  readonly categories: Readonly<Record<EstimateCategory, CategoryEstimate>>;
  /** Live byte categories summed, now. Zero after release. */
  readonly estimatedBytesCurrent: number;
  /** Peak of that sum at one instant. */
  readonly estimatedBytesPeak: number;
  /** Ordinary records above `ordinaryRecordBytes` (canonical UTF-8 size). */
  readonly oversizeRecordCount: number;
}

/**
 * Live estimate of one read or one import. One instance per operation, so
 * a peak never mixes two operations.
 */
export class ReadMemoryEstimator {
  private readonly estimatedCurrent = new Float64Array(N);
  private readonly estimatedPeak = new Float64Array(N);
  private readonly acquisitions = new Float64Array(N);
  private readonly estimatedAcquired = new Float64Array(N);
  private readonly thresholdExceedances = new Float64Array(N);
  private bytesCurrent = 0;
  private bytesPeak = 0;
  private oversize = 0;

  acquire(category: EstimateCategory, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new Error(`charge must be finite and >= 0: ${category}`);
    }
    const i = INDEX[category];
    const next = this.estimatedCurrent[i]! + amount;
    this.estimatedCurrent[i] = next;
    if (next > this.estimatedPeak[i]!) this.estimatedPeak[i] = next;
    this.acquisitions[i]! += 1;
    this.estimatedAcquired[i]! += amount;
    if (next > THRESHOLD[category]) this.thresholdExceedances[i]! += 1;
    if (IS_BYTES[category]) {
      this.bytesCurrent += amount;
      if (this.bytesCurrent > this.bytesPeak) {
        this.bytesPeak = this.bytesCurrent;
      }
    }
  }

  release(category: EstimateCategory, amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new Error(`charge must be finite and >= 0: ${category}`);
    }
    const i = INDEX[category];
    const next = this.estimatedCurrent[i]! - amount;
    if (next < 0) {
      throw new Error(`released more than acquired: ${category}`);
    }
    this.estimatedCurrent[i] = next;
    if (IS_BYTES[category]) this.bytesCurrent -= amount;
  }

  /** Count one ordinary record above the threshold. Counts only; nothing refuses it. */
  noteOversizeRecord(): void {
    this.oversize += 1;
  }

  snapshot(): ReadMemoryEstimate {
    const categories = {} as Record<EstimateCategory, CategoryEstimate>;
    for (const category of READ_CATEGORIES) {
      const i = INDEX[category];
      categories[category] = {
        unit: IS_BYTES[category] ? "bytes" : "count",
        threshold: THRESHOLD[category],
        estimatedCurrent: this.estimatedCurrent[i]!,
        estimatedPeak: this.estimatedPeak[i]!,
        acquisitions: this.acquisitions[i]!,
        estimatedAcquired: this.estimatedAcquired[i]!,
        thresholdExceedances: this.thresholdExceedances[i]!,
      };
    }
    return {
      categories,
      estimatedBytesCurrent: this.bytesCurrent,
      estimatedBytesPeak: this.bytesPeak,
      oversizeRecordCount: this.oversize,
    };
  }
}

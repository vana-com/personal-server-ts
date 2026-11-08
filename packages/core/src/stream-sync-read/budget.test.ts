import { describe, expect, it } from "vitest";
import {
  READ_THRESHOLDS,
  READ_CATEGORIES,
  ReadMemoryEstimator,
  retainedBytes,
  textCharge,
  utf8Bytes,
} from "./budget.js";

const KiB = 1024;

describe("read memory estimator (calibration)", () => {
  it("peaks at the sum of overlapping live buffers, and returns to zero", () => {
    const b = new ReadMemoryEstimator();
    b.acquire("importedPart", 64 * KiB);
    b.acquire("importedPart", 96 * KiB);
    b.release("importedPart", 64 * KiB);
    b.release("importedPart", 96 * KiB);
    const s = b.snapshot();
    expect(s.categories.importedPart.estimatedPeak).toBe(160 * KiB);
    expect(s.categories.importedPart.estimatedCurrent).toBe(0);
    expect(s.estimatedBytesPeak).toBe(160 * KiB);
    expect(s.estimatedBytesCurrent).toBe(0);
  });

  it("the total peak is the peak of the sum at one instant, not the sum of category peaks", () => {
    const b = new ReadMemoryEstimator();
    b.acquire("importedPart", 100);
    b.release("importedPart", 100);
    b.acquire("decodedPart", 100);
    b.release("decodedPart", 100);
    const s = b.snapshot();
    expect(s.categories.importedPart.estimatedPeak).toBe(100);
    expect(s.categories.decodedPart.estimatedPeak).toBe(100);
    expect(s.estimatedBytesPeak).toBe(100);
  });

  it("counts charges and threshold exceedances, and does not refuse", () => {
    const b = new ReadMemoryEstimator();
    // One acquisition above the 16 MiB part limit: counted, never thrown.
    b.acquire("importedPart", READ_THRESHOLDS.partLimitBytes + 1);
    const s = b.snapshot();
    expect(s.categories.importedPart.acquisitions).toBe(1);
    expect(s.categories.importedPart.estimatedAcquired).toBe(
      READ_THRESHOLDS.partLimitBytes + 1,
    );
    expect(s.categories.importedPart.thresholdExceedances).toBe(1);
    expect(s.categories.importedPart.threshold).toBe(
      READ_THRESHOLDS.partLimitBytes,
    );
  });

  it("an unthresholded category never exceeds", () => {
    const b = new ReadMemoryEstimator();
    b.acquire("otherRows", 10_000_000);
    expect(b.snapshot().categories.otherRows.thresholdExceedances).toBe(0);
    expect(b.snapshot().categories.otherRows.threshold).toBe(
      Number.POSITIVE_INFINITY,
    );
  });

  it("releasing more than was acquired throws, and so does a negative or NaN amount", () => {
    const b = new ReadMemoryEstimator();
    b.acquire("spoolBuffer", 10);
    expect(() => b.release("spoolBuffer", 11)).toThrow(/released more/);
    expect(() => b.acquire("spoolBuffer", -1)).toThrow(/finite and >= 0/);
    expect(() => b.acquire("spoolBuffer", Number.NaN)).toThrow(
      /finite and >= 0/,
    );
    expect(b.snapshot().categories.spoolBuffer.estimatedCurrent).toBe(10);
  });

  it("counts count-unit categories without adding them to the byte total", () => {
    const b = new ReadMemoryEstimator();
    b.acquire("overlayWinners", 500);
    const s = b.snapshot();
    expect(s.categories.overlayWinners.unit).toBe("count");
    expect(s.categories.overlayWinners.estimatedPeak).toBe(500);
    expect(s.estimatedBytesPeak).toBe(0);
  });

  it("charges a retained view by its whole buffer, and decoded text at 2 bytes a unit", () => {
    const backing = new Uint8Array(1024 * KiB);
    const view = backing.subarray(0, KiB);
    expect(retainedBytes(view)).toBe(1024 * KiB);
    expect(retainedBytes(new Uint8Array(7))).toBe(7);
    expect(textCharge("abc")).toBe(6);
    // Astral text: two UTF-16 units per code point, so the charge is 4 per code point.
    expect(textCharge("😀")).toBe(4);
  });

  it("reports oversize ordinary records as a count, never as a refusal", () => {
    const b = new ReadMemoryEstimator();
    b.noteOversizeRecord();
    b.noteOversizeRecord();
    expect(b.snapshot().oversizeRecordCount).toBe(2);
  });

  it("names every category exactly once in the estimate", () => {
    const s = new ReadMemoryEstimator().snapshot();
    expect(Object.keys(s.categories).sort()).toEqual(
      [...READ_CATEGORIES].sort(),
    );
    expect(new Set(READ_CATEGORIES).size).toBe(READ_CATEGORIES.length);
  });

  it("the thresholds follow the protocol constants they cite", () => {
    // Writer default and decode cap of the protocol, as read from the package.
    expect(READ_THRESHOLDS.partTargetBytes).toBe(4 * 1024 * 1024);
    expect(READ_THRESHOLDS.partLimitBytes).toBe(16 * 1024 * 1024);
    expect(READ_THRESHOLDS.mergeCursors).toBe(256);
    // The ordinary-record limit sits well below the protocol publish cap.
    expect(READ_THRESHOLDS.ordinaryRecordBytes).toBeLessThan(8 * 1024 * 1024);
  });
});

describe("canonical UTF-8 size vs UTF-16 memory charge", () => {
  const encoder = new TextEncoder();
  const fixtures: Record<string, string> = {
    ascii: "a".repeat(200 * KiB),
    bmp2byte: "é".repeat(1000),
    bmp3byte: "€".repeat(1000),
    astral: "😀".repeat(1000),
    loneHighSurrogate: "\ud800x",
    loneLowSurrogate: "\udc00",
    mixed: "a€😀é",
    empty: "",
  };
  for (const [name, text] of Object.entries(fixtures)) {
    it(`utf8Bytes matches the encoder for ${name}`, () => {
      expect(utf8Bytes(text)).toBe(encoder.encode(text).byteLength);
    });
  }

  it("keeps size in UTF-8 bytes and the memory charge in UTF-16 units", () => {
    expect(utf8Bytes("a")).toBe(1);
    expect(textCharge("a")).toBe(2);
    expect(utf8Bytes("€")).toBe(3);
    expect(textCharge("€")).toBe(2);
    expect(utf8Bytes("😀")).toBe(4);
    expect(textCharge("😀")).toBe(4);
  });

  it("classifies at the ordinary-record threshold by UTF-8 bytes", () => {
    const limit = READ_THRESHOLDS.ordinaryRecordBytes;
    expect(utf8Bytes("a".repeat(limit))).toBe(limit);
    expect(utf8Bytes("a".repeat(limit + 1))).toBe(limit + 1);
    // An ASCII body of 200 KiB is under the threshold by size, though its memory charge is above it.
    expect(utf8Bytes("a".repeat(200 * KiB))).toBeLessThan(limit);
    expect(textCharge("a".repeat(200 * KiB))).toBeGreaterThan(limit);
  });
});

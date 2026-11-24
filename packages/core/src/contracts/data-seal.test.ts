/**
 * The ingest contract on a storage that writes the blob and its index row in
 * two steps. If the seal closes between them, the caller must read the
 * refusal (426 or 503), not an "incomplete write" it would log as a fault.
 */
import { describe, expect, it } from "vitest";
import { IngestPersistedError, ingestDataContract } from "./data.js";
import {
  LegacyWriteRefusedError,
  legacyWriteRefusedErrorFor,
} from "../api/legacy-write-gate.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { openLegacyWriteSealForTests } from "../test-utils/legacy-write-seal.js";

function twoStepStorage(failure: Error) {
  const storage = createMemoryDataStorage({
    legacyWriteSeal: openLegacyWriteSealForTests(),
  });
  // A host without an atomic write-and-index step.
  (storage as { writeEnvelopeAndIndex?: unknown }).writeEnvelopeAndIndex =
    undefined;
  storage.insertEntry = async () => {
    throw failure;
  };
  return storage;
}

const ingest = (storage: ReturnType<typeof twoStepStorage>) =>
  ingestDataContract({
    storage,
    scopeParam: "notes.entries",
    body: { items: [] },
    collectedAt: "2026-11-09T00:00:00.000Z",
    status: "stored",
  }).then(
    () => null,
    (error: unknown) => error,
  );

describe("ingest when the seal closes between the blob and its row", () => {
  it.each(["switched", "unknown"] as const)(
    "rethrows a %s refusal unwrapped",
    async (verdict) => {
      const error = await ingest(
        twoStepStorage(legacyWriteRefusedErrorFor(verdict)),
      );
      expect(error).toBeInstanceOf(LegacyWriteRefusedError);
      expect((error as LegacyWriteRefusedError).verdict).toBe(verdict);
    },
  );

  it("still reports any other index failure as a persisted-but-unindexed write", async () => {
    const error = await ingest(twoStepStorage(new Error("disk full")));
    expect(error).toBeInstanceOf(IngestPersistedError);
  });
});

describe("persisted-write diagnostic", () => {
  it("preserves the exact error and the relative path for a repair caller", () => {
    const rootCause = new Error("fixture index unavailable");
    const error = new IngestPersistedError("fixtures/version.json", rootCause);
    expect(error.name).toBe("IngestPersistedError");
    expect(error.cause).toBe(rootCause);
    expect(error.relativePath).toBe("fixtures/version.json");
    expect(error.message).toContain(rootCause.message);
  });

  it("formats a non-Error cause without claiming the index was written", () => {
    const error = new IngestPersistedError(
      "fixtures/version.json",
      "fixture refused",
    );
    expect(error.cause).toBe("fixture refused");
    expect(error.message).toBe(
      "Envelope persisted at fixtures/version.json but write did not complete: fixture refused",
    );
  });
});

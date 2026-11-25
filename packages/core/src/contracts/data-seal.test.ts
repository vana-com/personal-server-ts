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

describe("two-step ingest index outcomes", () => {
  it("commits exactly one index row on the ordinary successful path", async () => {
    const storage = twoStepStorage(new Error("fixture should not be used"));
    const rows: Parameters<typeof storage.insertEntry>[0][] = [];
    storage.insertEntry = async (entry) => {
      rows.push(entry);
    };
    expect(await ingest(storage)).toBeNull();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.path).toBeTruthy();
  });

  it("keeps the failing index entry's exact path and cause for repair", async () => {
    const cause = new Error("fixture index unavailable");
    const storage = twoStepStorage(cause);
    const paths: string[] = [];
    storage.insertEntry = async (entry) => {
      paths.push(entry.path);
      throw cause;
    };
    const error = await ingest(storage);
    expect(paths).toHaveLength(1);
    expect(error).toBeInstanceOf(IngestPersistedError);
    expect((error as IngestPersistedError).cause).toBe(cause);
    expect((error as IngestPersistedError).relativePath).toBe(paths[0]);
  });
});

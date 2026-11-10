/**
 * A scope upload commit is a legacy write. When the seal refuses it, the
 * staged upload is discarded and the caller reads the refusal itself (426 or
 * 503), not a 500 and not "superseded".
 */
import { describe, expect, it, vi } from "vitest";
import { createScopeUploadRegistry } from "./scope-uploads.js";
import {
  LegacyWriteRefusedError,
  legacyWriteRefusedErrorFor,
} from "./legacy-write-gate.js";
import type { DataStoragePort } from "../ports/index.js";

const SCOPE = "notes.entries";

function storageWhoseCommit(commit: () => Promise<never>) {
  const abort = vi.fn(async () => undefined);
  const storage = {
    openVersionWriter: vi.fn(async () => ({
      write: vi.fn(async () => undefined),
      commit,
      abort,
    })),
  } as unknown as DataStoragePort;
  return { storage, abort };
}

describe("scope upload commit under the legacy-write seal", () => {
  it.each(["switched", "unknown"] as const)(
    "aborts the staged upload and rethrows a %s refusal as it is",
    async (verdict) => {
      const { storage, abort } = storageWhoseCommit(async () => {
        throw legacyWriteRefusedErrorFor(verdict);
      });
      const registry = createScopeUploadRegistry();
      const release = vi.fn();
      const { uploadId } = await registry.begin({
        storage,
        scope: SCOPE,
        collectedAt: "2026-11-09T00:00:00.000Z",
        release,
        body: {},
      });
      await registry.append({
        scope: SCOPE,
        uploadId,
        seq: 0,
        text: JSON.stringify({ items: [{ id: 1 }] }),
      });

      const failure = await registry
        .commit({
          scope: SCOPE,
          uploadId,
          body: {},
          afterTombstoneVersion: null,
        })
        .then(
          () => null,
          (error: unknown) => error,
        );

      expect(failure).toBeInstanceOf(LegacyWriteRefusedError);
      expect((failure as LegacyWriteRefusedError).verdict).toBe(verdict);
      expect(abort).toHaveBeenCalled();
      expect(release).toHaveBeenCalled();
    },
  );
});

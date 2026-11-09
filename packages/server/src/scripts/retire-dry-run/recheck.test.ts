import { describe, expect, it, vi } from "vitest";
import type {
  ReadbackRecord,
  RetireFileReport,
  RetireReport,
} from "@opendatalabs/personal-server-ts-core/sync";
import { contentHash } from "@opendatalabs/personal-server-ts-core/storage/legacy-entity-key-sets";
import { recheckReadyFiles } from "./recheck.js";

const AT = "2026-10-01T00:00:00.000Z";
const body = { items: [{ id: "a" }] };

const file = (
  id: number,
  decision: RetireFileReport["decision"] = "ready",
): RetireFileReport => ({
  scope: "demo.items",
  version: `${id}|path/${id}.json|${AT}`,
  importDone: true,
  readback: "pass",
  readbackReason: null,
  decision,
  wouldDelete: decision === "ready",
});

const record = (fileHash: string | undefined): ReadbackRecord =>
  ({ fileHash }) as ReadbackRecord;

const retire = (files: RetireFileReport[]): RetireReport => ({
  mode: "dry-run",
  files,
  deleted: 0,
});

const key = (f: RetireFileReport) => `${f.scope}|${f.version}`;

describe("the last check before a delete, in the dry run", () => {
  it("keeps a ready file whose bytes still hash to the readback", async () => {
    const f = file(1);
    const out = await recheckReadyFiles({
      retire: retire([f]),
      records: new Map([[key(f), record(contentHash(body))]]),
      storage: { readEnvelope: async () => ({ data: body }) as never },
    });
    expect(out.files).toEqual([f]);
  });

  it("reports file_changed when the file hashes differently, and reads the right version", async () => {
    const f = file(1);
    const read = vi.fn(async () => ({ data: { items: [] } }) as never);
    const out = await recheckReadyFiles({
      retire: retire([f]),
      records: new Map([[key(f), record(contentHash(body))]]),
      storage: { readEnvelope: read },
    });
    expect(out.files[0]).toMatchObject({
      decision: "file_changed",
      wouldDelete: false,
    });
    expect(read).toHaveBeenCalledWith("demo.items", AT);
  });

  it("reports file_changed when the file cannot be read", async () => {
    const f = file(1);
    const out = await recheckReadyFiles({
      retire: retire([f]),
      records: new Map([[key(f), record(contentHash(body))]]),
      storage: {
        readEnvelope: async () => {
          throw new Error("gone");
        },
      },
    });
    expect(out.files[0]).toMatchObject({ decision: "file_changed" });
  });

  it("reports file_changed when the readback recorded no hash", async () => {
    const f = file(1);
    const read = vi.fn(async () => ({ data: body }) as never);
    for (const records of [
      new Map([[key(f), record(undefined)]]),
      new Map<string, ReadbackRecord>(),
    ]) {
      const out = await recheckReadyFiles({
        retire: retire([f]),
        records,
        storage: { readEnvelope: read },
      });
      expect(out.files[0]).toMatchObject({
        decision: "file_changed",
        wouldDelete: false,
      });
    }
  });

  it("leaves every other decision as it is, unread", async () => {
    const kept = (
      [
        "no_import",
        "no_readback",
        "readback_failed",
        "fence_not_imported",
        "fence_not_recollected",
        "file_changed",
      ] as const
    ).map((d, i) => file(i, d));
    const read = vi.fn();
    const out = await recheckReadyFiles({
      retire: retire(kept),
      records: new Map(),
      storage: { readEnvelope: read },
    });
    expect(out.files).toEqual(kept);
    expect(read).not.toHaveBeenCalled();
    expect(out.mode).toBe("dry-run");
    expect(out.deleted).toBe(0);
  });
});

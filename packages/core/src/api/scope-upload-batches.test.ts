import { describe, expect, it, vi } from "vitest";
import type { DataStoragePort } from "../ports/index.js";
import { sha256Hex } from "../contracts/binary.js";
import { createScopeUploadRegistry } from "./scope-uploads.js";
import { prepareScopeUploadBatches } from "./scope-upload-batches.js";

const scope = "notes.entries";
const collectedAt = "2026-10-28T00:00:00.000Z";

async function prepared(items: unknown[]) {
  const batches = [];
  for await (const batch of prepareScopeUploadBatches(items, 1024 * 1024)) {
    batches.push(batch);
  }
  return batches[0]!;
}

async function fixture(maxBatchBytes?: number) {
  const pieces: string[] = [];
  let stored: string | undefined;
  const release = vi.fn();
  const abort = vi.fn();
  const storage = {
    async openVersionWriter() {
      return {
        async write(text: string) {
          pieces.push(text);
        },
        async commit() {
          stored = pieces.join("");
          return {
            path: "version",
            relativePath: "version",
            sizeBytes: new TextEncoder().encode(stored).byteLength,
          };
        },
        abort,
      };
    },
  } as unknown as DataStoragePort;
  const registry = createScopeUploadRegistry({
    createId: () => "upload",
    maxBatchBytes,
  });
  const { uploadId } = await registry.begin({
    scope,
    collectedAt,
    storage,
    release,
    body: { data: { source: "fixture" }, arrayKey: "records" },
  });
  const target = { scope, uploadId };
  return {
    registry,
    target,
    release,
    abort,
    stored: () => stored,
    commit: () =>
      registry.commit({
        ...target,
        body: { data: { total: 3 } },
        afterTombstoneVersion: null,
      }),
  };
}

describe("prepared scope upload batches", () => {
  it("serializes each item once and never parses item text, including a replay", async () => {
    const f = await fixture();
    const items = [{ marker: "count-a" }, { marker: "count-b" }];
    const stringify = vi.spyOn(JSON, "stringify");
    const parse = vi.spyOn(JSON, "parse");
    try {
      const batch = await prepared(items);
      await f.registry.appendPrepared!({ ...f.target, seq: 0, batch });
      await f.registry.appendPrepared!({ ...f.target, seq: 0, batch });
      expect(stringify.mock.calls).toEqual(items.map((item) => [item]));
      expect(parse).not.toHaveBeenCalled();
    } finally {
      stringify.mockRestore();
      parse.mockRestore();
      await f.registry.abort(f.target);
    }
  });

  it("preserves stored bytes, version, size and exact HTTP replay digests", async () => {
    const items = [
      { id: 1, text: 'π 😀 \\ "\n', nested: [null, true, { x: 2 }] },
      { id: 2, loneSurrogate: "\ud800", omitted: undefined, n: Number.NaN },
      null,
    ];
    const body = JSON.stringify({ items });
    const batch = await prepared(items);
    expect(batch.bodySha256).toBe(
      await sha256Hex(new TextEncoder().encode(body)),
    );
    expect(batch.byteLength).toBe(new TextEncoder().encode(body).byteLength);
    expect(Object.isFrozen(batch)).toBe(true);
    const remote = await fixture();
    const direct = await fixture();
    expect(
      await remote.registry.append({ ...remote.target, seq: 0, text: body }),
    ).toEqual(
      await direct.registry.appendPrepared!({
        ...direct.target,
        seq: 0,
        batch,
      }),
    );
    // A response lost across a transport switch still replays, not appends.
    expect(
      await direct.registry.append({ ...direct.target, seq: 0, text: body }),
    ).toEqual({ seq: 0, items: 0, replay: true });
    expect(
      await remote.registry.appendPrepared!({
        ...remote.target,
        seq: 0,
        batch,
      }),
    ).toEqual({ seq: 0, items: 0, replay: true });
    expect(await direct.commit()).toEqual(await remote.commit());
    expect(direct.stored()).toBe(remote.stored());
    expect(direct.release).toHaveBeenCalledTimes(1);
    expect(remote.release).toHaveBeenCalledTimes(1);
  });

  it("uses identical errors for limits, ordering, conflicts and abort", async () => {
    const items = [{ text: "π" }];
    const batch = await prepared(items);
    for (const maxBatchBytes of [batch.byteLength - 1, batch.byteLength]) {
      const remote = await fixture(maxBatchBytes);
      const direct = await fixture(maxBatchBytes);
      const append = (f: typeof remote, seq: number, values = items) =>
        f === remote
          ? f.registry.append({
              ...f.target,
              seq,
              text: JSON.stringify({ items: values }),
            })
          : prepared(values).then((value) =>
              f.registry.appendPrepared!({ ...f.target, seq, batch: value }),
            );
      const result = async (promise: Promise<unknown>) => {
        try {
          return await promise;
        } catch (error) {
          const e = error as { status: number; code: string; message: string };
          return { status: e.status, code: e.code, message: e.message };
        }
      };
      for (const seq of [-1, 1, 0, 0, 2]) {
        expect(await result(append(direct, seq))).toEqual(
          await result(append(remote, seq)),
        );
      }
      expect(await result(append(direct, 0, [{ text: "x" }]))).toEqual(
        await result(append(remote, 0, [{ text: "x" }])),
      );
      await direct.registry.abort(direct.target);
      await remote.registry.abort(remote.target);
      expect(await result(append(direct, 1))).toEqual(
        await result(append(remote, 1)),
      );
      expect(direct.stored()).toBeUndefined();
      expect(remote.stored()).toBeUndefined();
      expect(direct.abort).toHaveBeenCalledTimes(1);
      expect(remote.abort).toHaveBeenCalledTimes(1);
    }
  });

  it("keeps the legacy UTF-8 batching boundary and null array values", async () => {
    const items = [undefined, Number.NaN, "😀", "\ud800", "é", null, false, 0];
    const target = 24;
    const legacy: unknown[][] = [];
    let current: unknown[] = [];
    let bytes = 12;
    for (const item of items) {
      const size =
        new TextEncoder().encode(JSON.stringify(item) ?? "null").byteLength + 1;
      if (current.length && bytes + size > target) {
        legacy.push(current);
        current = [];
        bytes = 12;
      }
      current.push(item);
      bytes += size;
    }
    if (current.length) legacy.push(current);
    const actual = [];
    for await (const batch of prepareScopeUploadBatches(items, target))
      actual.push(batch);
    expect(actual.map((batch) => batch.items)).toEqual(
      legacy.map((batch) => batch.length),
    );
    for (const [i, batch] of actual.entries()) {
      const body = new TextEncoder().encode(
        JSON.stringify({ items: legacy[i] }),
      );
      expect(batch.byteLength).toBe(body.byteLength);
      expect(batch.bodySha256).toBe(await sha256Hex(body));
    }
  });
});

import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RECORD_LINE_LIMIT_BYTES } from "@opendatalabs/personal-server-ts-stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";
import { createSeedStaging, type SeedStaging } from "./seed-staging.js";

const encoder = new TextEncoder();
const DESCRIPTOR = JSON.stringify({
  primaryKey: ["id"],
  profile: { key: "p", version: "2.0.0" },
  records: 3,
});

/** Yield `text` in pieces of `size` bytes, so lines cross chunk borders. */
async function* pieces(text: string, size: number): AsyncGenerator<Uint8Array> {
  const bytes = encoder.encode(text);
  for (let at = 0; at < bytes.length; at += size) {
    yield bytes.subarray(at, at + size);
  }
}

describe("seed staging", () => {
  let root: string;
  let staging: SeedStaging;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "seed-staging-"));
    staging = createSeedStaging(createFsStreamSyncFiles(root));
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("keeps the install id across instances", async () => {
    const id = await staging.installId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(
      await createSeedStaging(createFsStreamSyncFiles(root)).installId(),
    ).toBe(id);
  });

  it("skips a line over the record limit without holding it, across chunk borders", async () => {
    const big = JSON.stringify({
      id: "big",
      pad: "x".repeat(RECORD_LINE_LIMIT_BYTES),
    });
    const text = [DESCRIPTOR, '{"id":"a"}', big, '{"id":"b"}'].join("\n");
    const seed = await staging.stage("c", "s", pieces(text, 64 * 1024 + 7));
    expect(seed).toMatchObject({ records: 2, invalid: 0, tooLarge: 1 });
    const source = staging.source("install", async () => ({}));
    const rows = [];
    for await (const row of source.records("c", "s")) rows.push(row);
    expect(rows).toEqual([{ id: "a" }, { id: "b" }]);
    expect(await source.streams("c")).toEqual([
      {
        stream: "s",
        primaryKey: ["id"],
        profile: { key: "p", version: "2.0.0" },
      },
    ]);
  });

  it("drops the rows of a stream once the writer holds its receipt", async () => {
    const text = [DESCRIPTOR, '{"id":"a"}', '{"id":"b"}', '{"id":"c"}'].join(
      "\n",
    );
    await staging.stage("c", "s", pieces(text, 5));
    await staging.stage("c", "t", pieces(text, 5));
    const source = staging.source("install", async () => ({ s: "skipped" }));
    expect((await source.streams("c")).map((s) => s.stream)).toEqual(["t"]);
    expect(Object.keys(await staging.staged("c"))).toEqual(["t"]);
    expect(await readdir(join(root, "uploads"))).toHaveLength(1);
  });

  it("removes an upload that failed", async () => {
    const text = [DESCRIPTOR, '{"id":"a"}'].join("\n");
    await expect(
      staging.stage("c", "s", pieces(text, 3)),
    ).rejects.toMatchObject({
      errorCode: "SEED_COUNT_MISMATCH",
    });
    expect(await readdir(join(root, "uploads")).catch(() => [])).toEqual([]);
  });
});

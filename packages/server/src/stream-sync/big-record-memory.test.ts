/**
 * Peak memory to write and read one record of 8, 30 and 100 MiB, in a fresh
 * child process per step (see `memory-oracle.ts`). The read paths check that
 * the bytes forwarded are the bytes written.
 */

import { appendFile, mkdtemp, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { bigRecord, type BigPublished } from "./big-record.workload.js";

const WORKLOAD = fileURLToPath(
  new URL("./big-record.workload.ts", import.meta.url),
);
const MiB = 1024 * 1024;
const SIZES = (process.env.BIG_RECORD_MIB ?? "8,30,100")
  .split(",")
  .map((n) => Number(n) * MiB);

describe.each([
  ["node", "timer25ms"],
  ["lite", "timer25ms"],
  ["lite", "none"],
] as const)("big record memory on %s with gc %s", (surface, gc) => {
  it.each(SIZES)(
    "writes and reads a %i byte record with forward-read memory bounded by part size",
    async (bodyBytes) => {
      const root = await mkdtemp(
        join(process.env.HOME ?? "", ".tmp", "big-record-"),
      );
      try {
        const base = { root, bodyBytes, surface };
        const write = await run<BigPublished>(
          { module: WORKLOAD, exportName: "writeWorkload", args: base },
          { gc },
        );
        const forward = await run<{ bytes: number; sha256: string }>(
          {
            module: WORKLOAD,
            exportName: "readForwardWorkload",
            args: { ...base, published: write.result },
          },
          { gc },
        );
        const parse = await run<{ bytes: number; padLength: number }>(
          {
            module: WORKLOAD,
            exportName: "readParseWorkload",
            args: { ...base, published: write.result },
          },
          { gc },
        );
        const body = canonicalJson(bigRecord(bodyBytes));
        expect(forward.result.bytes).toBe(bodyBytes);
        expect(forward.result.sha256).toBe(
          createHash("sha256").update(body).digest("hex"),
        );
        expect(parse.result.bytes).toBe(bodyBytes);
        await appendFile(
          process.env.BIG_RECORD_OUT ?? "/dev/null",

          `MEMORY ${surface}/${gc} ${bodyBytes / MiB} MiB: write ${(write.peakBytes / MiB).toFixed(0)} MiB, read-forward ${(forward.peakBytes / MiB).toFixed(0)} MiB, read-parse ${(parse.peakBytes / MiB).toFixed(0)} MiB\n`,
        );
        // Forwarding must not scale with the record: a few parts, not the body.
        if (surface === "node")
          expect(forward.peakBytes).toBeLessThan(48 * MiB);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
    600_000,
  );
});

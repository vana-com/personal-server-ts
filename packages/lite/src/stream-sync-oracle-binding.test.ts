/**
 * The heap runner's correctness oracle must read what a real reader reads: the
 * head named by the registry's dataHash, verified by verifyHead, and every part
 * verified by decodePart (SHA-256, byte length, line count). A published state
 * that a real reader rejects must make the oracle fail, not report the expected
 * count and digest.
 *
 * Each case publishes through the real writer, then tampers with the stored
 * state in-process (TamperContext) before the oracle runs.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodeHead,
  encodeHead,
  partBlobName,
  streamScope,
  toHex,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncHashes } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  runScenario,
  type RunOptions,
  type TamperContext,
} from "./test-support/stream-sync-heap-node.js";
import {
  CONNECTOR,
  STREAM,
} from "./test-support/stream-sync-heap-scenarios.js";

const SPEC = { kind: "uniform", records: 300 } as const;
let root = "";

beforeAll(() => {
  root = mkdtempSync(join(homedir(), ".tmp", "p3r6-oracle-"));
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

function run(tag: string, tamper?: RunOptions["tamper"]) {
  return runScenario(SPEC, {
    dir: join(root, tag),
    ...(tamper ? { tamper } : {}),
  });
}

async function currentRow(
  ctx: TamperContext,
): Promise<Extract<ControlRead, { found: true }>> {
  const row = await ctx.registry.read(ctx.scope);
  if (!row.found) throw new Error("tamper: no published row");
  return row;
}

/** Publish a new registry version (exclusive: version + 1) with the given data hash. */
async function repointRegistry(
  ctx: TamperContext,
  dataHash: string,
): Promise<void> {
  const row = await currentRow(ctx);
  const result = await ctx.registry.post({
    scope: ctx.scope,
    expectedVersion: String(row.version + 1),
    dataHash,
    metadataHash: row.metadataHash,
    deletedAt: "",
  } as never);
  if (result.kind !== "committed")
    throw new Error(`tamper: post ${result.kind}`);
}

function headNameOf(dataHash: string): string {
  return `h-${dataHash.toLowerCase().replace(/^0x/, "")}`;
}

describe("heap oracle is bound to the published registry head", () => {
  it("control: an untampered publish is accepted", async () => {
    const report = await run("control");
    expect(report.countOk).toBe(true);
    expect(report.digestOk).toBe(true);
  }, 120_000);

  it("rejects a registry row whose head blob is not stored", async () => {
    await expect(
      run("missing-head", async (ctx) => {
        await repointRegistry(ctx, `0x${"ab".repeat(32)}`);
      }),
    ).rejects.toThrow(/head .* missing/);
  }, 120_000);

  it("rejects a re-signed head whose part count disagrees with its lines", async () => {
    await expect(
      run("count-lie", async (ctx) => {
        const row = await currentRow(ctx);
        const headKey = `${ctx.scope}/${headNameOf(row.dataHash)}`;
        const cipher = await ctx.blobs.get(headKey);
        const decoded = decodeHead(await ctx.keys.decrypt(ctx.scope, cipher!));
        if (decoded.kind !== "ok") throw new Error("tamper: head not ok");
        const head = decoded.head;
        const lied = {
          ...head,
          parts: head.parts.map((p, i) =>
            i === 0 ? { ...p, count: p.count + 1 } : p,
          ),
          recordCount: head.recordCount + 1,
        };
        const bytes = encodeHead(lied);
        const hex = toHex(await streamSyncHashes.keccak256(bytes));
        await ctx.blobs.put(
          `${ctx.scope}/h-${hex}`,
          await ctx.keys.encrypt(ctx.scope, bytes),
        );
        await repointRegistry(ctx, `0x${hex}`);
      }),
    ).rejects.toThrow(/head says|lines/);
  }, 120_000);

  it("rejects a part whose bytes no longer match the head SHA-256", async () => {
    await expect(
      run("part-corrupt", async (ctx) => {
        const row = await currentRow(ctx);
        const cipher = await ctx.blobs.get(
          `${ctx.scope}/${headNameOf(row.dataHash)}`,
        );
        const decoded = decodeHead(await ctx.keys.decrypt(ctx.scope, cipher!));
        if (decoded.kind !== "ok") throw new Error("tamper: head not ok");
        const part = decoded.head.parts[0]!;
        const partKey = `${ctx.scope}/${partBlobName(decoded.head.generation, part.hash)}`;
        const clear = new Uint8Array(
          await ctx.keys.decrypt(ctx.scope, (await ctx.blobs.get(partKey))!),
        );
        // Swap one digit for another: same length, still a valid line, new SHA-256.
        const at = clear.findIndex((b) => b >= 0x30 && b <= 0x38);
        if (at < 0) throw new Error("tamper: no digit to change");
        clear[at] = clear[at]! + 1;
        await ctx.blobs.put(partKey, await ctx.keys.encrypt(ctx.scope, clear));
      }),
    ).rejects.toThrow(/SHA-256/);
  }, 120_000);
});

void tmpdir;
void streamScope;
void CONNECTOR;
void STREAM;

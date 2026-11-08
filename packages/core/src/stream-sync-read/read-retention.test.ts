/**
 * Step 1 retention gates: the no-overlay read must not hold its input.
 *
 * - Fixed-size gate (oracle, RSS): the clean read at the largest size stays
 *   under a budget. Catches all-part retention (the retain-all mutant).
 * - Growth gate (live heap after forced GC, deterministic): the retained live
 *   memory during the read does not grow from N to 16N records beyond a slack.
 *   Catches retention that is a fixed fraction of the input, which the fixed
 *   budget can miss. RSS is too noisy for this (see the PR body).
 *
 * Each size is a separate fixture. The parent builds it and copies its files
 * to disk. The child restarts from those files and drains the view, as a
 * restarted server would.
 */

import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDiskStreamSyncReadFiles } from "../test-support/disk-files.js";
import { run } from "../test-support/memory-oracle.js";
import {
  ask,
  bitsFor,
  CONNECTOR,
  Fixture,
  MiB,
  masterKey,
  prefixesFor,
  recordsOf,
} from "../test-support/read-fixture.js";
import { testOwnerKey } from "./testing.js";

const SEED = 41;
const SCOPE = "pdpp.acme.items";
/** N, 4N, 16N records. 16N is about 65 MB encoded, about 500 parts. */
const SIZES = [8_192, 32_768, 131_072] as const;
const SMALLEST = SIZES[0];
const LARGEST = SIZES[SIZES.length - 1];
/** Peak RSS the clean read may add at 16N. The retain-all mutant measured 70 to 78 MB there. */
const RETENTION_BUDGET = 48 * MiB;
/** Live memory the read may add from N to 16N. Calibrated in the PR body. */
const GROWTH_SLACK = 4 * MiB;
/** Live-heap sample every this many body chunks. */
const SAMPLE_EVERY = 25;

const PROBE = fileURLToPath(
  new URL("../test-support/read-workloads.ts", import.meta.url),
);

type Probe = { bytes: number; digest: string };
type Live = Probe & { retained: number };
type Stream = { dir: string; parent: Probe };

const streams = new Map<number, Stream>();
const dirs: string[] = [];

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function buildStream(records: number): Promise<Stream> {
  const home = join(homedir(), ".tmp");
  await mkdir(home, { recursive: true });
  const dir = await mkdtemp(join(home, "retention-"));
  dirs.push(dir);

  const owner = await testOwnerKey(masterKey(SEED));
  const f = new Fixture(owner);
  const ns = await owner.ns(CONNECTOR, "account-1");
  await f.activate(CONNECTOR, ns);
  await f.publish({
    connector: CONNECTOR,
    ns,
    stream: "items",
    generation: 1,
    records: recordsOf(records),
    prefixes: prefixesFor(bitsFor(records)),
  });
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask(SCOPE));
  if (decision.kind !== "view")
    throw new Error(`expected view: ${decision.kind}`);
  const reader = decision.body.getReader();
  const hash = sha256.create();
  let bytes = 0;
  for (;;) {
    const next = await reader.read();
    if (next.done) break;
    hash.update(next.value);
    bytes += next.value.byteLength;
  }
  const disk = createDiskStreamSyncReadFiles(dir);
  for (const [path, body] of f.files.files) await disk.write(path, body);
  return { dir, parent: { bytes, digest: hex(hash.digest()) } };
}

const args = (stream: Stream) => ({
  dir: stream.dir,
  seed: SEED,
  scope: SCOPE,
});

beforeAll(async () => {
  for (const n of SIZES) streams.set(n, await buildStream(n));
}, 900_000);

afterAll(async () => {
  for (const dir of dirs) await rm(dir, { recursive: true, force: true });
});

describe("stream-sync read retention (step 1)", () => {
  it("green setup: the restarted child reads the same body the parent drained at every size", async () => {
    for (const n of SIZES) {
      const stream = streams.get(n)!;
      const child = await run<Probe>({
        module: PROBE,
        exportName: "readRetention",
        args: args(stream),
      });
      expect(child.result.bytes, `bytes at ${n} records`).toBe(
        stream.parent.bytes,
      );
      expect(child.result.digest, `digest at ${n} records`).toBe(
        stream.parent.digest,
      );
    }
  }, 900_000);

  it("the no-overlay read's RSS peak at 16N stays under the retention budget", async () => {
    const r = await run<Probe>({
      module: PROBE,
      exportName: "readRetention",
      args: args(streams.get(LARGEST)!),
    });
    expect(r.result.bytes).toBe(streams.get(LARGEST)!.parent.bytes);
    expect(r.peakBytes, "clean read peak at 16N, bytes").toBeLessThan(
      RETENTION_BUDGET,
    );
  }, 300_000);

  it("the no-overlay read's live memory does not grow from N to 16N beyond the growth slack", async () => {
    const retained: Record<number, number> = {};
    for (const n of [SMALLEST, LARGEST]) {
      const stream = streams.get(n)!;
      const r = await run<Live>({
        module: PROBE,
        exportName: "readLiveRetention",
        args: { ...args(stream), sampleEvery: SAMPLE_EVERY },
      });
      expect(r.result.bytes, `bytes at ${n} records`).toBe(stream.parent.bytes);
      retained[n] = r.result.retained;
    }
    const growth = retained[LARGEST]! - retained[SMALLEST]!;
    expect(
      growth,
      `live growth N to 16N, bytes (retained: ${JSON.stringify(retained)})`,
    ).toBeLessThanOrEqual(GROWTH_SLACK);
  }, 900_000);
});

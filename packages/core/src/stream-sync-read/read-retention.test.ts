/**
 * Step 1 retention gate: the no-overlay read of a large stream must not hold
 * every parsed record. Measured in a fresh child by the shared memory oracle,
 * so the peak is process memory, not a bookkeeping estimate.
 *
 * The parent builds the fixture and copies its files to disk. The child then
 * restarts from those files and drains the view, as a restarted server would.
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
/** About 65 MB of encoded records: about 500 parts. The retain-all mutant peaks near 73 MB on this stream. */
const RECORDS = 131_072;
/** Peak the clean read may add. Clean read measured about 12 to 26 MiB; the retain-all mutant about 70 to 74 MiB. */
const RETENTION_BUDGET = 48 * MiB;

const PROBE = fileURLToPath(
  new URL("../test-support/read-workloads.ts", import.meta.url),
);

type Probe = { bytes: number; digest: string };

let dir: string;
let parent: Probe;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

beforeAll(async () => {
  const home = join(homedir(), ".tmp");
  await mkdir(home, { recursive: true });
  dir = await mkdtemp(join(home, "retention-"));

  const owner = await testOwnerKey(masterKey(SEED));
  const f = new Fixture(owner);
  const ns = await owner.ns(CONNECTOR, "account-1");
  await f.activate(CONNECTOR, ns);
  await f.publish({
    connector: CONNECTOR,
    ns,
    stream: "items",
    generation: 1,
    records: recordsOf(RECORDS),
    prefixes: prefixesFor(bitsFor(RECORDS)),
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
  parent = { bytes, digest: hex(hash.digest()) };

  const disk = createDiskStreamSyncReadFiles(dir);
  for (const [path, body] of f.files.files) await disk.write(path, body);
}, 300_000);

afterAll(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("stream-sync read retention (step 1)", () => {
  it("green setup: the restarted child reads the same body the parent drained", async () => {
    const child = await run<Probe>({
      module: PROBE,
      exportName: "readRetention",
      args: { dir, seed: SEED, scope: SCOPE },
    });
    expect(child.result.bytes).toBe(parent.bytes);
    expect(child.result.digest).toBe(parent.digest);
  }, 300_000);

  it("the no-overlay read keeps no more than the retention budget resident", async () => {
    const r = await run<Probe>({
      module: PROBE,
      exportName: "readRetention",
      args: { dir, seed: SEED, scope: SCOPE },
    });
    expect(r.result.bytes).toBe(parent.bytes);
    expect(r.peakBytes, "clean read peak, bytes").toBeLessThan(
      RETENTION_BUDGET,
    );
  }, 300_000);
});

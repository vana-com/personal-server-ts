/**
 * S11: with replication on, importing and retiring the server's own legacy
 * store captures nothing for replication. The import reads through a store
 * with no replica wrapper, and the door is closed first.
 */
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServerContext } from "../bootstrap.js";
import {
  boot,
  filesLeft,
  lineOf,
  readIndex,
  scratch,
  switchOn,
  writeDeclared,
  writeLegacyStore,
} from "./legacy-migration-fixture.test-utils.js";

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

const OUTBOX_TABLES = [
  "pdpp_replica_operations",
  "pdpp_replica_baseline",
  "pdpp_replica_view",
  "pdpp_transport_batches",
  "pdpp_transport_staged_fragments",
  "pdpp_transport_fragments_out",
  "pdpp_transport_manifests_out",
  "pdpp_transport_imported",
];

describe("zero-replica-outbox-after-import-and-retire", () => {
  it("captures nothing for replication while it imports and retires", async () => {
    const base = await scratch("legacy-replication-");
    directories.push(base);
    const root = join(base, "root");
    const declared = await writeDeclared(join(base, "declared"));
    writeLegacyStore(root);
    const { context } = await boot(root, declared, {
      retireLegacy: true,
      replication: true,
    });
    contexts.push(context);
    const run = await switchOn(context);
    await run.finished;
    await context.cleanup();
    contexts.pop();

    expect(lineOf(run.lines, "legacy store import finished")).toMatchObject({
      imported: 9,
    });
    expect(lineOf(run.lines, "legacy retirement finished")).toMatchObject({
      mode: "delete",
      deleted: 6,
    });
    expect(filesLeft(root)).toEqual([]);

    const { door, counts } = readIndex(root, (db) => ({
      door: db.prepare("SELECT off, capturing FROM pdpp_replica_door").all(),
      counts: Object.fromEntries(
        OUTBOX_TABLES.map((table) => [
          table,
          (
            db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as {
              n: number;
            }
          ).n,
        ]),
      ),
    }));
    // The door is closed for good: nothing is captured, now or after a restart.
    expect(door).toEqual([{ off: 1, capturing: 0 }]);
    expect(counts).toEqual(
      Object.fromEntries(OUTBOX_TABLES.map((t) => [t, 0])),
    );
  }, 120_000);
});

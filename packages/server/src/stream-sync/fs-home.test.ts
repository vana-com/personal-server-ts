import {
  mkdtemp,
  readdir,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openFsStreamSyncHome } from "./fs-home.js";
import { createSeedStaging } from "./seed-staging.js";

const A = "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63" as const;
const B = "0x2000000000000000000000000000000000000002" as const;
const NET = "vana:14800:https://g.test";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "fs-home-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("full-server stream-sync home", () => {
  it("lets one process hold a home; a second gets null until release", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(first).not.toBeNull();
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).toBeNull();
    await first!.close();
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).not.toBeNull();
  });

  it("keeps two owners in separate directories", async () => {
    const a = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    const b = await openFsStreamSyncHome({
      root,
      ownerAddress: B,
      network: NET,
    });
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(a!.home.id).not.toBe(b!.home.id);
    await a!.home.files.write("state.json", new Uint8Array([1]));
    expect(await b!.home.files.read("state.json")).toBeNull();
    expect(await readdir(join(root, "stream-sync-homes"))).not.toContain(
      "state.json",
    );
  });

  it("takes over a lock whose process is gone", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    await writeFile(
      join(root, "stream-sync-homes", `${first!.home.id}.lock`),
      "2147483646",
    );
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).not.toBeNull();
  });

  it("stages seed rows in the owner's home: another owner never sees them", async () => {
    const a = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    const stagingA = createSeedStaging(a!.seedFiles);
    await stagingA.stage(
      "c",
      "s",
      (async function* () {
        yield new TextEncoder().encode(
          [
            JSON.stringify({
              primaryKey: ["id"],
              profile: { key: "p", version: "2.0.0" },
              records: 1,
            }),
            '{"id":"a"}',
          ].join("\n"),
        );
      })(),
    );
    await a!.close();
    const b = await openFsStreamSyncHome({
      root,
      ownerAddress: B,
      network: NET,
    });
    const sourceB = createSeedStaging(b!.seedFiles).source(
      "i",
      async () => ({}),
    );
    expect(await sourceB.streams("c")).toEqual([]);
    await b!.close();
    const again = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    const sourceA = createSeedStaging(again!.seedFiles).source(
      "i",
      async () => ({}),
    );
    expect((await sourceA.streams("c")).length).toBe(1);
  });

  it("respects a lock held by a live server, and its heartbeat keeps it fresh", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
      staleMs: 300,
      heartbeatMs: 50,
    });
    const lock = join(root, "stream-sync-homes", `${first!.home.id}.lock`);
    await new Promise((r) => setTimeout(r, 700));
    expect(Date.now() - (await stat(lock)).mtimeMs).toBeLessThan(300);
    expect(
      await openFsStreamSyncHome({
        root,
        ownerAddress: A,
        network: NET,
        staleMs: 300,
      }),
    ).toBeNull();
    await first!.close();
  });

  it("takes over a lock whose pid is live but unrelated (reused pid, no heartbeat)", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
      heartbeatMs: 3_600_000,
    });
    const lock = join(root, "stream-sync-homes", `${first!.home.id}.lock`);
    // A crashed holder left a pid that a live process now owns (this one).
    await writeFile(lock, `${process.pid}\nold`);
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(lock, old, old);
    const second = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(second).not.toBeNull();
    // The first holder, stalled and replaced, must not delete the new lock.
    await first!.close();
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).toBeNull();
    await second!.close();
  });
});

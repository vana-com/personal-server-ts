import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openFsStreamSyncHome } from "./fs-home.js";

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
});

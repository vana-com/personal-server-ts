import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

  it("ignores a leftover lease file from the old lock scheme", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    const id = first!.home.id;
    await first!.close();
    await writeFile(
      join(root, "stream-sync-homes", `${id}.lock`),
      `${process.pid}\nold`,
    );
    const again = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(again).not.toBeNull();
    await again!.close();
  });

  it("closes twice without error and frees the home", async () => {
    const first = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    await first!.close();
    await first!.close();
    const again = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(again).not.toBeNull();
    await again!.close();
  });
});

const CHILD = fileURLToPath(
  new URL("./fs-home.child.test-utils.ts", import.meta.url),
);

interface Child {
  readonly process: ChildProcess;
  /** `held` or `busy`: what the child's open returned. */
  readonly result: Promise<"held" | "busy">;
  readonly exited: Promise<void>;
}

const children: ChildProcess[] = [];

function startChild(dir: string): Child {
  const process_ = spawn(
    process.execPath,
    ["--import", "tsx", CHILD, dir, A, NET],
    { stdio: ["ignore", "pipe", "inherit"] },
  );
  children.push(process_);
  const result = new Promise<"held" | "busy">((resolve, reject) => {
    let out = "";
    process_.stdout!.on("data", (chunk: Buffer) => {
      out += chunk.toString();
      if (out.includes("\n")) resolve(out.trim() as "held" | "busy");
    });
    process_.once("error", reject);
    process_.once("exit", (code, signal) =>
      reject(new Error(`child ended early: ${code ?? signal}`)),
    );
  });
  result.catch(() => {});
  const exited = new Promise<void>((resolve) => {
    if (process_.exitCode !== null || process_.signalCode !== null) resolve();
    else process_.once("exit", () => resolve());
  });
  return { process: process_, result, exited };
}

afterEach(() => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }
});

describe("full-server stream-sync home: one kernel-held lock", () => {
  it("gives exactly one of many in-process openers the home, every time", async () => {
    for (let round = 0; round < 100; round += 1) {
      const dir = join(root, `in-process-${round}`);
      const opened = await Promise.all(
        Array.from({ length: 6 }, () =>
          openFsStreamSyncHome({ root: dir, ownerAddress: A, network: NET }),
        ),
      );
      expect(opened.filter((h) => h !== null)).toHaveLength(1);
      await Promise.all(opened.map((h) => h?.close()));
    }
  }, 60_000);

  it("gives exactly one of several racing processes the home, every time", async () => {
    for (let round = 0; round < 12; round += 1) {
      const dir = join(root, `race-${round}`);
      const racers = Array.from({ length: 4 }, () => startChild(dir));
      const results = await Promise.all(racers.map((r) => r.result));
      expect(results.filter((r) => r === "held")).toHaveLength(1);
      // The winner still lives, so the parent cannot take the home either.
      expect(
        await openFsStreamSyncHome({
          root: dir,
          ownerAddress: A,
          network: NET,
        }),
      ).toBeNull();
      for (const r of racers) r.process.kill("SIGKILL");
      await Promise.all(racers.map((r) => r.exited));
    }
  }, 120_000);

  it("frees the home when the holder is killed without cleanup", async () => {
    const holder = startChild(root);
    expect(await holder.result).toBe("held");
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).toBeNull();
    holder.process.kill("SIGKILL");
    await holder.exited;
    const next = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(next).not.toBeNull();
    await next!.close();
  }, 30_000);

  it("never takes the home from a holder that is stalled", async () => {
    const holder = startChild(root);
    expect(await holder.result).toBe("held");
    holder.process.kill("SIGSTOP");
    // No clock takes part in who holds the home, so how long the holder stays
    // stopped (the old lease expired after 60 s) cannot matter. A short stop
    // proves the lock does not depend on the holder running.
    await new Promise((r) => setTimeout(r, 1_500));
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).toBeNull();
    const rival = startChild(root);
    expect(await rival.result).toBe("busy");
    holder.process.kill("SIGCONT");
    expect(
      await openFsStreamSyncHome({ root, ownerAddress: A, network: NET }),
    ).toBeNull();
    holder.process.kill("SIGKILL");
    await holder.exited;
    const next = await openFsStreamSyncHome({
      root,
      ownerAddress: A,
      network: NET,
    });
    expect(next).not.toBeNull();
    await next!.close();
  }, 30_000);
});

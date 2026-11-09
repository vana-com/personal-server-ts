/**
 * The folder owner is held by the kernel, so every case here uses real
 * processes: a child process claims the folder (`claim-child.test-utils.ts`),
 * and the test kills or stops it by its saved handle.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { hostname } from "node:os";
import Database from "better-sqlite3";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ModeStoreOwnedError,
  createModeAuthority,
  type DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const CHILD = fileURLToPath(
  new URL("./claim-child.test-utils.ts", import.meta.url),
);
const HOME = process.env.HOME ?? "";

const ON: DurableModeRecord = {
  switched: true,
  switchedAt: 12,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "b",
  importPending: false,
};

interface Child {
  readonly process: ChildProcess;
  /** The next line the child prints. */
  line(): Promise<string>;
  send(text: string): void;
  exited(): Promise<void>;
}

const children: ChildProcess[] = [];

function startChild(dir: string): Child {
  const proc = spawn(process.execPath, ["--import", "tsx", CHILD, dir], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  children.push(proc);
  const lines: string[] = [];
  const waiting: Array<(line: string) => void> = [];
  let buffer = "";
  proc.stdout!.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    for (let i = buffer.indexOf("\n"); i >= 0; i = buffer.indexOf("\n")) {
      const next = buffer.slice(0, i);
      buffer = buffer.slice(i + 1);
      const waiter = waiting.shift();
      if (waiter) waiter(next);
      else lines.push(next);
    }
  });
  const done = new Promise<void>((resolve) => {
    if (proc.exitCode !== null || proc.signalCode !== null) resolve();
    else proc.once("exit", () => resolve());
  });
  return {
    process: proc,
    line: () =>
      new Promise((resolve, reject) => {
        const ready = lines.shift();
        if (ready !== undefined) return resolve(ready);
        waiting.push(resolve);
        void done.then(() => reject(new Error("child ended before a line")));
      }),
    send: (text) => proc.stdin!.write(text),
    exited: () => done,
  };
}

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGCONT");
      child.kill("SIGKILL");
      await once(child, "exit");
    }
  }
});

async function kill(child: Child): Promise<void> {
  child.process.kill("SIGKILL");
  await child.exited();
}

async function listing(dir: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const name of (await readdir(dir)).sort()) {
    if (name.startsWith(".mode-owner.lock.db")) continue;
    out[name] = await readFile(join(dir, name), "utf8").catch(() => "<dir>");
  }
  return out;
}

describe("file record store ownership: a kernel-held lock", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(HOME, ".tmp", "mode-owner-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  // SECOND_OWNER_ADMITTED
  it("a: of two processes that claim at once, exactly one owns and the loser writes nothing", async () => {
    for (let round = 0; round < 3; round += 1) {
      const folder = join(dir, `race-${round}`);
      const a = startChild(folder);
      const b = startChild(folder);
      const answers = [await a.line(), await b.line()].sort();
      expect(answers).toEqual(["OWNED", "READY"]);
      const records = (await readdir(folder)).filter((n) =>
        /^c\d+\.json$/.test(n),
      );
      expect(records).toHaveLength(1);
      await kill(a);
      await kill(b);
    }
  }, 60_000);

  // LOCK_RELEASED_EARLY
  it("a: a contender in this process is refused while a child owns, and changes nothing", async () => {
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    const before = await listing(dir);
    const contender = createFileModeRecordStore(dir);
    await expect(contender.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    // A refused store neither reads nor writes: no sweep, no load, no save.
    await expect(contender.load()).rejects.toThrow();
    await expect(contender.save("x", ON, null)).rejects.toThrow();
    expect(await listing(dir)).toEqual(before);
    await kill(owner);
  }, 30_000);

  it("b: a new process claims at once after the owner is killed, and the records survive", async () => {
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    const written = `c${owner.process.pid}`;
    await kill(owner);
    const store = createFileModeRecordStore(dir);
    const lease = await store.claim();
    expect((await store.load()).get(written)).toMatchObject({
      switched: true,
      bootId: "child",
    });
    await lease.release();
  }, 30_000);

  it("c: a stopped but live owner still owns, even a day later, until it is killed", async () => {
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    owner.process.kill("SIGSTOP");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      for (const days of [0, 1, 400]) {
        vi.setSystemTime(Date.now() + days * 86_400_000);
        await expect(
          createFileModeRecordStore(dir).claim(),
        ).rejects.toBeInstanceOf(ModeStoreOwnedError);
      }
    } finally {
      vi.useRealTimers();
    }
    // A contender in another process is refused as well.
    const other = startChild(dir);
    expect(await other.line()).toBe("OWNED");
    owner.process.kill("SIGCONT");
    await kill(owner);
    const lease = await createFileModeRecordStore(dir).claim();
    await lease.release();
  }, 30_000);

  it("d: the recorded pid does not matter, in either direction", async () => {
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    // A lock file of the old format that names a pid nobody has, and one that
    // names this very (live, unrelated) process: neither says who owns.
    const old = join(dir, ".owner.lock");
    await writeFile(
      old,
      JSON.stringify({ pid: 2_000_000_000, host: "elsewhere", token: "t" }),
    );
    await expect(createFileModeRecordStore(dir).claim()).rejects.toBeInstanceOf(
      ModeStoreOwnedError,
    );
    await kill(owner);
    await writeFile(
      old,
      JSON.stringify({ pid: process.pid, host: hostname(), token: "t" }),
    );
    const lease = await createFileModeRecordStore(dir).claim();
    await lease.release();
    // Nothing deletes it: it is not part of the protocol.
    expect(await readdir(dir)).toContain(".owner.lock");
  }, 30_000);

  it("e: an alias or symlink to the same folder contends on the same lock", async () => {
    const alias = `${dir}-alias`;
    await symlink(dir, alias);
    try {
      const owner = startChild(alias);
      expect(await owner.line()).toBe("READY");
      await expect(
        createFileModeRecordStore(dir).claim(),
      ).rejects.toBeInstanceOf(ModeStoreOwnedError);
      await expect(
        createFileModeRecordStore(`${dir}/../${dir.split("/").pop()}`).claim(),
      ).rejects.toBeInstanceOf(ModeStoreOwnedError);
      await kill(owner);
      const lease = await createFileModeRecordStore(dir).claim();
      await expect(
        createFileModeRecordStore(alias).claim(),
      ).rejects.toBeInstanceOf(ModeStoreOwnedError);
      await lease.release();
    } finally {
      await rm(alias, { force: true });
    }
  }, 30_000);

  it("f: a claim whose load then fails lets the folder go", async () => {
    // A directory named like a record cannot be read as one: the load fails.
    await mkdir(join(dir, "x.json"));
    const authority = createModeAuthority({
      store: createFileModeRecordStore(dir),
      bootId: "boot",
    });
    await expect(authority.ready).rejects.toThrow();
    // Nothing is stranded: another runtime claims at once.
    const lease = await createFileModeRecordStore(dir).claim();
    await lease.release();
  });

  it("g: a runtime refused at start claims the same store later, once the owner closes, deleting nothing", async () => {
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    const store = createFileModeRecordStore(dir);
    await expect(store.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    owner.send("release\n");
    expect(await owner.line()).toBe("RELEASED");
    const before = await readdir(dir);
    const lease = await store.claim();
    const after = await readdir(dir);
    for (const name of before) expect(after).toContain(name);
    expect((await store.load()).size).toBe(1);
    await lease.release();
    await kill(owner);
  }, 30_000);

  // LOCK_ON_SHARED_DB_FILE
  it("h: the owner using other files in the folder, including a database, keeps the lock", async () => {
    // A database that other code reads, writes, copies and backs up.
    const shared = join(dir, "index.db");
    const seed = new Database(shared);
    seed.exec("create table t (x)");
    seed.close();
    const owner = startChild(dir);
    expect(await owner.line()).toBe("READY");
    owner.send(`touch ${shared}\n`);
    expect(await owner.line()).toBe("TOUCHED");
    const second = startChild(dir);
    expect(await second.line()).toBe("OWNED");
    const contender = createFileModeRecordStore(dir);
    await expect(contender.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    // The owner is still the owner: it stops, and then the next one claims.
    await kill(owner);
    const next = startChild(dir);
    expect(await next.line()).toBe("READY");
  });

  it("i: only the lock module ever names the lock file, because any other open of it would drop the lock", async () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const found: string[] = [];
    const walk = async (folder: string): Promise<void> => {
      for (const entry of await readdir(folder, { withFileTypes: true })) {
        const path = join(folder, entry.name);
        if (entry.isDirectory()) await walk(path);
        else if (
          /\.tsx?$/.test(entry.name) &&
          !/\.test(-utils)?\.tsx?$/.test(entry.name) &&
          (await readFile(path, "utf8")).includes("mode-owner.lock")
        ) {
          found.push(path.slice(root.length));
        }
      }
    };
    await walk(root);
    // The file store names it in its header comment only.
    expect(found.sort()).toEqual([
      "account-mode/file-record-store.ts",
      "account-mode/owner-lock.ts",
    ]);
    const store = await readFile(
      join(root, "account-mode/file-record-store.ts"),
      "utf8",
    );
    const code = store
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    expect(code).not.toContain("mode-owner.lock");
  });

  it("save and load need a live lease, before the claim and after the release", async () => {
    const store = createFileModeRecordStore(dir);
    await expect(store.save("x", ON, null)).rejects.toThrow();
    await expect(store.load()).rejects.toThrow();
    const lease = await store.claim();
    await store.save("x", ON, null);
    await lease.release();
    await expect(store.save("x", ON, ON)).rejects.toThrow();
    await expect(store.load()).rejects.toThrow();
    expect(await readdir(dir)).not.toContain(".tmp-x");
  });

  it("a second claim on a store object that holds the folder is refused", async () => {
    const store = createFileModeRecordStore(dir);
    const lease = await store.claim();
    await expect(store.claim()).rejects.toBeInstanceOf(ModeStoreOwnedError);
    await lease.release();
    await (await store.claim()).release();
  });

  it("release waits for a save that is already running before it lets the folder go", async () => {
    const store = createFileModeRecordStore(dir);
    const lease = await store.claim();
    const saved = store.save("x", ON, null);
    await lease.release();
    // The save finished before the lock went: its record is on disk, and no
    // new owner could have written between.
    await expect(saved).resolves.toBeUndefined();
    const next = createFileModeRecordStore(dir);
    const second = await next.claim();
    expect((await next.load()).get("x")).toEqual(ON);
    await second.release();
  });
});

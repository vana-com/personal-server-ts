/**
 * The authority over the real file store: ownership, draining on close, and an
 * unreadable record. (The same authority rules run against the memory store in
 * the core package; these show the file store honors them on a disk.)
 */
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createModeAuthority,
  type ModeAuthority,
  type ModeAuthorityOptions,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const A = "0x1111111111111111111111111111111111111111";

const UNKNOWN = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};
const OWNED = {
  kind: "refuse",
  code: "ACCOUNT_MODE_STORE_OWNED",
  status: 503,
};

function evidence(owner: string, state: "on" | "off") {
  return {
    owner,
    authOwner: owner,
    state,
    fetchStartedAt: Date.now(),
    rawStatus: 200,
  };
}

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

const tick = (ms = 0) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/** The file store as one runtime sees it: it logs claims, saves and releases. */
function viewOf(
  dir: string,
  name: string,
  log: string[],
  hooks: { holdSaves?: () => Promise<void> } = {},
): ModeRecordStore {
  const inner = createFileModeRecordStore(dir);
  return {
    async claim() {
      const lease = await inner.claim();
      log.push(`${name}:claimed`);
      return {
        async release() {
          await lease.release();
          log.push(`${name}:released`);
        },
      };
    },
    load: () => inner.load(),
    async save(owner, next, expected) {
      await hooks.holdSaves?.();
      await inner.save(owner, next, expected);
      log.push(`${name}:save-landed`);
    },
  };
}

const before = (log: string[], first: string, second: string) => {
  expect(log, `${first} must be logged`).toContain(first);
  expect(log, `${second} must be logged`).toContain(second);
  expect(log.indexOf(first)).toBeLessThan(log.indexOf(second));
};

describe("the authority over the file store", () => {
  let dir: string;
  const authorities: ModeAuthority[] = [];
  async function boot(
    folder: string,
    bootId: string,
    extra: Partial<ModeAuthorityOptions> = {},
  ): Promise<ModeAuthority> {
    const authority = createModeAuthority({
      store: createFileModeRecordStore(folder),
      bootId,
      ...extra,
    });
    authorities.push(authority);
    await authority.ready;
    return authority;
  }
  beforeEach(async () => {
    dir = await mkdtemp(join(process.env.HOME ?? "", ".tmp", "mode-auth-"));
  });
  afterEach(async () => {
    for (const authority of authorities.splice(0)) {
      await authority.close().catch(() => {});
    }
    await rm(dir, { recursive: true, force: true });
  });

  it("two authorities on the folder: the second is refused and its Off never reaches the disk", async () => {
    const first = await boot(dir, "boot-1");
    const second = createModeAuthority({
      store: createFileModeRecordStore(dir),
      bootId: "boot-2",
    });
    authorities.push(second);
    await second.ready.catch(() => undefined);
    expect(await second.submitEvidence(evidence(A, "off"))).toMatchObject({
      code: "ACCOUNT_MODE_STORE_OWNED",
    });
    expect(second.admit(A, "op").kind).toBe("refuse");
    expect((await readdir(dir)).filter((n) => n.endsWith(".json"))).toEqual([]);
    await first.submitEvidence(evidence(A, "on"));
    expect(second.read(A)).toMatchObject({ code: "ACCOUNT_MODE_STORE_OWNED" });
  });

  // LATCH_NOT_DURABLE
  it("keeps an On across a restart that wipes the data folder", async () => {
    const modeDir = join(dir, "account-mode");
    const dataDir = join(dir, "data");
    const first = await boot(modeDir, "boot-1");
    await first.submitEvidence(evidence(A, "on"));
    await rm(dataDir, { recursive: true, force: true });
    await first.close();
    const second = await boot(modeDir, "boot-2");
    expect(second.read(A).kind).toBe("streams");
  });

  describe("close drains before it lets go of the folder", () => {
    // CLOSE_BEFORE_DRAIN
    it("keeps the folder while an admitted legacy write is in flight, and lands nothing after the next owner has it", async () => {
      const log: string[] = [];
      const first = createModeAuthority({
        store: viewOf(dir, "first", log),
        bootId: "boot-1",
      });
      authorities.push(first);
      await first.ready;
      await first.submitEvidence(evidence(A, "off"));
      const started = gate();
      const latch = gate();
      const write = first.commitLegacy(A, "op-1", async () => {
        started.open();
        await latch.opened;
        // The legacy sink's write, in the log with the stores' events.
        await writeFile(join(dir, "legacy-sink.txt"), "legacy write");
        log.push("first:legacy-write");
      });
      await started.opened;

      let closeDone = false;
      const closing = first.close().then(() => {
        closeDone = true;
      });
      await tick(20);

      // A second runtime is refused while the first still holds the folder.
      const second = createModeAuthority({
        store: viewOf(dir, "second", log),
        bootId: "boot-2",
      });
      authorities.push(second);
      await expect(second.ready).rejects.toThrow();
      expect(second.read(A)).toEqual(OWNED);
      expect(closeDone).toBe(false);

      // New work is refused as soon as close begins.
      let late = 0;
      expect(
        await first.commitLegacy(A, "op-2", () => {
          late += 1;
        }),
      ).toMatchObject({ ok: false });
      expect(late).toBe(0);

      latch.open();
      expect(await write).toEqual({ ok: true, value: undefined });
      await closing;

      // Only now does the next owner take the folder and latch On.
      expect((await second.submitEvidence(evidence(A, "on"))).kind).toBe(
        "streams",
      );
      before(log, "first:legacy-write", "first:released");
      before(log, "first:released", "second:claimed");
      expect(log.filter((e) => e === "first:legacy-write")).toHaveLength(1);
      expect(log.indexOf("first:legacy-write")).toBeLessThan(
        log.indexOf("second:save-landed"),
      );
    });

    it("keeps the folder while an evidence save is in flight, and lands nothing after the next owner has it", async () => {
      const log: string[] = [];
      const hold = gate();
      let holding = false;
      const first = createModeAuthority({
        store: viewOf(dir, "first", log, {
          holdSaves: () => (holding ? hold.opened : Promise.resolve()),
        }),
        bootId: "boot-1",
      });
      authorities.push(first);
      await first.ready;
      holding = true;
      const answer = first.submitEvidence(evidence(A, "off"));
      await tick(20);

      const closing = first.close();
      await tick(20);
      const second = createModeAuthority({
        store: viewOf(dir, "second", log),
        bootId: "boot-2",
      });
      authorities.push(second);
      await expect(second.ready).rejects.toThrow();
      expect(second.read(A)).toEqual(OWNED);

      hold.open();
      await answer;
      await closing;
      expect((await second.submitEvidence(evidence(A, "on"))).kind).toBe(
        "streams",
      );
      before(log, "first:save-landed", "first:released");
      before(log, "first:released", "second:claimed");
      // The second owner's On is the last word on the disk.
      expect(
        JSON.parse(await readFile(join(dir, `${A}.json`), "utf8")),
      ).toMatchObject({ switched: true });
      expect(log.filter((e) => e === "first:save-landed")).toHaveLength(1);
    });
  });

  // CLI_NEVER_RETRIES_CLAIM
  it("a runtime refused at start claims the folder from an ordinary read once the owner has closed, deleting nothing", async () => {
    let mono = 0;
    const clock = { mono: () => mono, wall: () => Date.now() };
    const owner = await boot(dir, "boot-1", { clock });
    await owner.submitEvidence(evidence(A, "on"));
    const refused = createModeAuthority({
      store: createFileModeRecordStore(dir),
      bootId: "boot-2",
      clock,
      ownerRetryMs: 1000,
    });
    authorities.push(refused);
    await expect(refused.ready).rejects.toThrow();
    expect(refused.read(A)).toEqual(OWNED);

    await owner.close();
    const filesBefore = (await readdir(dir)).sort();
    mono = 1500;
    expect(refused.read(A)).toEqual(OWNED);
    await tick(50);
    expect(refused.read(A)).toEqual({ kind: "streams", importRequired: false });
    for (const name of filesBefore) {
      expect(await readdir(dir)).toContain(name);
    }
  });

  describe("an unreadable record", () => {
    const owedOn = {
      hasLegacyFiles: (owner: string) => owner === A,
    };
    const corrupt = (text = "{corrupt") =>
      writeFile(join(dir, `${A}.json`), text);

    // QUARANTINE_FORGETS_ON
    it("cannot erase a saved On: an Off after the restart is refused and no legacy write lands", async () => {
      const first = await boot(dir, "boot-1", owedOn);
      expect(await first.submitEvidence(evidence(A, "on"))).toEqual({
        kind: "streams",
        importRequired: true,
      });
      await first.close();
      await corrupt();

      const restarted = await boot(dir, "boot-2", {
        hasLegacyFiles: () => false,
      });
      expect(restarted.read(A)).toEqual(UNKNOWN);
      expect(await restarted.submitEvidence(evidence(A, "off"))).toEqual(
        UNKNOWN,
      );
      let wrote = 0;
      expect(
        await restarted.commitLegacy(A, "op", () => {
          wrote += 1;
        }),
      ).toEqual({ ok: false, decision: UNKNOWN });
      expect(wrote).toBe(0);
      // The disk holds the tombstone, not an Off.
      expect(
        JSON.parse(await readFile(join(dir, `${A}.json`), "utf8")),
      ).toMatchObject({ switched: false, historyUnknown: true });

      // An On re-establishes the latch with the import owed.
      expect(await restarted.submitEvidence(evidence(A, "on"))).toEqual({
        kind: "streams",
        importRequired: true,
      });
      expect(await restarted.commitStream(A, "op", () => {})).toMatchObject({
        ok: false,
        decision: { code: "IMPORT_PENDING" },
      });
      const onDisk = JSON.parse(await readFile(join(dir, `${A}.json`), "utf8"));
      expect(onDisk).toMatchObject({ switched: true, importPending: true });
      expect(onDisk).not.toHaveProperty("historyUnknown");
    });

    it("stays unknown across more restarts until an On answers", async () => {
      const first = await boot(dir, "boot-1", owedOn);
      await first.submitEvidence(evidence(A, "on"));
      await first.close();
      await corrupt();
      for (let i = 0; i < 3; i += 1) {
        const runtime = await boot(dir, `boot-r${i}`);
        expect(runtime.read(A)).toEqual(UNKNOWN);
        expect(await runtime.submitEvidence(evidence(A, "off"))).toEqual(
          UNKNOWN,
        );
        await runtime.close();
      }
      const last = await boot(dir, "boot-last");
      expect(await last.submitEvidence(evidence(A, "on"))).toEqual({
        kind: "streams",
        importRequired: true,
      });
      await last.close();
      const after = await boot(dir, "boot-after");
      expect(after.read(A)).toEqual({ kind: "streams", importRequired: true });
    });

    it("is stable through a second corrupt-then-heal cycle", async () => {
      const first = await boot(dir, "boot-1", owedOn);
      await first.submitEvidence(evidence(A, "on"));
      await (async () => {
        await first.importDone(A);
        await first.close();
      })();
      for (const round of [1, 2]) {
        await corrupt(`garbage ${round}`);
        const runtime = await boot(dir, `boot-c${round}`);
        expect(await runtime.submitEvidence(evidence(A, "off"))).toEqual(
          UNKNOWN,
        );
        expect(await runtime.submitEvidence(evidence(A, "on"))).toEqual({
          kind: "streams",
          importRequired: true,
        });
        await runtime.importDone(A);
        await runtime.close();
        const healed = await boot(dir, `boot-h${round}`);
        expect(healed.read(A)).toEqual({
          kind: "streams",
          importRequired: false,
        });
        await healed.close();
      }
      const kept = await Promise.all(
        (await readdir(dir))
          .filter((n) => n.includes(".corrupt-"))
          .map((n) => readFile(join(dir, n), "utf8")),
      );
      expect(kept.sort()).toEqual(["garbage 1", "garbage 2"]);
    });
  });
});

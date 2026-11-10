/**
 * The legacy-write seal in persistent Lite storage, against a REAL mode
 * authority. Each test builds `createPersistentPsLiteStorage` over a
 * persistence adapter and a file store (not the memory test double), parks a
 * write inside the storage with a gate, and asks the authority for an On while
 * it is parked. What it proves, per sink:
 *
 * - a write that started before the On lands before the On is answered;
 * - a write that starts after the On is submitted is refused, and leaves no
 *   blob and no row (checked in the file store and in the persisted index);
 * - the mode record decides: the storage is never told about the switch.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { IDBFactory } from "fake-indexeddb";
import { LegacyWriteRefusedError } from "@opendatalabs/personal-server-ts-core/api";
import {
  createLegacyWriteSeal,
  type LegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  authorityHearing,
  fixedAccountStorageMode,
  fixedLegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createPersistentPsLiteStorage,
  type PsLiteDataFileStore,
  type PsLitePersistenceAdapter,
  type PsLiteStoragePort,
} from "./storage.js";
import {
  createMemoryPsLitePersistence,
  createMemoryPsLiteStagedFileStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import {
  importOuraBrowserRecords,
  type OuraBrowserImportInput,
} from "./oura-import.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SCOPE = "notes.entries";
const at = (n: number) => `2026-11-09T00:00:0${n}.000Z`;
const pathOf = (n: number) => `data/${SCOPE}/${at(n)}.json`;
const envelope = (n: number) =>
  createDataFileEnvelope(SCOPE, at(n), { entry: n });
const newEntry = (n: number, fileId: string | null = null) => ({
  fileId,
  scope: SCOPE,
  collectedAt: at(n),
});

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 10));

const submitOn = (authority: ModeAuthority) =>
  authority.submitEvidence({
    owner: OWNER,
    state: "on",
  });

/** A real, unsworn authority: it has heard nothing, so the owner is unknown. */
async function unheardAuthority(): Promise<ModeAuthority> {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  return authority;
}

interface Gate {
  /** Resolves when a call has reached the gate. */
  arrived: Promise<void>;
  release(): void;
}

/** Gates still parked when a test ends (an assertion failed): free them. */
const parked: Gate[] = [];
afterEach(() => {
  for (const gate of parked.splice(0)) gate.release();
});

type GateName = "files" | "persistence" | "commit" | "delete";

/**
 * A storage, its persistence and its file store, with one-shot gates: the
 * next call to a gated point parks until the test releases it.
 */
function createRig() {
  const armed = new Map<
    GateName,
    { arrive(): void; released: Promise<void> }
  >();
  function arm(name: GateName): Gate {
    let release!: () => void;
    let arrive!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (arrive = resolve));
    armed.set(name, { arrive, released });
    const gate = { arrived, release };
    parked.push(gate);
    return gate;
  }
  async function hit(name: GateName): Promise<void> {
    const gate = armed.get(name);
    if (!gate) return;
    armed.delete(name);
    gate.arrive();
    await gate.released;
  }

  const memory = createMemoryPsLitePersistence();
  const persistence: PsLitePersistenceAdapter = {
    ...memory,
    async write(state) {
      await hit("persistence");
      return memory.write(state);
    },
  };
  const staged = createMemoryPsLiteStagedFileStore();
  const aborted: string[] = [];
  const files: PsLiteDataFileStore = {
    ...staged,
    async writeEnvelope(path, value) {
      await hit("files");
      return staged.writeEnvelope(path, value);
    },
    async deleteEnvelope(path) {
      await hit("delete");
      return staged.deleteEnvelope(path);
    },
    async openEnvelopeWriter(path) {
      const writer = await staged.openEnvelopeWriter!(path);
      return {
        write: (text) => writer.write(text),
        async commit() {
          await hit("commit");
          return writer.commit();
        },
        async abort() {
          aborted.push(path);
          return writer.abort();
        },
      };
    },
  };

  return {
    arm,
    aborted,
    open: (seal: LegacyWriteSeal) =>
      createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
        seal,
      ),
    /** What a restart would see: the persisted index rows. */
    rows: async () => (await memory.read())?.entries ?? [],
    blobs: () => [...staged.files.keys()],
    /** Drop a stored blob behind the index's back, as a lost file would. */
    removeBlob: async (n: number) => {
      staged.files.delete(pathOf(n));
    },
    /** Has any trace of version `n` (a blob or an index row) become durable? */
    async trace(n: number) {
      const entries = (await memory.read())?.entries ?? [];
      return {
        blob: staged.files.has(pathOf(n)),
        row: entries.some((entry) => entry.path === pathOf(n)),
      };
    },
  };
}
type Rig = ReturnType<typeof createRig>;

async function expectNothing(rig: Rig, n: number) {
  expect(await rig.trace(n)).toEqual({ blob: false, row: false });
}

async function openOn(
  authority: ModeAuthority,
  rig: Rig,
): Promise<PsLiteStoragePort> {
  return rig.open(createLegacyWriteSeal({ authority, owner: OWNER }));
}

interface Sink {
  name: string;
  /** The gated point inside this sink's sealed write. */
  gate: GateName;
  start(storage: PsLiteStoragePort, n: number): Promise<unknown>;
  /** What of version `n` is durable once the write has landed. */
  landed(rig: Rig, n: number): Promise<boolean>;
}

const bothTraces = async (rig: Rig, n: number) => {
  const { blob, row } = await rig.trace(n);
  return blob && row;
};

const SINKS: Sink[] = [
  {
    name: "writeEnvelope",
    gate: "files",
    start: (storage, n) => storage.writeEnvelope(envelope(n)),
    landed: async (rig, n) => (await rig.trace(n)).blob,
  },
  {
    name: "writeEnvelopeAndIndex",
    gate: "files",
    start: (storage, n) =>
      storage.writeEnvelopeAndIndex!(envelope(n), newEntry(n)),
    landed: bothTraces,
  },
  {
    name: "insertEntry",
    gate: "persistence",
    start: async (storage, n) =>
      storage.insertEntry({
        ...newEntry(n),
        path: pathOf(n),
        sizeBytes: 1,
      }),
    landed: async (rig, n) => (await rig.trace(n)).row,
  },
  {
    name: "openVersionWriter.commit",
    gate: "commit",
    start: async (storage, n) => {
      const writer = await storage.openVersionWriter!(SCOPE, at(n));
      await writer.write(JSON.stringify(envelope(n)));
      return writer.commit({ fileId: null });
    },
    landed: bothTraces,
  },
];

const refusal = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return undefined;
};

describe.each(SINKS)("legacy-write seal: $name", (sink) => {
  it("lands a write that started before the On, before the On is answered", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    const storage = await openOn(authority, rig);

    const gate = rig.arm(sink.gate);
    const writing = sink.start(storage, 1);
    await gate.arrived;

    let answered = false;
    let landedWhenAnswered = false;
    const on = submitOn(authority).then(async () => {
      answered = true;
      landedWhenAnswered = await sink.landed(rig, 1);
    });
    await tick();
    expect(answered).toBe(false);

    gate.release();
    await writing;
    await on;
    expect(landedWhenAnswered).toBe(true);
    expect(authority.read(OWNER).kind).toBe("streams");
  });

  it("refuses a write queued after the On, and leaves no blob and no row", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    const storage = await openOn(authority, rig);

    const gate = rig.arm(sink.gate);
    const first = sink.start(storage, 1);
    await gate.arrived;
    const on = submitOn(authority);
    await tick();
    // The On is waiting for the first write; this one starts after it.
    const second = refusal(sink.start(storage, 2));
    await tick();

    gate.release();
    await first;
    await on;

    const error = await second;
    expect(error).toBeInstanceOf(LegacyWriteRefusedError);
    expect((error as LegacyWriteRefusedError).verdict).toBe("switched");
    expect((error as LegacyWriteRefusedError).response.status).toBe(426);
    expect(await sink.landed(rig, 1)).toBe(true);
    await expectNothing(rig, 2);
    // A restart sees the same: nothing of the refused write.
    expect((await rig.rows()).some((row) => row.path === pathOf(2))).toBe(
      false,
    );
    expect(rig.blobs()).not.toContain(pathOf(2));
  });

  it("refuses a write that starts after the On is answered, and leaves nothing", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    const storage = await openOn(authority, rig);
    await sink.start(storage, 1);

    await submitOn(authority);
    const error = await refusal(sink.start(storage, 2));

    expect(error).toBeInstanceOf(LegacyWriteRefusedError);
    expect((error as LegacyWriteRefusedError).response.status).toBe(426);
    await expectNothing(rig, 2);
    expect(await sink.landed(rig, 1)).toBe(true);
  });

  it("does not nest: an On queued mid-flight and a later write both settle", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    const storage = await openOn(authority, rig);

    const gate = rig.arm(sink.gate);
    const first = sink.start(storage, 1);
    await gate.arrived;
    const on = submitOn(authority);
    await tick();
    const later = refusal(sink.start(storage, 2));
    await tick();
    gate.release();

    // A sealed call made from inside a sealed call would wait behind the On
    // that waits for it, and none of these would settle.
    await Promise.all([first, on, later]);
    expect(await later).toBeInstanceOf(LegacyWriteRefusedError);
  });

  describe("per mode", () => {
    it("allows an unswitched account", async () => {
      const rig = createRig();
      const storage = await rig.open(fixedLegacyWriteSeal("unswitched"));
      await sink.start(storage, 1);
      expect(await sink.landed(rig, 1)).toBe(true);
    });

    it("refuses a switched account with 426 and leaves nothing", async () => {
      const rig = createRig();
      const storage = await rig.open(fixedLegacyWriteSeal("switched"));
      const error = await refusal(sink.start(storage, 1));
      expect(error).toBeInstanceOf(LegacyWriteRefusedError);
      expect((error as LegacyWriteRefusedError).response.status).toBe(426);
      await expectNothing(rig, 1);
    });

    it("refuses an unknown mode with 503 and leaves nothing", async () => {
      const rig = createRig();
      const storage = await rig.open(fixedLegacyWriteSeal("unknown"));
      const error = await refusal(sink.start(storage, 1));
      expect(error).toBeInstanceOf(LegacyWriteRefusedError);
      expect((error as LegacyWriteRefusedError).verdict).toBe("unknown");
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
      await expectNothing(rig, 1);
    });

    it("refuses with 503 when the authority has heard nothing for the owner", async () => {
      const rig = createRig();
      const storage = await openOn(await unheardAuthority(), rig);
      const error = await refusal(sink.start(storage, 1));
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
      await expectNothing(rig, 1);
    });

    it("refuses with 503 when the storage has no owner, whatever the authority holds", async () => {
      const rig = createRig();
      const storage = await rig.open(
        createLegacyWriteSeal({
          authority: await authorityHearing(OWNER, "off"),
          owner: undefined,
        }),
      );
      const error = await refusal(sink.start(storage, 1));
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
      await expectNothing(rig, 1);
    });
  });
});

describe("a refused streamed commit", () => {
  it("aborts the staged file, so nothing is left at its path", async () => {
    const rig = createRig();
    const storage = await rig.open(fixedLegacyWriteSeal("switched"));
    const writer = await storage.openVersionWriter!(SCOPE, at(1));
    await writer.write(JSON.stringify(envelope(1)));
    await expect(writer.commit({ fileId: null })).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
    expect(rig.aborted).toContain(pathOf(1));
    await expectNothing(rig, 1);
  });
});

/** Removals: one entry per pure-removal method of the storage port. */
interface Removal {
  name: string;
  run(storage: PsLiteStoragePort): Promise<unknown>;
  /** Same call, passing the hold of an enclosing `commit`. */
  runHeld(
    storage: PsLiteStoragePort,
    hold: Parameters<Parameters<LegacyWriteSeal["commit"]>[0]>[0],
  ): Promise<unknown>;
  /** Make the removal's precondition hold. */
  prepare?(rig: Rig): Promise<void>;
}

const FENCE = (id: number, n: number) => ({ id, path: pathOf(n) });

const REMOVALS: Removal[] = [
  {
    name: "deleteScope",
    run: (storage) => storage.deleteScope(SCOPE),
    runHeld: (storage, hold) => storage.deleteScope(SCOPE, hold),
  },
  {
    name: "deleteVersion",
    run: (storage) => storage.deleteVersion(SCOPE, at(1)),
    runHeld: (storage, hold) =>
      storage.deleteVersion(SCOPE, at(1), undefined, hold),
  },
  {
    name: "deleteByFileId",
    run: (storage) => storage.deleteByFileId("file-1"),
    runHeld: (storage, hold) => storage.deleteByFileId("file-1", hold),
  },
  {
    name: "deleteVersionIfEnvelopeMissing",
    run: (storage) =>
      storage.deleteVersionIfEnvelopeMissing!(SCOPE, at(1), FENCE(1, 1)),
    runHeld: (storage, hold) =>
      storage.deleteVersionIfEnvelopeMissing!(SCOPE, at(1), FENCE(1, 1), hold),
    // Only while the envelope file is gone.
    prepare: async (rig) => {
      await rig.removeBlob(1);
    },
  },
];

/** Seed one stored version (`file-1`, row id 1) through an open seal. */
async function seed(rig: Rig): Promise<void> {
  const storage = await rig.open(fixedLegacyWriteSeal("unswitched"));
  await storage.writeEnvelopeAndIndex!(envelope(1), newEntry(1, "file-1"));
  expect((await rig.rows()).map((row) => row.id)).toEqual([1]);
}

describe.each(REMOVALS)("legacy-write seal removal: $name", (removal) => {
  it.each(["switched", "unknown", "unswitched"] as const)(
    "is admitted in a %s account",
    async (mode) => {
      const rig = createRig();
      await seed(rig);
      await removal.prepare?.(rig);
      const storage = await rig.open(fixedLegacyWriteSeal(mode));
      await removal.run(storage);
      expect(await rig.rows()).toEqual([]);
    },
  );

  it("runs under the shared lock: an On waits for a removal in flight", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    await seed(rig);
    await removal.prepare?.(rig);
    const storage = await openOn(authority, rig);

    const gate = rig.arm("delete");
    const removing = removal.run(storage);
    await gate.arrived;

    let answered = false;
    let rowsWhenAnswered = -1;
    const on = submitOn(authority).then(async () => {
      answered = true;
      rowsWhenAnswered = (await rig.rows()).length;
    });
    await tick();
    expect(answered).toBe(false);

    gate.release();
    await removing;
    await on;
    expect(rowsWhenAnswered).toBe(0);
  });

  it("is admitted after the On is answered, and does not deadlock on a queued On when it holds the lock already", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const seal = createLegacyWriteSeal({ authority, owner: OWNER });
    const rig = createRig();
    await seed(rig);
    await removal.prepare?.(rig);
    const storage = await rig.open(seal);

    // A route that decides and removes under one `commit` hands its hold on.
    // It reaches the removal only after the On is queued: a removal that took
    // the lock again would queue behind that On, which waits for this commit.
    let inside!: () => void;
    let proceed!: () => void;
    const insideCommit = new Promise<void>((resolve) => (inside = resolve));
    const proceeding = new Promise<void>((resolve) => (proceed = resolve));
    parked.push({ arrived: insideCommit, release: proceed });
    const removing = seal.commit(async (hold) => {
      inside();
      await proceeding;
      return removal.runHeld(storage, hold);
    });
    await insideCommit;
    const on = submitOn(authority);
    await tick();
    const later = refusal(
      storage.writeEnvelopeAndIndex!(envelope(2), newEntry(2)),
    );
    await tick();
    proceed();

    await Promise.all([removing, on, later]);
    expect(await later).toBeInstanceOf(LegacyWriteRefusedError);
    expect(await rig.rows()).toEqual([]);
    await expectNothing(rig, 2);
  });
});

describe("what the seal leaves alone", () => {
  it("lets a switched account update metadata and sidecars", async () => {
    const rig = createRig();
    await seed(rig);
    const storage = await rig.open(fixedLegacyWriteSeal("switched"));
    const path = pathOf(1);

    await expect(storage.updateFileId(path, "file-2")).resolves.toBe(true);
    await expect(storage.updateDataPointId(path, "dp-1")).resolves.toBe(true);
    await expect(storage.updateEntryVersion(path, 7)).resolves.toBe(true);
    await storage.writeFirstSeenLedger!(SCOPE, { through: at(1) });
    await expect(storage.readFirstSeenLedger!(SCOPE)).resolves.toEqual({
      through: at(1),
    });
    expect((await rig.rows())[0]).toMatchObject({
      fileId: "file-2",
      dataPointId: "dp-1",
      version: 7,
    });
  });

  it("keeps reads open in every mode", async () => {
    const rig = createRig();
    await seed(rig);
    for (const mode of ["switched", "unknown"] as const) {
      const storage = await rig.open(fixedLegacyWriteSeal(mode));
      expect(storage.countVersions(SCOPE)).toBe(1);
      await expect(storage.readEnvelope(SCOPE, at(1))).resolves.toBeDefined();
    }
  });
});

describe("the in-memory test storage", () => {
  it("takes an optional seal, and refuses a switched write through it", async () => {
    const storage = createMemoryPsLiteStorage({
      legacyWriteSeal: fixedLegacyWriteSeal("switched"),
    });
    await expect(storage.writeEnvelope(envelope(1))).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
    await expect(
      Promise.resolve(
        storage.insertEntry({ ...newEntry(1), path: pathOf(1), sizeBytes: 1 }),
      ),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    expect(storage.countVersions(SCOPE)).toBe(0);
  });

  it("stays unsealed without one", async () => {
    const storage = createMemoryPsLiteStorage();
    storage.insertEntry({ ...newEntry(1), path: pathOf(1), sizeBytes: 1 });
    expect(storage.countVersions(SCOPE)).toBe(1);
  });
});

describe("the default runtime wires one authority into the storage", () => {
  it("answers a legacy write with 426 after the authority hears On, and stores nothing", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    try {
      const account = privateKeyToAccount(`0x${"22".repeat(32)}`);
      const ownerSignature = await signOwnerMasterKey(account);
      const built = await createIndexedDbPsLiteRuntime({
        ownerAddress: account.address,
        ownerSignature,
        accountModeStore: createMemoryModeRecordStore(),
        dbName: "legacy-write-seal-runtime",
        gateway: createMockPsLiteGateway(),
        auth: createBearerTokenPsLiteAuth({
          ownerToken: "owner-token",
          builderToken: "builder-token",
        }),
        active: true,
        configDefaults: {
          gateway: { url: "https://gateway.local" },
          sync: { enabled: false },
        },
      });
      const evidence = (state: "off" | "on") => ({
        owner: account.address,
        state,
      });
      const post = () =>
        built.runtime.fetch(
          new Request("https://ps.local/v1/data/instagram.profile", {
            method: "POST",
            headers: {
              Authorization: "Bearer owner-token",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ username: "lite_user" }),
          }),
        );
      await built.accountModeAuthority.submitEvidence(evidence("off"));
      expect((await post()).status).toBe(201);

      await built.accountModeAuthority.submitEvidence(evidence("on"));
      const refused = await post();
      expect(refused.status).toBe(426);
      expect(built.storage.countVersions("instagram.profile")).toBe(1);
      // The storage was never told: it reads the same authority.
      expect(
        (built.storage as PsLiteStoragePort).legacyWriteSeal.verdict(),
      ).toBe("switched");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("an Oura browser import that straddles the switch", () => {
  const streams = ["sleep", "readiness", "activity"] as const;
  const input = () =>
    ({
      selection: { streams: streams.map((name) => ({ name })) },
      collectedAt: "2026-10-15T00:00:00.000Z",
      records: streams.map((stream) => ({
        stream,
        data: {
          id: `${stream}-1`,
          day: "2026-10-13",
          score: 80,
          ...(stream === "sleep"
            ? { record_type: "daily_score", sleep_score: 80 }
            : {}),
        },
      })),
      completion: {
        streams: streams.map((name) => ({
          stream: name,
          status: "complete",
          recordCount: 1,
        })),
      },
    }) as unknown as OuraBrowserImportInput;

  it("stops at the switch: what was stored before it stays, nothing after it", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const rig = createRig();
    const storage = await openOn(authority, rig);
    // The importer's own checks see a stale unswitched account; only the
    // storage's seal reads the record, so it alone can stop the batch.
    let installs = 0;
    const flipping = new Proxy(storage, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (typeof value !== "function") return value;
        if (property !== "writeEnvelopeAndIndex") return value.bind(target);
        return async (...args: unknown[]) => {
          const result = await value.apply(target, args);
          if (++installs === 1) await submitOn(authority);
          return result;
        };
      },
    });

    const outcome = await importOuraBrowserRecords(flipping, input(), {
      accountStorageMode: fixedAccountStorageMode("unswitched"),
    }).catch((error: unknown) => error);
    // The importer names the seal's refusal and the stream it stopped at.
    expect(outcome).toMatchObject({
      ok: false,
      reason: "update_required",
      scope: "oura.readiness",
    });
    const stored = streams.filter(
      (stream) => storage.countVersions(`oura.${stream}`) > 0,
    );
    expect(stored).toHaveLength(1);
  });
});

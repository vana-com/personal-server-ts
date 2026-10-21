import { afterEach, describe, expect, it, vi } from "vitest";
import {
  mkdtemp,
  readFile,
  writeFile,
  rename,
  rm,
  link,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keccak256, stringToHex } from "viem";
import { z } from "zod";
import {
  createDataFileEnvelope,
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import type { VersionInventoryClient } from "./version-inventory.js";
import {
  additionsLedgerScope,
  createDurableAdditions,
  type DurableAdditionsOptions,
} from "./durable.js";
import type { ByteBudget } from "./budget.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SOURCE = "test.conversations";
const MASTER_KEY = new Uint8Array(32).fill(17);
const T1 = "2026-10-01T12:00:00.000Z";
const T2 = "2026-10-02T12:00:00.000Z";
const T3 = "2026-10-03T12:00:00.000Z";
const T4 = "2026-10-04T12:00:00.000Z";
const QUERY = { timezone: "UTC", days: 4, now: new Date(T4) };
const slotSchema = z.object({
  expectedVersion: z.string(),
  dataHash: z.string(),
  metadataHash: z.string(),
  status: z.string(),
  addedAt: z.string(),
  isTombstone: z.boolean(),
});
const headSchema = slotSchema
  .omit({ addedAt: true, isTombstone: true })
  .extend({ deletedAt: z.string().nullable() });
const registrySchema = z.record(
  z.string(),
  z.object({ head: headSchema.nullable(), versions: z.array(slotSchema) }),
);
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

function password(scope: string) {
  return Array.from(deriveScopeKey(MASTER_KEY, scope), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** Disk-backed fake Gateway ports, not a SQL/concurrency or real Gateway authentication proof. */
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "durable-additions-"));
  roots.push(root);
  const registryPath = join(root, "registry.json");
  await writeFile(registryPath, "{}");
  let registryWrites = Promise.resolve();
  let fileSequence = 0;
  const readRawRegistry = async () =>
    registrySchema.parse(JSON.parse(await readFile(registryPath, "utf8")));
  const readRegistry = async () => {
    await registryWrites;
    return readRawRegistry();
  };
  async function atomicWrite(path: string, bytes: Uint8Array | string) {
    const temporary = `${path}.write-${fileSequence++}`;
    await writeFile(temporary, bytes);
    await rename(temporary, path);
  }
  const blobPath = (key: string) =>
    join(root, `${encodeURIComponent(key)}.encrypted`);
  function storage(): StorageAdapter {
    return {
      urlForKey: blobPath,
      async upload(key, bytes) {
        const path = blobPath(key);
        await atomicWrite(path, bytes);
        return path;
      },
      async uploadCreateOnly(key, bytes) {
        const path = blobPath(key);
        const candidate = `${path}.candidate-${fileSequence++}`;
        await writeFile(candidate, bytes);
        try {
          await link(candidate, path);
        } catch (error) {
          if (
            !(error instanceof Error) ||
            !("code" in error) ||
            error.code !== "EEXIST"
          )
            throw error;
          if (!Buffer.from(await readFile(path)).equals(Buffer.from(bytes)))
            throw new StoredBlobConflictError(key);
        } finally {
          await rm(candidate);
        }
        return path;
      },
      async download(path) {
        return new Uint8Array(await readFile(path));
      },
      async delete(path) {
        try {
          await rm(path);
          return true;
        } catch {
          return false;
        }
      },
      async exists(path) {
        try {
          await readFile(path);
          return true;
        } catch {
          return false;
        }
      },
    };
  }
  async function setSlot(
    scope: string,
    slot: z.infer<typeof slotSchema>,
    deletedAt: string | null = null,
  ) {
    // Serialize fake DB statements, not actor recovery: independent registrations remain last-writer wins.
    const pending = registryWrites.then(async () => {
      const registry = await readRawRegistry();
      const previous = registry[scope]?.versions ?? [];
      const versions = [
        ...previous.filter(
          (row) => row.expectedVersion !== slot.expectedVersion,
        ),
        slot,
      ].sort((a, b) =>
        BigInt(a.expectedVersion) < BigInt(b.expectedVersion) ? -1 : 1,
      );
      registry[scope] = { versions, head: { ...slot, deletedAt } };
      await atomicWrite(registryPath, JSON.stringify(registry));
    });
    registryWrites = pending.catch(() => {});
    return pending;
  }
  async function put(
    scope: string,
    expectedVersion: string,
    collectedAt: string,
    data: Record<string, unknown>,
    createOnly = false,
  ) {
    const plaintext = new TextEncoder().encode(
      JSON.stringify(createDataFileEnvelope(scope, collectedAt, data)),
    );
    const encrypted = await encryptWithPassword(plaintext, password(scope));
    const adapter = storage();
    await (createOnly ? adapter.uploadCreateOnly! : adapter.upload)(
      `${scope}/${expectedVersion}`,
      encrypted,
    );
    await setSlot(scope, {
      expectedVersion,
      dataHash: keccak256(plaintext),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope,
            collectedAt,
            sizeBytes: encrypted.byteLength,
          }),
        ),
      ),
      status: "confirmed",
      addedAt: "2026-10-09T00:00:00.000Z",
      isTombstone: false,
    });
    return {
      encryptedBytes: encrypted.byteLength,
      plaintextBytes: plaintext.byteLength,
    };
  }
  async function source(version: string, collectedAt: string, ids: string[]) {
    return put(SOURCE, version, collectedAt, {
      conversations: ids.map((id) => ({ id })),
    });
  }
  async function tombstone(version: string) {
    await setSlot(
      SOURCE,
      {
        expectedVersion: version,
        dataHash:
          "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
        metadataHash:
          "0xc5255a141acd6a2ae55971b62c0a85977c2511989dc114ad2abc2b7644f57d90",
        status: "confirmed",
        addedAt: T2,
        isTombstone: true,
      },
      T2,
    );
  }
  async function document(scope: string) {
    const registry = await readRegistry();
    const version = registry[scope]?.head?.expectedVersion;
    if (!version) throw new Error("Fixture has no document");
    const bytes = await storage().download(blobPath(`${scope}/${version}`));
    return z
      .record(z.string(), z.unknown())
      .parse(
        JSON.parse(
          new TextDecoder().decode(
            await decryptWithPassword(bytes, password(scope)),
          ),
        ),
      ).data;
  }
  function actor(
    budgets: Partial<DurableAdditionsOptions> = {},
    beforeInventoryRead?: (scope: string) => Promise<void>,
  ) {
    // Each actor constructs fresh ports and discovers state solely from the shared files.
    const inventory: VersionInventoryClient = {
      async list(scope) {
        await beforeInventoryRead?.(scope);
        return (await readRegistry())[scope] ?? { head: null, versions: [] };
      },
      async listScopes() {
        return Object.keys(await readRegistry()).filter(
          (scope) => !scope.startsWith("vana.system."),
        );
      },
      async page() {
        throw new Error("Fixture exposes the completed inventory port only");
      },
    };
    return createDurableAdditions({
      ownerAddress: OWNER,
      network: "chain:1:https://gateway.example",
      inventory,
      storageAdapter: storage(),
      masterKey: MASTER_KEY,
      signer: {
        async signAddData() {
          return "0x1234";
        },
      },
      gateway: {
        async registerDataPoint(params) {
          await setSlot(params.scope, {
            ...params,
            status: "confirmed",
            addedAt: T4,
            isTombstone: false,
          });
          return { expectedVersion: params.expectedVersion };
        },
      },
      ...budgets,
    });
  }
  function boundedActor(
    input: {
      beforeDownload?: (key: string, budget: ByteBudget) => Promise<void>;
      proof?: (proof: {
        expectedVersion: string;
        dataHash: string;
        metadataHash: string;
      }) => { expectedVersion: string; dataHash: string; metadataHash: string };
      options?: Partial<DurableAdditionsOptions>;
    } = {},
  ) {
    const events: string[] = [];
    const adapter = storage();
    const service = actor({
      byteBudget: 2 * 1024 * 1024,
      storageAdapter: {
        ...adapter,
        async downloadBounded(key, budget) {
          budget.charge();
          events.push(`download:${key}`);
          await input.beforeDownload?.(key, budget);
          budget.charge();
          const bytes = new Uint8Array(
            await readFile(key, { signal: budget.signal }),
          );
          budget.charge(bytes.byteLength * 2);
          return bytes;
        },
      },
      boundedWork: {
        async decrypt(bytes, key, budget) {
          budget.charge(bytes.byteLength * 8);
          const plaintext = await decryptWithPassword(bytes, key);
          budget.charge(plaintext.byteLength);
          return plaintext;
        },
        async publish(scope, data, budget) {
          budget.charge();
          events.push(`publish:${scope}`);
          const previous =
            (await readRegistry())[scope]?.versions.at(-1)?.expectedVersion ??
            "0";
          const expectedVersion = String(BigInt(previous) + 1n);
          budget.charge(JSON.stringify(data).length * 16);
          await put(scope, expectedVersion, T4, data, true);
          budget.charge();
          const slot = (await readRegistry())[scope].versions.at(-1)!;
          const proof = {
            expectedVersion,
            dataHash: slot.dataHash,
            metadataHash: slot.metadataHash,
          };
          return input.proof?.(proof) ?? proof;
        },
        async confirmed(scope, budget) {
          budget.charge();
          events.push(`confirmed:${scope}`);
        },
      },
      ...input.options,
    });
    return { service, events };
  }
  return {
    root,
    actor,
    source,
    tombstone,
    put,
    document,
    readRegistry,
    blobPath,
    setSlot,
    boundedActor,
    storage,
  };
}

describe("durable owner additions recovery", () => {
  it("binds portable counts to historical commitments when the head version is unchanged", async () => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    await f.source("2", T2, ["a", "b"]);
    const first = await f.actor().summarize(QUERY);
    expect(first.inventory?.[SOURCE]).toMatch(/^0x[0-9a-f]{64}$/);
    const head = (await f.readRegistry())[SOURCE].versions[1];
    // A reorg permits an older confirmed slot to be replaced and settled again;
    // the later head can retain its exact content and version.
    await f.source("1", T1, ["a", "b"]);
    await f.setSlot(SOURCE, head);
    const next = await f.actor().summarize(QUERY);
    expect(next.through).toEqual(first.through);
    expect(next.inventory?.[SOURCE]).not.toBe(first.inventory?.[SOURCE]);
    expect(next.days.map((day) => day.added)).toEqual([2, 0, 0, 0]);
    expect(await f.document("vana.system.additions")).toMatchObject({
      inventory: next.inventory,
    });
  });

  it("restarts from encrypted remote ledgers with no local sidecar or original source blobs", async () => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    await f.source("2", T2, ["a", "b"]);
    const desktop = f.actor();
    const first = await desktop.summarize(QUERY);
    expect(first).toMatchObject({
      coverage: "complete",
      total: 2,
      through: { [SOURCE]: "2" },
      days: [
        { date: "2026-10-01", added: 1 },
        { date: "2026-10-02", added: 1 },
        { date: "2026-10-03", added: 0 },
        { date: "2026-10-04", added: 0 },
      ],
    });
    await rm(f.blobPath(`${SOURCE}/1`));
    await rm(f.blobPath(`${SOURCE}/2`));
    const teeAfterRestart = f.actor();
    expect(await teeAfterRestart.summarize(QUERY)).toEqual(first);
  });

  it("repairs a stale actor's lower-prefix ledger after another actor advanced it", async () => {
    const f = await fixture();
    const desktop = f.actor();
    const tee = f.actor();
    await f.source("1", T1, ["a"]);
    await desktop.summarize(QUERY);
    const oldDocument = z
      .record(z.string(), z.unknown())
      .parse(await f.document(additionsLedgerScope(SOURCE)));
    await f.source("2", T2, ["a", "b"]);
    expect((await tee.summarize(QUERY)).through).toEqual({ [SOURCE]: "2" });
    await rm(f.blobPath(`${SOURCE}/1`));
    await rm(f.blobPath(`${SOURCE}/2`));
    // Simulate a delayed registration of the older whole-document writer.
    await f.put(additionsLedgerScope(SOURCE), "3", T3, oldDocument);
    const repaired = await desktop.summarize(QUERY);
    expect(repaired).toMatchObject({
      coverage: "complete",
      total: 2,
      through: { [SOURCE]: "2" },
    });
    expect(repaired.days.map((day) => day.added)).toEqual([1, 1, 0, 0]);
    expect(await f.document(additionsLedgerScope(SOURCE))).toMatchObject({
      through: "2",
    });
  });

  it("invalidates cached first-seen dates when commitments change at the same source version", async () => {
    const f = await fixture();
    await f.source("1", T1, ["a", "b"]);
    await f.source("2", T2, ["b", "c"]);
    expect(
      (await f.actor().summarize(QUERY)).days.map((day) => day.added),
    ).toEqual([2, 1, 0, 0]);
    await f.source("1", T1, ["x"]);
    // Replacement of a retained slot need not move the head; restore the current head at v2.
    await f.source("2", T2, ["b", "c"]);
    const repaired = await f.actor().summarize(QUERY);
    expect(repaired).toMatchObject({
      coverage: "complete",
      total: 2,
      through: { [SOURCE]: "2" },
    });
    expect(repaired.days.map((day) => day.added)).toEqual([1, 2, 0, 0]);
  });

  it.each(["missing", "data hash", "metadata hash"])(
    "keeps %s source evidence unresolved",
    async (failure) => {
      const f = await fixture();
      await f.source("1", T1, ["a"]);
      const key = f.blobPath(`${SOURCE}/1`);
      if (failure === "missing") await rm(key);
      else {
        const envelope = createDataFileEnvelope(
          SOURCE,
          failure === "metadata hash" ? T2 : T1,
          { conversations: [{ id: "forged" }] },
        );
        const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
        const encrypted = await encryptWithPassword(
          plaintext,
          password(SOURCE),
        );
        await writeFile(key, encrypted);
        if (failure === "metadata hash") {
          const registry = await f.readRegistry();
          const slot = registry[SOURCE]?.versions[0];
          const head = registry[SOURCE]?.head;
          if (!slot || !head) throw new Error("Fixture missing source");
          slot.dataHash = keccak256(plaintext);
          head.dataHash = slot.dataHash;
          await writeFile(
            join(f.root, "registry.json"),
            JSON.stringify(registry),
          );
        }
      }
      const summary = await f.actor().summarize(QUERY);
      expect(summary).toMatchObject({
        coverage: "partial",
        total: 0,
        through: { [SOURCE]: "0" },
      });
      expect(summary.days.map((day) => day.added)).toEqual([0, 0, 0, 0]);
    },
  );

  it.each([T4, T3, T2])(
    "suppresses reimport baseline identities when the next timestamp is %s",
    async (nextTime) => {
      const f = await fixture();
      await f.source("1", T1, ["old"]);
      await f.actor().summarize(QUERY);
      await f.tombstone("2");
      expect(await f.actor().summarize(QUERY)).toMatchObject({
        coverage: "complete",
        total: 0,
      });
      await f.source("3", T3, ["old", "baseline"]);
      await f.source("4", nextTime, ["old", "baseline", "new"]);
      const summary = await f.actor().summarize(QUERY);
      expect(summary).toMatchObject({
        coverage: "complete",
        total: 3,
        partial: true,
        through: { [SOURCE]: "4" },
      });
      expect(summary.days).toEqual([
        { date: "2026-10-01", added: 0 },
        { date: "2026-10-02", added: nextTime === T2 ? 1 : 0 },
        { date: "2026-10-03", added: nextTime === T3 ? 1 : 0 },
        { date: "2026-10-04", added: nextTime === T4 ? 1 : 0 },
      ]);
    },
  );

  it("refuses budgeted work without cancellable crypto and lets a full actor finish", async () => {
    const f = await fixture();
    const first = await f.source("1", T1, ["a"]);
    await f.source("2", T2, ["a", "b"]);
    const lite = f.actor({
      byteBudget: first.encryptedBytes + first.plaintextBytes + 1,
    });
    const progress = await lite.summarize(QUERY);
    expect(progress).toMatchObject({
      coverage: "unavailable",
      total: 0,
      through: {},
    });
    expect(await f.readRegistry()).not.toHaveProperty(
      additionsLedgerScope(SOURCE),
    );
    expect(progress.days.map((day) => day.added)).toEqual([0, 0, 0, 0]);
    expect(await f.actor().summarize(QUERY)).toMatchObject({
      coverage: "complete",
      total: 2,
      through: { [SOURCE]: "2" },
    });
  });
});

it("honors cancellation and uses only bounded registry deletion for durable-only cleanup", async () => {
  const f = await fixture();
  const ordinary = vi.fn(async () => {});
  const bounded = vi.fn(async (_scope: string, _budget: ByteBudget) => {});
  const actor = f.actor({
    deleteSystemScope: ordinary,
    deleteSystemScopeBounded: bounded,
  });
  const aborted = AbortSignal.abort(new Error("cancel deletion"));
  await expect(
    actor.deleteScope(SOURCE, { durableOnly: true, signal: aborted }),
  ).rejects.toThrow("cancel deletion");
  expect(ordinary).not.toHaveBeenCalled();
  expect(bounded).not.toHaveBeenCalled();
  await actor.deleteScope(SOURCE, { durableOnly: true });
  expect(bounded.mock.calls.map((call) => call[0])).toEqual([
    additionsLedgerScope(SOURCE),
    "vana.system.additions",
  ]);
  expect(ordinary).not.toHaveBeenCalled();
  await expect(
    f
      .actor({ deleteSystemScope: ordinary })
      .deleteScope(SOURCE, { durableOnly: true }),
  ).rejects.toThrow("Bounded additions deletion is unavailable");
  expect(ordinary).not.toHaveBeenCalled();
});

it("persists a bounded prefix when the next source unit exhausts its allowance and resumes after pruning", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.source("2", T2, ["a", "b"]);
  const first = f.boundedActor({
    beforeDownload: async (key, budget) => {
      if (key === f.blobPath(`${SOURCE}/2`))
        budget.charge(budget.remaining + 1);
    },
  });
  expect(await first.service.summarize(QUERY)).toMatchObject({
    coverage: "behind",
    total: 1,
    through: { [SOURCE]: "1" },
  });
  expect(first.events).toContain(`confirmed:${additionsLedgerScope(SOURCE)}`);
  expect(await f.document(additionsLedgerScope(SOURCE))).toMatchObject({
    through: "1",
    currentTotal: 1,
  });
  await rm(f.blobPath(`${SOURCE}/1`));
  expect(await f.boundedActor().service.summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
});

it("advances bounded recovery without rereading all older checkpoints", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.actor().summarize(QUERY);
  const scope = additionsLedgerScope(SOURCE);
  const document = z
    .record(z.string(), z.unknown())
    .parse(await f.document(scope));
  for (let version = 2; version <= 20; version++)
    await f.put(scope, String(version), T4, document);
  await f.source("2", T2, ["a", "b"]);
  const actor = f.boundedActor({
    beforeDownload: async (key, budget) => {
      if (
        key.startsWith(f.blobPath(`${scope}/`).slice(0, -".encrypted".length))
      )
        budget.charge(150_000);
    },
  });
  expect(await actor.service.summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
});

it("preserves publication capacity on bounded fallback overflow and resumes only from longer evidence", async () => {
  const f = await fixture();
  const scope = additionsLedgerScope(SOURCE);
  await f.source("1", T1, ["a"]);
  await f.actor().summarize(QUERY);
  const stale = z
    .record(z.string(), z.unknown())
    .parse(await f.document(scope));
  await f.source("2", T2, ["a", "b"]);
  await f.source("3", T3, ["a", "b", "c"]);
  await f.actor().summarize(QUERY);
  await f.source("4", T4, ["a", "b", "c", "d"]);
  await f.put(scope, "3", T4, stale);
  await rm(f.blobPath(`${SOURCE}/1`));
  await rm(f.blobPath(`${SOURCE}/3`));
  const limited = f.boundedActor({
    beforeDownload: async (key, budget) => {
      if (key === f.blobPath(`${scope}/2`)) {
        budget.charge(budget.remaining);
        budget.charge(1);
      }
    },
  });
  expect(await limited.service.summarize(QUERY)).toMatchObject({
    coverage: "behind",
    total: 2,
    through: { [SOURCE]: "2" },
  });
  expect(limited.events).toContain(`confirmed:${scope}`);
  expect(await f.document(scope)).toMatchObject({
    through: "2",
    currentTotal: 2,
  });
  await rm(f.blobPath(`${SOURCE}/2`));
  const downloaded: string[] = [];
  const restarted = f.boundedActor({
    beforeDownload: async (key) => {
      downloaded.push(key);
    },
  });
  expect(await restarted.service.summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 4,
    through: { [SOURCE]: "4" },
  });
  expect(downloaded).not.toContain(f.blobPath(`${SOURCE}/2`));
  expect(
    downloaded.filter((key) => key === f.blobPath(`${SOURCE}/3`)),
  ).toHaveLength(1);
});

it.each(["proof", "content"])(
  "does not confirm bounded publication with mismatched %s",
  async (failure) => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    const actor = f.boundedActor({
      proof:
        failure === "proof"
          ? (proof) => ({ ...proof, dataHash: `0x${"ff".repeat(32)}` })
          : undefined,
      beforeDownload: async (key) => {
        if (
          failure === "content" &&
          key === f.blobPath(`${additionsLedgerScope(SOURCE)}/1`)
        )
          await f.put(additionsLedgerScope(SOURCE), "1", T3, { forged: true });
      },
    });
    expect(await actor.service.summarize(QUERY)).toMatchObject({
      coverage: "behind",
      total: 1,
    });
    expect(
      actor.events.filter((event) => event.startsWith("confirmed:")),
    ).toEqual([]);
  },
);

it("settles an aborted bounded source unit before returning and starts no later effects", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  const controller = new AbortController();
  let started!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => {
    started = resolve;
  });
  const settling = new Promise<void>((resolve) => {
    release = resolve;
  });
  const actor = f.boundedActor({
    options: { signal: controller.signal },
    beforeDownload: async () => {
      controller.abort(new Error("cancel recovery"));
      started();
      await settling;
      controller.signal.throwIfAborted();
    },
  });
  let returned = false;
  const summary = actor.service.summarize(QUERY).then((result) => {
    returned = true;
    return result;
  });
  await entered;
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(returned).toBe(false);
  } finally {
    release();
  }
  expect(await summary).toMatchObject({
    coverage: "behind",
    total: 0,
  });
  const completedEvents = [...actor.events];
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(actor.events).toEqual(completedEvents);
  expect(
    actor.events.filter((event) => /^(publish|confirmed):/.test(event)),
  ).toEqual([]);
  expect(await f.readRegistry()).not.toHaveProperty(
    additionsLedgerScope(SOURCE),
  );
});

it("converges after two independent actors summarize concurrently and a third restarts", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.source("2", T2, ["a", "b"]);
  const desktop = f.actor();
  const tee = f.actor();
  const results = await Promise.all([
    desktop.summarize(QUERY),
    tee.summarize(QUERY),
  ]);
  for (const result of results) {
    expect(result.total).toBe(2);
    expect(result.through).toEqual({ [SOURCE]: "2" });
    expect(result.days.map((day) => day.added)).toEqual([1, 1, 0, 0]);
  }
  const restarted = await f.actor().summarize(QUERY);
  expect(restarted).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
  expect(restarted.days.map((day) => day.added)).toEqual([1, 1, 0, 0]);
  expect(await f.document(additionsLedgerScope(SOURCE))).toMatchObject({
    through: "2",
  });
});

it("keeps the first committed checkpoint when a late writer uploads then crashes after originals are pruned", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  const scope = additionsLedgerScope(SOURCE);
  let resume!: () => void;
  let entered!: () => void;
  const paused = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    resume = resolve;
  });
  const adapter = f.storage();
  async function delayedUpload(
    key: string,
    bytes: Uint8Array,
    createOnly: boolean,
  ) {
    if (key === `${scope}/1`) {
      entered();
      await released;
    }
    return (createOnly ? adapter.uploadCreateOnly! : adapter.upload)(
      key,
      bytes,
    );
  }
  const late = f
    .actor({
      storageAdapter: {
        ...adapter,
        upload: (key, bytes) => delayedUpload(key, bytes, false),
        uploadCreateOnly: (key, bytes) => delayedUpload(key, bytes, true),
      },
      gateway: {
        async registerDataPoint() {
          throw new Error("writer crashed before registration");
        },
      },
    })
    .summarize(QUERY);
  await Promise.race([
    paused,
    late.then(() => {
      throw new Error("late actor returned before reaching upload");
    }),
  ]);
  try {
    await f.source("2", T2, ["a", "b"]);
    expect(await f.actor().summarize(QUERY)).toMatchObject({
      coverage: "complete",
      total: 2,
    });
    await rm(f.blobPath(`${SOURCE}/1`));
    await rm(f.blobPath(`${SOURCE}/2`));
  } finally {
    resume();
    await late;
  }
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
});

it("does not upload any checkpoint through an adapter without atomic create-only support", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  const upload = vi.fn(f.storage().upload);
  const actor = f.actor({
    storageAdapter: { ...f.storage(), upload, uploadCreateOnly: undefined },
  });
  expect(await actor.summarize(QUERY)).toMatchObject({
    coverage: "behind",
    total: 1,
  });
  expect(upload).not.toHaveBeenCalled();
});

it("distinguishes unavailable immutable storage from an invalid orphan in publication diagnostics", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  const codes: string[] = [];
  await f
    .actor({
      storageAdapter: { ...f.storage(), uploadCreateOnly: undefined },
      onRecoveryDiagnostic: (event) => codes.push(event.code),
    })
    .summarize(QUERY);
  expect(codes).toContain("immutable_storage_unavailable");
  codes.length = 0;
  await writeFile(
    f.blobPath(`${additionsLedgerScope(SOURCE)}/1`),
    new Uint8Array([1, 2, 3]),
  );
  await f
    .actor({ onRecoveryDiagnostic: (event) => codes.push(event.code) })
    .summarize(QUERY);
  expect(codes).toContain("checkpoint_adoption_failed");
  expect(await f.readRegistry()).not.toHaveProperty(
    additionsLedgerScope(SOURCE),
  );
});

it("registers an authenticated immutable orphan without rewriting or skipping its version", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f
    .actor({
      gateway: {
        async registerDataPoint() {
          throw new Error("crashed after upload");
        },
      },
    })
    .summarize(QUERY);
  const path = f.blobPath(`${additionsLedgerScope(SOURCE)}/1`);
  const orphan = await readFile(path);
  expect(
    (await f.readRegistry())[additionsLedgerScope(SOURCE)],
  ).toBeUndefined();
  await f.actor().summarize(QUERY);
  expect(await readFile(path)).toEqual(orphan);
  expect(await f.document(additionsLedgerScope(SOURCE))).toMatchObject({
    through: "1",
    currentTotal: 1,
  });
  await rm(f.blobPath(`${SOURCE}/1`));
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 1,
  });
});

it("selects an older compatible checkpoint when the source head rolls back after pruning", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.actor().summarize(QUERY);
  const first = (await f.readRegistry())[SOURCE].versions[0];
  await f.source("2", T2, ["a", "b"]);
  await f.actor().summarize(QUERY);
  await rm(f.blobPath(`${SOURCE}/1`));
  await rm(f.blobPath(`${SOURCE}/2`));
  await f.setSlot(SOURCE, first);
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 1,
    through: { [SOURCE]: "1" },
  });
});

it("returns behind when source commitments change between inventory validation reads", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  let sourceReads = 0;
  const actor = f.actor({}, async (scope) => {
    if (scope === SOURCE && ++sourceReads === 2)
      await f.source("1", T2, ["b", "c"]);
  });
  const summary = await actor.summarize(QUERY);
  expect(summary).toMatchObject({
    coverage: "behind",
    total: 0,
    through: { [SOURCE]: "0" },
  });
  expect(summary.days.map((day) => day.added)).toEqual([0, 0, 0, 0]);
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "1" },
  });
});

it.each(["pending", "failed"])(
  "keeps %s slots partial and revisits a replaced same-version registration",
  async (status) => {
    const f = await fixture();
    await f.source("1", T1, ["old"]);
    const slot = (await f.readRegistry())[SOURCE]?.versions[0];
    if (!slot) throw new Error("Fixture missing source slot");
    await f.setSlot(SOURCE, { ...slot, status });
    const unresolved = await f.actor().summarize(QUERY);
    expect(unresolved).toMatchObject({
      coverage: "partial",
      total: status === "pending" ? 1 : 0,
      through: { [SOURCE]: status === "pending" ? "1" : "0" },
    });
    await f.source("1", T2, ["replacement", "extra"]);
    const recovered = await f.actor().summarize(QUERY);
    expect(recovered).toMatchObject({
      coverage: "complete",
      total: 2,
      through: { [SOURCE]: "1" },
    });
    expect(recovered.days.map((day) => day.added)).toEqual([0, 2, 0, 0]);
  },
);

it.each(["owner", "network"])(
  "rebuilds rather than trusting a portable ledger from another %s",
  async (field) => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    await f.actor().summarize(QUERY);
    const scope = additionsLedgerScope(SOURCE);
    const doc = z
      .record(z.string(), z.unknown())
      .parse(await f.document(scope));
    const ledger = z.record(z.string(), z.unknown()).parse(doc.ledger);
    await f.put(scope, "2", T2, {
      ...doc,
      [field]:
        field === "owner"
          ? "0x2222222222222222222222222222222222222222"
          : "chain:2:https://elsewhere.example",
      ledger: { ...ledger, latest: { collectedAt: T1, total: 999 } },
    });
    const summary = await f.actor().summarize(QUERY);
    expect(summary).toMatchObject({
      coverage: "complete",
      total: 1,
      through: { [SOURCE]: "1" },
    });
    expect(summary.days.map((day) => day.added)).toEqual([1, 0, 0, 0]);
    expect(await f.document(scope)).toMatchObject({
      owner: OWNER,
      network: "chain:1:https://gateway.example",
      ledger: { latest: { total: 1 } },
    });
  },
);

it.each(["failed", "unknown"])(
  "discards a checkpoint contribution when its pending registration becomes %s",
  async (status) => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    await f.actor().summarize(QUERY);
    await f.source("2", T2, ["a", "b"]);
    const slot = (await f.readRegistry())[SOURCE].versions[1];
    await f.setSlot(SOURCE, { ...slot, status: "pending" });
    expect(await f.actor().summarize(QUERY)).toMatchObject({
      total: 2,
      through: { [SOURCE]: "2" },
    });
    await rm(f.blobPath(`${SOURCE}/1`));
    await f.setSlot(SOURCE, { ...slot, status });
    for (let read = 0; read < 2; read++) {
      const summary = await f.actor().summarize(QUERY);
      expect(summary).toMatchObject({
        coverage: "partial",
        total: 1,
        through: { [SOURCE]: "1" },
      });
      expect(summary.days.map((day) => day.added)).toEqual([1, 0, 0, 0]);
    }
  },
);

it("backfills more than 200 encrypted retained versions without losing the original baseline", async () => {
  const f = await fixture();
  await f.source("1", T1, ["old"]);
  for (let version = 2; version <= 204; version++)
    await f.source(String(version), T2, ["old"]);
  await f.source("205", T4, ["old", "new"]);
  const summary = await f.actor().summarize(QUERY);
  expect(summary).toMatchObject({
    coverage: "complete",
    total: 2,
    partial: false,
    trackedSince: T1,
    through: { [SOURCE]: "205" },
  });
  expect(summary.days.map((day) => day.added)).toEqual([1, 0, 0, 1]);
  const restarted = await f.actor().summarize(QUERY);
  expect(restarted).toEqual(summary);
}, 30000);

it("retains verified history across confirmed-to-finalized lifecycle promotion after source blob removal", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  const before = await f.actor().summarize(QUERY);
  expect(before).toMatchObject({ coverage: "complete", total: 1 });
  await rm(f.blobPath(`${SOURCE}/1`));
  const slot = (await f.readRegistry())[SOURCE]?.versions[0];
  if (!slot) throw new Error("Fixture missing source");
  await f.setSlot(SOURCE, { ...slot, status: "finalized" });
  const after = await f.actor().summarize(QUERY);
  expect(after).toMatchObject({
    coverage: "complete",
    total: 1,
    through: { [SOURCE]: "1" },
  });
  expect(after.days.map((day) => day.added)).toEqual([1, 0, 0, 0]);
});

it("keeps an unsettled deletion tombstone partial on every read", async () => {
  const f = await fixture();
  await f.source("1", T1, ["deleted"]);
  await f.actor().summarize(QUERY);
  await f.tombstone("2");
  const slot = (await f.readRegistry())[SOURCE]?.versions.find(
    (row) => row.expectedVersion === "2",
  );
  if (!slot) throw new Error("Fixture missing tombstone");
  await f.setSlot(SOURCE, { ...slot, status: "pending" }, T2);
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "partial",
    total: 0,
  });
  expect(await f.actor().summarize(QUERY)).toMatchObject({
    coverage: "partial",
    total: 0,
  });
});

it.each([
  [T2, T2],
  [T3, T2],
])(
  "reports numeric-head totals when version timestamps are %s then %s",
  async (firstTime, headTime) => {
    const f = await fixture();
    await f.source("1", firstTime, ["a", "b", "c"]);
    await f.source("2", headTime, ["a"]);
    const summary = await f.actor().summarize(QUERY);
    expect(summary).toMatchObject({
      coverage: "complete",
      total: 1,
      through: { [SOURCE]: "2" },
      scopes: [{ scope: SOURCE, total: 1 }],
    });
    expect(await f.actor().summarize(QUERY)).toEqual(summary);
  },
);

it("recovers prior durable history after interleaved writers leave current ledger blob and commitments mismatched", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.source("2", T2, ["a", "b"]);
  const before = await f.actor().summarize(QUERY);
  const scope = additionsLedgerScope(SOURCE);
  const doc = z.record(z.string(), z.unknown()).parse(await f.document(scope));
  await rm(f.blobPath(`${SOURCE}/1`));
  await rm(f.blobPath(`${SOURCE}/2`));

  async function candidate(collectedAt: string) {
    const plaintext = new TextEncoder().encode(
      JSON.stringify(createDataFileEnvelope(scope, collectedAt, doc)),
    );
    const encrypted = await encryptWithPassword(plaintext, password(scope));
    return {
      encrypted,
      slot: {
        expectedVersion: "2",
        dataHash: keccak256(plaintext),
        metadataHash: keccak256(
          stringToHex(
            JSON.stringify({
              scope,
              collectedAt,
              sizeBytes: encrypted.byteLength,
            }),
          ),
        ),
        status: "confirmed",
        addedAt: T4,
        isTombstone: false,
      },
    };
  }
  const [candidateA, candidateB] = await Promise.all([
    candidate(T3),
    candidate(T4),
  ]);
  let releaseAUploaded: () => void = () => {};
  let releaseBRegistered: () => void = () => {};
  const aUploaded = new Promise<void>((resolve) => {
    releaseAUploaded = resolve;
  });
  const bRegistered = new Promise<void>((resolve) => {
    releaseBRegistered = resolve;
  });
  // Force A upload, B upload, B registration, A registration at one derived version.
  await Promise.all([
    (async () => {
      await writeFile(f.blobPath(`${scope}/2`), candidateA.encrypted);
      releaseAUploaded();
      await bRegistered;
      await f.setSlot(scope, candidateA.slot);
    })(),
    (async () => {
      await aUploaded;
      await writeFile(f.blobPath(`${scope}/2`), candidateB.encrypted);
      await f.setSlot(scope, candidateB.slot);
      releaseBRegistered();
    })(),
  ]);
  expect((await f.readRegistry())[scope]?.head?.dataHash).toBe(
    candidateA.slot.dataHash,
  );
  expect(new Uint8Array(await readFile(f.blobPath(`${scope}/2`)))).toEqual(
    candidateB.encrypted,
  );
  const restarted = await f.actor().summarize(QUERY);
  expect(restarted).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
  expect(restarted.days).toEqual(before.days);
  expect(restarted.buckets).toEqual(before.buckets);
  expect(await f.actor().summarize(QUERY)).toEqual(restarted);
});

it("preserves a durable checkpoint through a one-time inventory failure after originals are pruned", async () => {
  const f = await fixture();
  await f.source("1", T1, ["a"]);
  await f.source("2", T2, ["a", "b"]);
  const before = await f.actor().summarize(QUERY);
  const scope = additionsLedgerScope(SOURCE);
  const checkpoint = await f.document(scope);
  await rm(f.blobPath(`${SOURCE}/1`));
  await rm(f.blobPath(`${SOURCE}/2`));
  let failed = false;
  const transientFailure = f.actor({}, async (readScope) => {
    if (readScope === scope && !failed) {
      failed = true;
      throw new Error("Temporary Gateway inventory transport failure");
    }
  });
  const unresolved = await transientFailure.summarize(QUERY);
  expect(failed).toBe(true);
  expect(["partial", "unavailable", "behind"]).toContain(unresolved.coverage);
  expect(await f.document(scope)).toEqual(checkpoint);
  const healthy = await f.actor().summarize(QUERY);
  expect(healthy).toMatchObject({
    coverage: "complete",
    total: 2,
    through: { [SOURCE]: "2" },
  });
  expect(healthy.days).toEqual(before.days);
  expect(healthy.buckets).toEqual(before.buckets);
});

it("persists the on-upload fold from registered in-memory bytes before any source download", async () => {
  const f = await fixture();
  const first = await f.source("1", T1, ["a"]);
  const data = { conversations: [{ id: "a" }] };
  const envelope = createDataFileEnvelope(SOURCE, T1, data);
  await rm(f.blobPath(`${SOURCE}/1`));
  await f
    .actor()
    .recordUpload(
      { scope: SOURCE, collectedAt: T1, data },
      { envelope, encryptedSize: first.encryptedBytes },
    );
  expect(await f.document(additionsLedgerScope(SOURCE))).toMatchObject({
    through: "1",
    currentTotal: 1,
  });
  const restarted = await f.actor().summarize(QUERY);
  expect(restarted).toMatchObject({
    coverage: "complete",
    total: 1,
    through: { [SOURCE]: "1" },
  });
  expect(restarted.days.map((day) => day.added)).toEqual([1, 0, 0, 0]);
});

it("keeps Unicode byte-edge names and literal hash-looking sources collision-separated", () => {
  const prefixBytes = new TextEncoder().encode("vana.system.additions.").length;
  const edge = "é".repeat(Math.floor((256 - prefixBytes) / 2));
  expect(
    new TextEncoder().encode(additionsLedgerScope(edge)).length,
  ).toBeLessThanOrEqual(256);
  expect(additionsLedgerScope(edge)).toBe(`vana.system.additions.${edge}`);
  const long = `${edge}é`;
  const hashed = additionsLedgerScope(long);
  expect(hashed).toMatch(/^vana\.system\.additions-hash\.[a-f0-9]{64}$/);
  expect(additionsLedgerScope(`hash.${hashed.split(".").at(-1)}`)).not.toBe(
    hashed,
  );
  expect(additionsLedgerScope(long + " ")).not.toBe(hashed);
});

it.each(["confirmed", "pending"])(
  "keeps the readable checkpoint when a %s tombstone is retained above the authoritative head and sources are pruned",
  async (status) => {
    const f = await fixture();
    await f.source("1", T1, ["a"]);
    const first = await f.actor().summarize(QUERY);
    expect(first).toMatchObject({ coverage: "complete", total: 1 });
    const ledgerScope = additionsLedgerScope(SOURCE);
    const head = (await f.readRegistry())[ledgerScope]?.versions.at(-1);
    if (!head) throw new Error("Fixture missing checkpoint");
    const before = await f.document(ledgerScope);
    // A rollback leaves the higher tombstone in the inventory but moves the head back.
    await f.setSlot(
      ledgerScope,
      {
        expectedVersion: String(BigInt(head.expectedVersion) + 1n),
        dataHash:
          "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
        metadataHash:
          "0xc5255a141acd6a2ae55971b62c0a85977c2511989dc114ad2abc2b7644f57d90",
        status,
        addedAt: T2,
        isTombstone: true,
      },
      T2,
    );
    await f.setSlot(ledgerScope, head);
    await rm(f.blobPath(`${SOURCE}/1`));
    const next = await f.actor().summarize(QUERY);
    expect(next).toMatchObject({
      coverage: "complete",
      total: 1,
      through: { [SOURCE]: "1" },
    });
    expect(next.days.map((day) => day.added)).toEqual([1, 0, 0, 0]);
    expect(await f.document(ledgerScope)).toEqual(before);
  },
);

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, writeFile, rename, rm } from "node:fs/promises";
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
import type { StorageAdapter } from "../storage/adapters/interface.js";
import type { VersionInventoryClient } from "./version-inventory.js";
import {
  createDurableAdditions,
  type DurableAdditionsOptions,
} from "./durable.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SOURCE = "test.conversations";
const MASTER_KEY = new Uint8Array(32).fill(17);
const T1 = "2026-10-01T12:00:00.000Z";
const T2 = "2026-10-02T12:00:00.000Z";
const T4 = "2026-10-04T12:00:00.000Z";
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
  ) {
    const plaintext = new TextEncoder().encode(
      JSON.stringify(createDataFileEnvelope(scope, collectedAt, data)),
    );
    const encrypted = await encryptWithPassword(plaintext, password(scope));
    await storage().upload(`${scope}/${expectedVersion}`, encrypted);
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
    budgets: Pick<DurableAdditionsOptions, "byteBudget" | "timeBudgetMs"> = {},
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
  };
}

import { handlePersonalServerDataRequest } from "../api/index.js";
import { createScopeDeletionTracker } from "../sync/scope-deletions.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { AdditionsSummary } from "./summary.js";

/**
 * The owner's additions summary built from the durable registry holds the
 * scopes and registry versions it counted: a deletion that lands before the
 * response is released refuses it, and a scope already deleted is left out.
 */
describe("durable additions release", () => {
  async function summaryRequest(
    onSummarized?: (
      tracker: ReturnType<typeof createScopeDeletionTracker>,
    ) => void,
    before?: (tracker: ReturnType<typeof createScopeDeletionTracker>) => void,
    version = "1",
    readdAfter?: string,
  ) {
    const f = await fixture();
    if (readdAfter) {
      await f.source("1", T1, ["old"]);
      await f.tombstone(readdAfter);
    }
    await f.source(version, readdAfter ? T4 : T1, ["private"]);
    const actor = f.actor();
    const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
    before?.(tracker);
    let captured: AdditionsSummary | undefined;
    const additions = {
      ...actor,
      async summarize(input: Parameters<typeof actor.summarize>[0]) {
        captured = await actor.summarize(input);
        onSummarized?.(tracker);
        return captured;
      },
    };
    const response = await handlePersonalServerDataRequest(
      new Request("http://ps/v1/data/additions?days=4"),
      {
        auth: { authorizeOwner: async () => undefined },
        storage: createMemoryDataStorage(),
        additions,
        scopeDeletions: tracker,
        serverOwner: OWNER,
        now: () => new Date(T4),
      } as never,
      { basePath: "/v1/data" },
    );
    return { response, captured: () => captured };
  }

  it("refuses a summary whose counted scope is deleted before release", async () => {
    const { response, captured } = await summaryRequest((tracker) =>
      tracker.markDeleted(SOURCE, { deletedAt: T4, version: "2" }),
    );
    expect(captured()?.total).toBe(1);
    expect(response.status, await response.text()).toBe(410);
  });

  it("leaves out a scope already deleted when the summary is built", async () => {
    const { response, captured } = await summaryRequest(undefined, (tracker) =>
      tracker.markDeleted(SOURCE, { deletedAt: T4, version: "2" }),
    );
    expect(response.status).toBe(200);
    expect(captured()?.total).toBe(0);
  });

  it("serves the summary when nothing is deleted (positive control)", async () => {
    const { response, captured } = await summaryRequest();
    expect(response.status).toBe(200);
    expect(captured()?.total).toBe(1);
  });

  it("omits an exact uint256 version covered by its equal tombstone", async () => {
    const version = "9007199254740995";
    const { response, captured } = await summaryRequest(
      undefined,
      (tracker) => tracker.markDeleted(SOURCE, { deletedAt: T4, version }),
      version,
    );
    expect(response.status).toBe(200);
    expect(captured()?.total).toBe(0);
  });

  it("refuses an exact uint256 version deleted after summary selection", async () => {
    const version = "9007199254740995";
    const { response, captured } = await summaryRequest(
      (tracker) => tracker.markDeleted(SOURCE, { deletedAt: T4, version }),
      undefined,
      version,
    );
    expect(captured()?.total).toBe(1);
    expect(response.status, await response.text()).toBe(410);
  });

  it("keeps an exact uint256 re-add newer than its tombstone", async () => {
    const tombstone = "9007199254740992";
    const { response, captured } = await summaryRequest(
      undefined,
      (tracker) =>
        tracker.markDeleted(SOURCE, { deletedAt: T2, version: tombstone }),
      "9007199254740993",
      tombstone,
    );
    expect(response.status).toBe(200);
    expect(captured()?.total).toBe(1);
  });
});

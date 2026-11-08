import { describe, it, expect, vi } from "vitest";

import {
  RETIRE_LEGACY_SCOPES_PER_CYCLE,
  countsOnlyLogger,
  liveRetireLegacy,
  retireLegacyScopes,
  type RetireCoverage,
} from "./retire-legacy.js";
import { deleteScope } from "./delete.js";
import type { Logger } from "../../logger/index.js";
import type { DeleteDataPort, DataStoragePort } from "../../ports/index.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

function logger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger & { info: ReturnType<typeof vi.fn> };
}

interface Row {
  collectedAt: string;
  dataPointId: string | null;
}
const BEFORE = "2026-11-01T00:00:00.000Z";
const SWITCH = "2026-11-05T00:00:00.000Z";
const AFTER = "2026-11-06T00:00:00.000Z";

const entryFor = (scope: string, row: Partial<Row> = {}) => ({
  id: 1,
  fileId: null,
  schemaId: null,
  path: `${scope}/x.json`,
  scope,
  collectedAt: BEFORE,
  createdAt: BEFORE,
  sizeBytes: 1,
  version: 1,
  dataPointId: "0xdp" as string | null,
  ...row,
});

/** One device's local legacy storage. */
function deviceStorage(
  local: Set<string>,
  rows: Record<string, Partial<Row>> = {},
): DataStoragePort {
  return {
    listScopes: ({ limit = 100, offset = 0 }) => {
      const all = [...local].sort();
      return {
        total: all.length,
        scopes: all.slice(offset, offset + limit).map((scope) => ({
          scope,
          latestCollectedAt: "2026-11-01T00:00:00.000Z",
          versionCount: 1,
        })),
      };
    },
    listVersions: (scope: string) =>
      local.has(scope) ? [entryFor(scope, rows[scope])] : [],
    deleteVersion: async (scope: string) => local.delete(scope),
  } as unknown as DataStoragePort;
}

/** A gateway shared by every device of the account. */
function gateway(remote: Set<string>) {
  const tombstones: string[] = [];
  const deleteData: DeleteDataPort = {
    async tombstone(scope) {
      tombstones.push(scope);
      const live = remote.delete(scope);
      return live
        ? {
            status: "tombstoned",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          }
        : {
            status: "already-deleted",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          };
    },
    // A second deleter finds the keys already gone: missing is success.
    async deleteBlobVersions(_scope, versions) {
      return { deleted: [], missing: versions, failed: [] };
    },
  };
  return { deleteData, tombstones };
}

function world(scopes: string[], rows: Record<string, Partial<Row>> = {}) {
  const local = new Set(scopes);
  const remote = new Set(scopes);
  return {
    local,
    remote,
    storage: deviceStorage(local, rows),
    ...gateway(remote),
  };
}

const covered = (throughMs = Date.parse(SWITCH)): RetireCoverage => ({
  kind: "covered",
  throughMs,
});

interface RunOptions {
  coverage?: (scope: string) => RetireCoverage;
  switchedAt?: string | undefined;
  registeredAt?: (scope: string) => Promise<string | null>;
  log?: ReturnType<typeof logger>;
}

function run(w: ReturnType<typeof world>, o: RunOptions = {}) {
  const log = o.log ?? logger();
  return retireLegacyScopes({
    storage: w.storage,
    switchedAt: "switchedAt" in o ? o.switchedAt : SWITCH,
    coverage: o.coverage ?? (() => covered()),
    registeredAt: o.registeredAt ?? (async () => BEFORE),
    deleteScope: (scope) =>
      deleteScope(
        {
          storage: w.storage,
          serverOwner: OWNER,
          deleteData: w.deleteData,
          pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
          logger: logger(),
        },
        scope,
      ),
    logger: log,
  });
}

describe("retireLegacyScopes", () => {
  it("deletes the legacy files, remote and local, of covered scopes only", async () => {
    const w = world(["acme.items", "acme.orders", "beta.things"]);
    const result = await run(w, {
      coverage: (s) =>
        s === "acme.orders"
          ? { kind: "skip", reason: "incomplete" }
          : covered(),
    });
    expect(result).toMatchObject({ considered: 3, deleted: 2 });
    expect(result.skipped.incomplete).toBe(1);
    expect([...w.local]).toEqual(["acme.orders"]);
    expect([...w.remote]).toEqual(["acme.orders"]);
  });

  it("keeps every file when no view covers", async () => {
    const w = world(["acme.items", "acme.orders"]);
    const result = await run(w, {
      coverage: () => ({ kind: "skip", reason: "incomplete" }),
    });
    expect(result.deleted).toBe(0);
    expect(w.tombstones).toEqual([]);
    expect(w.local.size).toBe(2);
  });

  it("counts an ambiguous scope (more than one connection) and keeps it", async () => {
    const w = world(["acme.items"]);
    const result = await run(w, {
      coverage: () => ({ kind: "skip", reason: "ambiguous" }),
    });
    expect(result.skipped.ambiguous).toBe(1);
    expect(w.local.size).toBe(1);
  });

  describe("switchedAt", () => {
    it.each([
      ["absent", undefined],
      ["unparsable", "not a time"],
      ["empty", ""],
    ])("%s: nothing is deleted", async (_name, switchedAt) => {
      const w = world(["acme.items"]);
      const result = await run(w, { switchedAt });
      expect(result.deleted).toBe(0);
      expect(w.tombstones).toEqual([]);
      expect(w.local.size).toBe(1);
    });

    it("a local file written after the switch keeps the whole scope and is counted", async () => {
      const w = world(["acme.items", "acme.orders"], {
        "acme.items": { collectedAt: AFTER },
      });
      const result = await run(w, {
        coverage: () => covered(Date.parse(AFTER) + 1000),
      });
      expect(result.deleted).toBe(1);
      expect(result.skipped.afterSwitch).toBe(1);
      expect(result.legacyWritesAfterSwitch).toBe(1);
      expect([...w.local]).toEqual(["acme.items"]);
    });

    it("a file written at exactly the switch time is after it", async () => {
      const w = world(["acme.items"], {
        "acme.items": { collectedAt: SWITCH },
      });
      const result = await run(w);
      expect(result.deleted).toBe(0);
      expect(result.legacyWritesAfterSwitch).toBe(1);
    });

    it("a remote head registered after the switch keeps the scope and is counted", async () => {
      const w = world(["acme.items"]);
      const result = await run(w, { registeredAt: async () => AFTER });
      expect(result.deleted).toBe(0);
      expect(result.legacyWritesAfterSwitch).toBe(1);
      expect(w.local.size).toBe(1);
    });

    it("an unreadable registry keeps the scope without counting a write", async () => {
      const w = world(["acme.items"]);
      const result = await run(w, {
        registeredAt: async () => {
          throw new Error("gateway down");
        },
      });
      expect(result.deleted).toBe(0);
      expect(result.legacyWritesAfterSwitch).toBe(0);
    });

    it("a scope the gateway never saw is retired", async () => {
      const w = world(["acme.items"]);
      const result = await run(w, { registeredAt: async () => null });
      expect(result.deleted).toBe(1);
    });

    it("all files before the switch and covered: retired", async () => {
      const w = world(["acme.items"]);
      expect((await run(w)).deleted).toBe(1);
      expect(w.local.size).toBe(0);
      expect(w.remote.size).toBe(0);
    });
  });

  describe("coverage", () => {
    it("a local row collected after the oldest head is kept", async () => {
      const w = world(["acme.items"], {
        "acme.items": { collectedAt: "2026-11-03T00:00:00.000Z" },
      });
      const result = await run(w, {
        coverage: () => covered(Date.parse("2026-11-02T00:00:00.000Z")),
      });
      expect(result.deleted).toBe(0);
      expect(result.skipped.uncovered).toBe(1);
      expect(w.local.size).toBe(1);
    });

    it("a row with an unreadable time is kept", async () => {
      const w = world(["acme.items"], {
        "acme.items": { collectedAt: "garbage" },
      });
      const result = await run(w);
      expect(result.deleted).toBe(0);
    });

    it("a row never uploaded is retired when a head covers it (uploads stop at the switch)", async () => {
      const w = world(["acme.items"], { "acme.items": { dataPointId: null } });
      const result = await run(w, { registeredAt: async () => null });
      expect(result.deleted).toBe(1);
      expect(w.local.size).toBe(0);
    });
  });

  it("is idempotent: a second pass finds nothing to do", async () => {
    const w = world(["acme.items"]);
    await run(w);
    const again = await run(w);
    expect(again.considered).toBe(0);
    expect(w.tombstones).toEqual(["acme.items"]);
  });

  it("two devices deleting at the same time both succeed", async () => {
    const w = world(["acme.items", "acme.orders"]);
    const localB = new Set(w.local);
    const b = { ...w, local: localB, storage: deviceStorage(localB) };
    const [ra, rb] = await Promise.all([run(w), run(b)]);
    expect(ra.deleted).toBe(2);
    expect(rb.deleted).toBe(2);
    expect(w.local.size).toBe(0);
    expect(localB.size).toBe(0);
    expect(w.remote.size).toBe(0);
  });

  it("never touches stream-sync or reserved names", async () => {
    const w = world([
      "acme.items",
      "pdpp.acme~0123456789abcdef.items",
      "pdpp.acme~0123456789abcdef",
      "vana.system.keys",
    ]);
    const asked: string[] = [];
    await run(w, { coverage: (s) => (asked.push(s), covered()) });
    expect(asked).toEqual(["acme.items"]);
    expect(w.tombstones).toEqual(["acme.items"]);
    expect(w.local.has("pdpp.acme~0123456789abcdef.items")).toBe(true);
    expect(w.local.has("pdpp.acme~0123456789abcdef")).toBe(true);
    expect(w.local.has("vana.system.keys")).toBe(true);
  });

  it("keeps the local copy when the gateway delete fails, and retries later", async () => {
    const w = world(["acme.items"]);
    let fail = true;
    const original = w.deleteData.tombstone.bind(w.deleteData);
    w.deleteData.tombstone = async (scope, fence) => {
      if (fail) throw new Error("gateway down");
      return original(scope, fence);
    };
    const first = await run(w);
    expect(first.deleted).toBe(0);
    expect(first.skipped.failed).toBe(1);
    expect(w.local.has("acme.items")).toBe(true);
    fail = false;
    expect((await run(w)).deleted).toBe(1);
    expect(w.local.size).toBe(0);
  });

  it("limits the scopes deleted per cycle", async () => {
    const names = Array.from(
      { length: RETIRE_LEGACY_SCOPES_PER_CYCLE + 3 },
      (_, i) => `acme.s${i}`,
    );
    const w = world(names);
    const result = await run(w);
    expect(result.deleted).toBe(RETIRE_LEGACY_SCOPES_PER_CYCLE);
    expect(w.local.size).toBe(3);
  });

  it("its own log carries counts only", async () => {
    const w = world(["secret-connector.private-stream"]);
    const log = logger();
    await run(w, { log });
    expect(JSON.stringify(log.info.mock.calls)).not.toContain("secret");
  });
});

describe("countsOnlyLogger", () => {
  it("passes counts and statuses and drops every identifying field", () => {
    const sink = logger();
    const log = countsOnlyLogger(sink);
    log.info(
      {
        scope: "secret.scope",
        dataPointId: "0xsecret",
        version: "7",
        tombstoneVersion: "9",
        keys: ["secret-key"],
        error: "secret message",
        marker: { scope: "secret.scope" },
        durable: true,
        gateway: "ok",
        storage: "deferred",
        blobsDeleted: 3,
        pending: 2,
        local: "secret-status-text",
      },
      "Scope deletion finished",
    );
    expect(sink.info).toHaveBeenCalledWith(
      {
        durable: true,
        gateway: "ok",
        storage: "deferred",
        blobsDeleted: 3,
        pending: 2,
      },
      "Scope deletion finished",
    );
    expect(JSON.stringify(sink.info.mock.calls)).not.toContain("secret");
  });

  it("drops an error object passed as the payload", () => {
    const sink = logger();
    countsOnlyLogger(sink).warn(new Error("secret message"), "failed");
    expect(JSON.stringify(sink.warn.mock.calls)).not.toContain("secret");
  });
});

describe("liveRetireLegacy", () => {
  const reader = { viewCoverage: () => covered() };
  const config = (write: boolean, switchedAt?: string) => ({
    streamSync: { write, switchedAt },
  });

  it("is off without the writer, without the reader, or with write off", () => {
    expect(
      liveRetireLegacy({ config: config(true), writer: null, reader })(),
    ).toBeNull();
    expect(
      liveRetireLegacy({ config: config(true), writer: {}, reader: null })(),
    ).toBeNull();
    expect(
      liveRetireLegacy({ config: config(false), writer: {}, reader })(),
    ).toBeNull();
  });

  it("reads the config each call: turning write off turns it off", () => {
    const c = config(true, SWITCH);
    const live = liveRetireLegacy({ config: c, writer: {}, reader });
    expect(live()?.switchedAt).toBe(SWITCH);
    c.streamSync.write = false;
    expect(live()).toBeNull();
    c.streamSync.write = true;
    c.streamSync.switchedAt = AFTER;
    expect(live()?.switchedAt).toBe(AFTER);
  });
});

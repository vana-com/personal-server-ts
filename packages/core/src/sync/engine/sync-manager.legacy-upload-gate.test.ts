import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { Logger } from "../../logger/index.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn(async () => []) }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll } from "../workers/download.js";
import { requeueLostDataPoints } from "../workers/lost-data-points.js";
import { createSyncManager } from "./sync-manager.js";
import { entityKeySets } from "../../storage/legacy-entity-key-sets.js";
import type { RetireLegacyOption } from "../workers/retire-legacy.js";

const logger = () =>
  ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }) as unknown as Logger;

/** Local legacy bodies by `scope@collectedAt`; every entry below is one version. */
const BODY = { activities: [{ id: "a" }] };

function rig() {
  const storage = {
    findUnsynced: () => [],
    listScopes: () => ({ total: 0, scopes: [] }),
    listVersions: (scope: string) => [{ id: "1", scope, collectedAt: T0 }],
    readEnvelope: async () => ({ data: BODY }),
  } as unknown as DataStoragePort;
  const upload = {
    storage,
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: logger(),
  } as unknown as UploadWorkerDeps;
  const download = {
    storage,
    cursor: { read: async () => null, write: async () => {} },
    logger: logger(),
  } as unknown as DownloadWorkerDeps;
  return { upload, download };
}

/** A host-shaped switch: `write` reads live state on every access. */
function hostSwitch(state: { on: boolean }) {
  const publish = vi.fn(async () => {});
  return {
    publish,
    streamSync: {
      get write() {
        return state.on;
      },
      publisher: { cycle: publish },
    },
  };
}

/** The predicate the manager handed to the upload and requeue workers. */
function predicates() {
  const upload = vi.mocked(uploadAll).mock.calls.at(-1)?.[1]?.skipEntry;
  const requeue = vi
    .mocked(requeueLostDataPoints)
    .mock.calls.at(-1)?.[2]?.skipScope;
  return { upload, requeue };
}
const T0 = "2026-11-01T00:00:00.000Z";
const entry = (scope: string) =>
  ({ id: "1", scope, collectedAt: T0 }) as IndexEntry;

/** The retire inputs a host gives; only the published view matters to the gate. */
function retireWith(
  view: (scope: string) => ReturnType<typeof entityKeySets> | Promise<null>,
  o: { throughMs?: number; revision?: () => string } = {},
): () => RetireLegacyOption {
  return () => ({
    coverage: () => ({
      kind: "covered",
      throughMs: o.throughMs ?? Date.parse(T0) + 86_400_000,
    }),
    viewKeys: async (scope) => view(scope),
    viewRevision: o.revision ?? (() => "r1"),
    switchedAt: undefined,
  });
}
const holdsA = retireWith((scope) => entityKeySets(scope, BODY));
const holdsNothing = retireWith((scope) =>
  entityKeySets(scope, { activities: [] }),
);

const CARRIED = "strava.activities"; // a legacy binding the stream carries
const MEMORY = "memory.notes.0"; // agent memory: legacy path only
const REPLICA = "pdpp_replica_v1.items"; // replica transport: legacy path only

describe("sync manager: legacy is read-only history after the switch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("writer on: stream-carried scopes are not uploaded or requeued; memory and replica scopes still are; the stream publishes; downloads continue", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(true);
    expect(await upload?.(entry(MEMORY))).toBe(false);
    expect(await upload?.(entry(REPLICA))).toBe(false);
    expect(await requeue?.(CARRIED)).toBe(true);
    expect(await requeue?.(MEMORY)).toBe(false);
    expect(await requeue?.(REPLICA)).toBe(false);
    expect(h.publish).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);
  });

  it("writer off: nothing is skipped, legacy upload and registration run unchanged, nothing publishes", async () => {
    const r = rig();
    const h = hostSwitch({ on: false });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    for (const scope of [CARRIED, MEMORY, REPLICA]) {
      expect(await upload?.(entry(scope))).toBe(false);
      expect(await requeue?.(scope)).toBe(false);
    }
    expect(h.publish).not.toHaveBeenCalled();
  });

  it("no stream-sync option at all: legacy upload unchanged", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {});
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect((await upload?.(entry(CARRIED))) ?? false).toBe(false);
    expect((await requeue?.(CARRIED)) ?? false).toBe(false);
  });

  it("switched off mid-run: the next cycle uploads stream-carried scopes again", async () => {
    const r = rig();
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    state.on = false;
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(false);
    expect(h.publish).toHaveBeenCalledTimes(1);
  });

  it("the switch is read when the predicate runs, not when the cycle starts", async () => {
    const r = rig();
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    const { upload } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(true);
    state.on = false;
    expect(await upload?.(entry(CARRIED))).toBe(false);
  });

  it("a failing publish is reported", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    h.publish.mockRejectedValueOnce(new Error("boom"));
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(manager.getStatus().errors.map((e) => e.message)).toContain(
      "Stream sync publish failed: boom",
    );
  });

  it("a host may name what its stream carries", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: {
        ...h.streamSync,
        carries: (scope) => scope === CARRIED,
      },
      retireLegacy: holdsA,
    });
    await manager.trigger();
    const { upload } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(true);
    expect(await upload?.(entry("instagram.profile"))).toBe(false);
  });

  // Mutant killed: gate on `carries` alone (skip every carried scope). A run
  // the writer discarded or refused is in no view; its legacy file is the
  // only copy, so it must keep uploading.
  it("a carried scope whose data the stream does not hold keeps uploading and requeuing", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsNothing,
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(false);
    expect(await requeue?.(CARRIED)).toBe(false);
  });

  // Mutant killed: re-prove a held file every cycle (no finished set). The
  // gate would read and parse the file again on every poll.
  it("a file the published view holds is finished: later cycles skip it without reading it", async () => {
    const r = rig();
    const reads = vi.fn(async () => ({ data: BODY }));
    (r.upload.storage as unknown as { readEnvelope: unknown }).readEnvelope =
      reads;
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    expect(reads).toHaveBeenCalledTimes(1);
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    expect(reads).toHaveBeenCalledTimes(1);
  });

  // Mutant killed: gate on keys only (no time check). The view holds key a
  // through T0 with old content; the local file was collected later with new
  // content under the same key. Skipping it would lose the edit.
  it("a local file newer than the view's coverage keeps uploading", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: retireWith((scope) => entityKeySets(scope, BODY), {
        throughMs: Date.parse(T0) - 1,
      }),
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(false);
    expect(await requeue?.(CARRIED)).toBe(false);
  });

  it("coverage that is not complete keeps uploading", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: () => ({
        coverage: () => ({ kind: "skip", reason: "incomplete" }),
        viewKeys: async (scope) => entityKeySets(scope, BODY),
        viewRevision: () => "r1",
        switchedAt: undefined,
      }),
    });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(false);
  });

  // Mutant killed: ignore the revision a mark was proved against.
  it("a finished file is proved again when the view changes", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    let revision = "r1";
    let view: ReturnType<typeof entityKeySets> = entityKeySets(CARRIED, BODY);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: retireWith(async () => view as never, {
        revision: () => revision,
      }),
    });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    revision = "r2";
    view = entityKeySets(CARRIED, { activities: [] });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(false);
  });

  // Mutant killed: never clear the finished set when the writer is off.
  it("a finished file is proved again after the switch goes off and on", async () => {
    const r = rig();
    const reads = vi.fn(async () => ({ data: BODY }));
    (r.upload.storage as unknown as { readEnvelope: unknown }).readEnvelope =
      reads;
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    expect(reads).toHaveBeenCalledTimes(1);
    state.on = false;
    await manager.trigger();
    state.on = true;
    await manager.trigger();
    expect(await predicates().upload?.(entry(CARRIED))).toBe(true);
    expect(reads).toHaveBeenCalledTimes(2);
  });

  // Mutant killed: clear the finished set only at cycle start. The switch can
  // go off and on again between two predicate calls inside one cycle.
  it("a finished file is proved again after an off-on flip inside one cycle", async () => {
    const r = rig();
    const reads = vi.fn(async () => ({ data: BODY }));
    (r.upload.storage as unknown as { readEnvelope: unknown }).readEnvelope =
      reads;
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
      retireLegacy: holdsA,
    });
    await manager.trigger();
    const { upload } = predicates();
    expect(await upload?.(entry(CARRIED))).toBe(true);
    state.on = false;
    expect(await upload?.(entry(CARRIED))).toBe(false);
    state.on = true;
    expect(await upload?.(entry(CARRIED))).toBe(true);
    expect(reads).toHaveBeenCalledTimes(2);
  });

  it("a view that cannot be read, or a host with no reader, keeps uploading", async () => {
    for (const retireLegacy of [retireWith(async () => null), undefined]) {
      const r = rig();
      const h = hostSwitch({ on: true });
      const manager = createSyncManager(r.upload, r.download, {
        streamSync: h.streamSync,
        ...(retireLegacy ? { retireLegacy } : {}),
      });
      await manager.trigger();
      expect(await predicates().upload?.(entry(CARRIED))).toBe(false);
    }
  });
});

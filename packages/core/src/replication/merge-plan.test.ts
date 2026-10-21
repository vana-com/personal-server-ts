import { describe, expect, it } from "vitest";
import {
  appView,
  OWNER_DELETE_GRACE_PERIOD_MS,
  planReplicaMerge,
} from "./merge-plan.js";
import { binding, identity, registration, T0, upsert } from "./fixtures.js";
import type { RecordOperation, ReplicaOperation } from "./envelope.js";

const context = {
  owner: identity.owner,
  declarations: [
    {
      sourceId: identity.sourceId,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.text === "string",
    },
  ],
  finalizedAt: (_batchId: string) => T0 + 100 * 86_400_000,
  now: T0,
};
const day = 86_400_000;
const observed = (
  id: string,
  device: string,
  value: string,
  days = 0,
  logical = 0,
) => ({
  ...upsert(id, logical, value, device, T0 + days * day),
  batchId: `batch-${id}`,
});
const observedMs = (
  id: string,
  device: string,
  value: string,
  offsetMs: number,
  logical = 0,
) => ({
  ...upsert(id, logical, value, device, T0 + offsetMs),
  batchId: `batch-${id}`,
});
const sourceDelete = (
  id: string,
  device: string,
  days: number,
  logical = 0,
): RecordOperation => ({
  ...identity,
  kind: "source-delete",
  declaration: binding,
  recordKey: "same-key",
  emittedAt: new Date(T0 + days * day).toISOString(),
  contentHash: `sha256:${"c".repeat(64)}`,
  origin: "source-event",
  batchId: `batch-${id}`,
  revision: {
    wallMs: T0 + days * day,
    logical,
    writerId: device,
    operationId: id,
  },
});
const plan = (ops: ReplicaOperation[], opts: Partial<typeof context> = {}) =>
  planReplicaMerge({ ...context, ...opts }, [registration, ...ops]);

describe("replica policy v3 vectors", () => {
  it("N01 and N02: observation time beats operation volume in either direction", () => {
    expect(
      plan([observed("a", "A", "X", 0, 10_000), observed("b", "B", "Y", 6, 5)])
        .records[0].current?.revision.operationId,
    ).toBe("b");
    expect(
      plan([observed("a", "A", "X", 6, 5), observed("b", "B", "Y", 0, 10_000)])
        .records[0].current?.revision.operationId,
    ).toBe("a");
  });
  it("N03-N08 source-version cases: declared dominance is set-based and never mixed with unversioned candidates", () => {
    const versionedBinding = {
      ...binding,
      sourceVersionOrder: "ordered-integer" as const,
    };
    const versionContext = [
      { ...context.declarations[0], binding: versionedBinding },
    ];
    const withVersion = (
      id: string,
      value: string,
      version: string,
      days: number,
    ) => ({
      ...observed(id, id, value, days),
      declaration: versionedBinding,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: version },
    });
    const newer = plan(
      [
        {
          ...withVersion("old", "X", "11", 1),
          revision: {
            ...withVersion("old", "X", "11", 1).revision,
            logical: 99,
          },
        },
        withVersion("new", "Y", "12", 0),
      ],
      { declarations: versionContext },
    );
    expect(newer.records[0].current?.revision.operationId).toBe("new");
    const staleLate = plan(
      [withVersion("new", "X", "12", 0), withVersion("stale", "Y", "11", 6)],
      { declarations: versionContext },
    );
    expect(staleLate.records[0].current?.revision.operationId).toBe("new");
    const sameContent = plan(
      [withVersion("old", "X", "11", 0), withVersion("new", "X", "12", 1)],
      { declarations: versionContext },
    );
    expect(sameContent.records[0].state).toBe("settled");
    const equalVersion = plan(
      [withVersion("a", "X", "12", 0), withVersion("b", "Y", "12", 0)],
      { declarations: versionContext },
    );
    expect(equalVersion.records[0].state).toBe("conflict");
    expect(equalVersion.conflicts).toHaveLength(1);
    const independent = plan(
      [
        withVersion("a", "X", "12", 0),
        {
          ...observed("b", "B", "Y", 1),
          declaration: versionedBinding,
          sourceVersion: { domain: "q", incarnation: "e1", value: "99" },
        },
      ],
      { declarations: versionContext },
    );
    expect(independent.records[0].state).toBe("settled");
  });
  it("N03-N06: old disagreements settle by time and close disagreements request re-observation", () => {
    const threeHours = plan([
      observedMs("a", "A", "X", 0),
      observedMs("b", "B", "Y", 3 * 60 * 60_000),
    ]);
    expect(threeHours.records[0].state).toBe("settled");
    const close = plan([
      observedMs("a", "A", "X", 0),
      observedMs("b", "B", "Y", 30_000),
    ]);
    expect(close.records[0].refreshRequested).toBe(true);
    expect(
      plan([
        observed("a", "A", "X"),
        observed("b", "B", "Y", 1),
        observed("c", "C", "Y", 2),
      ]).records[0].state,
    ).toBe("settled");
    expect(
      plan([
        observed("a", "A", "X"),
        observed("b", "B", "Y", 1),
        observed("c", "C", "X", 2),
      ]).records[0].current?.revision.operationId,
    ).toBe("c");
  });
  it("N07-N08 and fixture 18: finality caps future clocks; fixture 18 reverses its prior display", () => {
    const old = observed("a", "A", "X", -10_000);
    const fast = {
      ...observed("b", "B", "Y", 8),
      revision: {
        ...observed("b", "B", "Y", 8).revision,
        wallMs: Date.parse("2099-01-01T00:00:00Z"),
      },
    };
    const result = plan([old, fast], { finalizedAt: () => T0 + 7 * day });
    expect(result.records[0].current?.revision.operationId).toBe("b"); // Fixture 18 reversal: bounded 2099 beats the year-2000 observation.
    expect(
      plan([observed("a", "A", "X", 6), observed("b", "B", "Y", 3)]).records[0]
        .current?.revision.operationId,
    ).toBe("a");
  });
  it("N09-N12: source deletion orders like any observation; uncertainty rechecks or escalates only when re-observation is unavailable", () => {
    expect(
      plan([sourceDelete("del", "A", 2), observed("stale", "B", "X", 0, 900)])
        .records[0].current?.kind,
    ).toBe("source-delete");
    expect(
      plan([sourceDelete("del", "A", 0), observed("new", "B", "Y", 2)])
        .records[0].current?.revision.operationId,
    ).toBe("new");
    const closeDelete = plan([
      sourceDelete("del", "A", 0),
      observed("new", "B", "Y", 0, 1),
    ]).records[0];
    expect(closeDelete.state).toBe("unsettled");
    expect(appView(closeDelete)).toBeNull();
    const nonReobservable = { ...binding, reobservable: false };
    const result = plan(
      [
        { ...observed("a", "A", "X"), declaration: nonReobservable },
        { ...observed("b", "B", "Y", 0, 1), declaration: nonReobservable },
      ],
      {
        declarations: [
          { ...context.declarations[0], binding: nonReobservable },
        ],
      },
    );
    expect(result.records[0].state).toBe("conflict");
  });
  it("N13-N16: owner removal is remove-wins, restore names removals, and deletion erases after the grace period", () => {
    const item = observed("a", "A", "X");
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...ownerBase
    } = item;
    const hide = {
      ...ownerBase,
      kind: "owner-hide" as const,
      parents: [],
      revision: { ...item.revision, operationId: "hide" },
    };
    const hidden = plan([item, hide]).records[0];
    expect(hidden.ownerControl).toBe("hidden");
    expect(appView(hidden)).toBeNull();
    expect(hidden.payloadRetained).toBe(true);
    const del = {
      ...hide,
      kind: "owner-delete" as const,
      revision: { ...hide.revision, operationId: "owner-delete" },
      batchId: "delete-batch",
    };
    const erased = plan([item, del], {
      now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 1,
      finalizedAt: () => T0,
    }).records[0];
    expect(erased.ownerControl).toBe("deleted");
    expect(erased.payloadRetained).toBe(false);
    expect(erased.suppressionMarker?.observations[0]).toMatchObject({
      operationId: "a",
      contentHash: expect.stringMatching(/^sha256:/),
    });
    expect(erased.suppressionMarker?.removals).toEqual([
      { operationId: "owner-delete", deletedAt: T0, finalizedAt: T0 },
    ]);
    const restore = {
      ...hide,
      kind: "owner-restore" as const,
      parents: ["hide"],
      revision: { ...hide.revision, operationId: "restore" },
    };
    expect(plan([item, hide, restore]).records[0].ownerControl).toBe("visible");
    const deleteOp = {
      ...del,
      revision: { ...del.revision, wallMs: T0 },
      batchId: "delete-batch",
    };
    const postPurgeRestore = {
      ...hide,
      kind: "owner-restore" as const,
      parents: ["owner-delete"],
      revision: {
        ...hide.revision,
        wallMs: T0 + 31 * day,
        operationId: "restore-after-purge",
      },
    };
    const afterPurge = plan(
      [
        item,
        deleteOp,
        postPurgeRestore,
        observed("after-purge", "C", "new", 32),
      ],
      { now: T0 + 31 * day, finalizedAt: () => T0 },
    );
    expect(afterPurge.records[0].current?.revision.operationId).toBe(
      "after-purge",
    );
    expect(afterPurge.records[0].payloadRetained).toBe(true);
    const laterRemoval = {
      ...hide,
      revision: { ...hide.revision, operationId: "concurrent-hide" },
    };
    expect(
      plan([item, hide, restore, laterRemoval]).records[0].ownerControl,
    ).toBe("hidden");
  });
  it("keeps owner resolutions explicit, waits for their dependencies, and exposes competing choices", () => {
    const a = observed("a", "A", "X");
    const b = observed("b", "B", "Y", 1);
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...base
    } = a;
    const resolution = {
      ...base,
      kind: "owner-resolve" as const,
      candidates: ["a", "b"],
      choice: "a",
      resolvedValue: {
        kind: "upsert" as const,
        data: a.data,
        blobs: a.blobs,
        contentHash: a.contentHash,
      },
      revision: { ...a.revision, operationId: "resolve-a" },
    };
    const chosen = plan([a, b, resolution]);
    expect(chosen.records[0].current?.revision.operationId).toBe("resolve-a");
    const pending = plan([a, { ...resolution, candidates: ["a", "missing"] }]);
    expect(pending.pending[0].reason).toBe("resolution_dependency_missing");
    expect(pending.records[0].current?.revision.operationId).toBe("a");
    const competing = plan([
      a,
      b,
      resolution,
      {
        ...resolution,
        choice: "b",
        resolvedValue: {
          kind: "upsert" as const,
          data: b.data,
          blobs: b.blobs,
          contentHash: b.contentHash,
        },
        revision: {
          ...resolution.revision,
          operationId: "resolve-b",
          writerId: "device-c",
        },
      },
    ]);
    expect(competing.records[0].state).toBe("conflict");
    const samePayloadChoice = {
      ...resolution,
      candidates: ["a", "b", "same-x"],
      resolvedValue: {
        kind: "upsert" as const,
        data: a.data,
        blobs: a.blobs,
        contentHash: a.contentHash,
      },
    };
    const equivalent = plan([
      a,
      b,
      observed("same-x", "device-c", "X"),
      samePayloadChoice,
      {
        ...samePayloadChoice,
        choice: "same-x",
        revision: {
          ...samePayloadChoice.revision,
          operationId: "resolve-same-x",
          writerId: "device-d",
        },
      },
    ]);
    expect(equivalent.records[0].state).toBe("settled");
  });
  it("N17-N19: partial absence is no event and stable account ids ignore login changes", () => {
    expect(plan([observed("a", "A", "X")]).records[0].current?.kind).toBe(
      "upsert",
    );
    const otherAccount = {
      ...observed("wrong", "B", "Y"),
      upstreamAccount: { issuer: "https://github.com", subject: "gh:2002" },
    };
    expect(plan([otherAccount]).quarantined[0].reason).toBe(
      "upstream_account_mismatch",
    );
    const wrongConnectionDelete = {
      ...registration,
      kind: "connection-delete" as const,
      upstreamAccount: otherAccount.upstreamAccount,
      revision: { ...registration.revision, operationId: "wrong-delete" },
    };
    const protectedConnection = plan([
      observed("kept", "A", "X"),
      wrongConnectionDelete,
    ]);
    expect(protectedConnection.suppressed).toEqual([]);
    expect(protectedConnection.quarantined[0].reason).toBe(
      "upstream_account_mismatch",
    );
    const renamed = {
      ...observed("renamed", "B", "Y", 1),
      upstreamAccount: identity.upstreamAccount,
    };
    expect(plan([observed("a", "A", "X"), renamed]).quarantined).toEqual([]);
  });
  it("N20: app projection hides all except visible upsert values", () => {
    const visible = plan([observed("a", "A", "X")]).records[0];
    expect(appView(visible)).not.toBeNull();
    expect(appView({ ...visible, ownerControl: "deleted" })).toBeNull();
    expect(appView({ ...visible, payloadRetained: false })).toBeNull();
  });
  it("N21: received clock advancement is bounded and reports skew", () => {
    // receiveHlc is exercised in revision.test.ts; planning never lets it alter candidate order.
    expect(plan([observed("a", "A", "X")]).records[0].flags).toEqual([]);
  });
  it("N22-N25: held mismatched data, explicit account separation, and unmapped identity fail closed", () => {
    const held = {
      ...observed("held", "B", "Y"),
      upstreamAccount: { issuer: "https://github.com", subject: "gh:2002" },
    };
    expect(plan([held]).quarantined).toHaveLength(1);
    const separateConnection = { ...held, connectionId: "connection-b" };
    const separateRegister = {
      ...registration,
      connectionId: "connection-b",
      upstreamAccount: separateConnection.upstreamAccount,
      revision: { ...registration.revision, operationId: "register-b" },
    };
    expect(
      planReplicaMerge(context, [
        registration,
        separateRegister,
        separateConnection,
      ]).records,
    ).toHaveLength(1);
    expect(plan([observed("a", "A", "X")]).records).toHaveLength(1);
  });
  it("N26: source version incarnation prevents a reset version from dominating old deletion", () => {
    const versionBinding = {
      ...binding,
      sourceVersionOrder: "ordered-integer" as const,
    };
    const declaration = { ...context.declarations[0], binding: versionBinding };
    const del = {
      ...sourceDelete("del", "A", 0),
      declaration: versionBinding,
      sourceVersion: { domain: "cursor", incarnation: "1", value: "12" },
    };
    const next = {
      ...observed("next", "B", "Y", 2),
      declaration: versionBinding,
      sourceVersion: { domain: "cursor", incarnation: "2", value: "1" },
    };
    expect(
      plan([del, next], { declarations: [declaration] }).records[0].current
        ?.kind,
    ).toBe("upsert");
  });
  it("N27-N29: complete scans are declared, own-writer order wins, and volatile values can recheck", () => {
    const scan = {
      ...sourceDelete("scan", "A", 0),
      origin: "complete-scan" as const,
    };
    expect(plan([scan]).records[0].state).toBe("unsettled");
    const confirmed = {
      ...sourceDelete("scan-confirmed", "A", 1),
      origin: "complete-scan" as const,
      confirmationOf: "scan",
    };
    expect(plan([scan, confirmed]).records[0].current?.kind).toBe(
      "source-delete",
    );
    const ownWriter = plan([
      observed("a", "A", "X"),
      observed("b", "A", "Y", 0, 1),
    ]).records[0];
    expect(ownWriter.current?.revision.operationId).toBe("b");
    expect(ownWriter.state).toBe("settled");
    expect(
      plan([observed("a", "A", "X"), observed("b", "B", "Y", 0, 1)]).records[0]
        .refreshRequested,
    ).toBe(true);
    expect(
      plan([observed("a", "A", "X"), observed("b", "B", "Y", 0, 1)], {
        reobservedRecordKeys: ["same-key"],
      }).records[0].refreshRequested,
    ).toBe(false);
  });
});

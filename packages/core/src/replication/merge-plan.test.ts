import { describe, expect, it } from "vitest";
import {
  appView,
  OWNER_DELETE_GRACE_PERIOD_MS,
  planReplicaMerge,
} from "./merge-plan.js";
import { binding, identity, registration, T0, upsert } from "./fixtures.js";
import { receiveHlc } from "./revision.js";
import { resolveLocalInstance } from "./identity.js";
import type { RecordOperation, ReplicaOperation } from "./envelope.js";

const context = {
  owner: identity.owner,
  connectorPrincipals: [
    {
      sourceId: identity.sourceId,
      connectionId: identity.connectionId,
      upstreamAccount: identity.upstreamAccount,
    },
  ],
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
const ref = (operationId: string, writerId: string) => ({
  writerId,
  operationId,
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
      {
        writerId: "A",
        operationId: "owner-delete",
        deletedAt: T0,
        finalizedAt: T0,
      },
    ]);
    const restore = {
      ...hide,
      kind: "owner-restore" as const,
      parents: [ref("hide", "A")],
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
      parents: [ref("owner-delete", "A")],
      revision: {
        ...hide.revision,
        wallMs: T0 + 31 * day,
        operationId: "restore-after-purge",
      },
    };
    const afterPurgeObservation = {
      ...observed("after-purge", "C", "new", 32),
      frontier: { A: { wallMs: T0 + 31 * day, logical: 0 } },
    };
    const afterPurge = plan(
      [item, deleteOp, postPurgeRestore, afterPurgeObservation],
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
  it("keeps a pre-expiry restore and erasure irreversible after the deadline", () => {
    const item = observed("expiry-item", "A", "payload");
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...ownerBase
    } = item;
    const deletion = {
      ...ownerBase,
      kind: "owner-delete" as const,
      parents: [],
      batchId: "expiry-delete-batch",
      revision: { ...item.revision, operationId: "expiry-delete" },
    };
    const restoredBeforeExpiry = {
      ...ownerBase,
      kind: "owner-restore" as const,
      parents: [ref("expiry-delete", "A")],
      revision: {
        ...item.revision,
        operationId: "restore-before-expiry",
        wallMs: T0 + day,
      },
    };
    const afterDeadline = T0 + 31 * day;
    const retainedRestore = planReplicaMerge(
      { ...context, now: afterDeadline, finalizedAt: () => T0 },
      [registration, item, deletion, restoredBeforeExpiry],
    );
    expect(retainedRestore.records[0].ownerControl).toBe("visible");
    expect(retainedRestore.records[0].current?.revision.operationId).toBe(
      "expiry-item",
    );
    expect(retainedRestore.records[0].payloadRetained).toBe(true);
    expect(retainedRestore.payloadErasures).toEqual([]);

    const erased = planReplicaMerge(
      { ...context, now: afterDeadline, finalizedAt: () => T0 },
      [registration, item, deletion],
    );
    expect(erased.records[0].payloadRetained).toBe(false);
    expect(erased.payloadErasures[0].operationReferences).toContainEqual(
      ref("expiry-item", "A"),
    );
    const restoredAfterErasure = planReplicaMerge(
      {
        ...context,
        now: afterDeadline + day,
        finalizedAt: () => T0,
        suppressionMarkers: erased.records[0].suppressionMarker
          ? [erased.records[0].suppressionMarker]
          : [],
      },
      [
        registration,
        deletion,
        {
          ...restoredBeforeExpiry,
          revision: {
            ...restoredBeforeExpiry.revision,
            operationId: "restore-after-erasure",
            wallMs: afterDeadline + day,
          },
        },
      ],
    );
    expect(restoredAfterErasure.records[0].ownerControl).toBe("visible");
    expect(restoredAfterErasure.records[0].payloadRetained).toBe(false);
    expect(restoredAfterErasure.records[0].current).toBeNull();
    expect(restoredAfterErasure.payloadErasures).toEqual([]);
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
      candidates: [ref("a", "A"), ref("b", "B")],
      choice: ref("a", "A"),
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
    const deleteResolution = {
      ...resolution,
      candidates: [ref("a", "A")],
      resolvedValue: {
        kind: "source-delete" as const,
        contentHash: a.contentHash,
      },
      revision: { ...resolution.revision, operationId: "resolve-delete" },
    };
    const resolvedDelete = plan([a, deleteResolution]).records[0].current;
    expect(resolvedDelete?.kind).toBe("source-delete");
    expect(resolvedDelete).not.toHaveProperty("data");
    expect(resolvedDelete).not.toHaveProperty("blobs");
    const pending = plan([
      a,
      {
        ...resolution,
        candidates: [ref("a", "A"), ref("missing", "B")],
      },
    ]);
    expect(pending.pending[0].reason).toBe("resolution_dependency_missing");
    expect(pending.records[0].current?.revision.operationId).toBe("a");
    const competing = plan([
      a,
      b,
      resolution,
      {
        ...resolution,
        choice: ref("b", "B"),
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
    const settleCompeting = {
      ...resolution,
      candidates: [ref("resolve-a", "A"), ref("resolve-b", "device-c")],
      choice: ref("resolve-a", "A"),
      resolvedValue: resolution.resolvedValue,
      frontier: {
        A: {
          wallMs: resolution.revision.wallMs,
          logical: resolution.revision.logical,
        },
        "device-c": {
          wallMs: resolution.revision.wallMs,
          logical: resolution.revision.logical,
        },
      },
      revision: {
        ...resolution.revision,
        operationId: "resolve-settled",
        writerId: "device-e",
      },
    };
    expect(
      plan([
        a,
        b,
        resolution,
        {
          ...resolution,
          choice: ref("b", "B"),
          revision: {
            ...resolution.revision,
            operationId: "resolve-b",
            writerId: "device-c",
          },
          resolvedValue: {
            kind: "upsert" as const,
            data: b.data,
            blobs: b.blobs,
            contentHash: b.contentHash,
          },
        },
        settleCompeting,
      ]).records[0].state,
    ).toBe("settled");
    const samePayloadChoice = {
      ...resolution,
      candidates: [ref("a", "A"), ref("b", "B"), ref("same-x", "device-c")],
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
        choice: ref("same-x", "device-c"),
        revision: {
          ...samePayloadChoice.revision,
          operationId: "resolve-same-x",
          writerId: "device-d",
        },
      },
    ]);
    expect(equivalent.records[0].state).toBe("settled");
  });
  it("validates resolution payloads and record-scoped dependencies before materializing", () => {
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
      candidates: [ref("a", "A"), ref("b", "B")],
      choice: ref("a", "A"),
      resolvedValue: {
        kind: "upsert" as const,
        data: { id: "other-key", text: "bad" },
        blobs: [],
        contentHash: a.contentHash,
      },
      revision: { ...a.revision, operationId: "resolve-invalid" },
    };
    expect(plan([a, b, resolution]).rejected).toContainEqual(
      expect.objectContaining({ reason: "invalid_resolution_data" }),
    );
    const otherRecord = {
      ...observed("other", "C", "Z"),
      connectionId: "other-connection",
    };
    const outOfScope = {
      ...resolution,
      candidates: [ref("a", "A"), ref("other", "C")],
      choice: ref("a", "A"),
      resolvedValue: {
        kind: "upsert" as const,
        data: a.data,
        blobs: a.blobs,
        contentHash: a.contentHash,
      },
    };
    expect(plan([a, otherRecord, outOfScope]).pending).toContainEqual(
      expect.objectContaining({ reason: "resolution_dependency_out_of_scope" }),
    );
    const rejectedChoice = {
      ...b,
      data: { id: "wrong-key", text: "invalid dependency" },
    };
    const resolutionWithRejectedChoice = {
      ...resolution,
      candidates: [ref("a", "A"), ref("b", "B")],
      choice: ref("b", "B"),
      resolvedValue: {
        kind: "upsert" as const,
        data: a.data,
        blobs: a.blobs,
        contentHash: a.contentHash,
      },
      revision: {
        ...resolution.revision,
        operationId: "resolve-rejected-choice",
      },
    };
    const rejectedChoicePlan = plan([
      a,
      rejectedChoice,
      resolutionWithRejectedChoice,
    ]);
    expect(rejectedChoicePlan.rejected).toContainEqual(
      expect.objectContaining({ reason: "invalid_record_data" }),
    );
    expect(rejectedChoicePlan.pending).toContainEqual(
      expect.objectContaining({ reason: "resolution_dependency_rejected" }),
    );
    expect(rejectedChoicePlan.records[0].current?.revision.operationId).toBe(
      "a",
    );
    const invalidA = { ...a, data: { id: "invalid-a", text: "bad" } };
    const invalidB = { ...b, data: { id: "invalid-b", text: "bad" } };
    const allRejected = plan([
      invalidA,
      invalidB,
      {
        ...resolutionWithRejectedChoice,
        candidates: [ref("a", "A"), ref("b", "B")],
        choice: ref("a", "A"),
        revision: {
          ...resolution.revision,
          operationId: "resolve-all-rejected",
        },
      },
    ]);
    expect(allRejected.records).toEqual([]);
    expect(allRejected.pending).toContainEqual(
      expect.objectContaining({ reason: "resolution_dependency_rejected" }),
    );
  });
  it("keeps removal references writer-qualified when operation ids collide", () => {
    const item = observed("item", "A", "X");
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...base
    } = item;
    const removalA = {
      ...base,
      kind: "owner-hide" as const,
      revision: {
        ...base.revision,
        operationId: "shared-removal",
        writerId: "A",
      },
      parents: [],
    };
    const removalB = {
      ...removalA,
      revision: { ...removalA.revision, writerId: "B" },
    };
    const restoreA = {
      ...removalA,
      kind: "owner-restore" as const,
      revision: { ...removalA.revision, operationId: "restore", writerId: "C" },
      parents: [ref("shared-removal", "A")],
    };
    expect(
      plan([item, removalA, removalB, restoreA]).records[0].ownerControl,
    ).toBe("hidden");
  });
  it("retains no expired payload in conflict diagnostics or restores skewed old writes", () => {
    const versionBinding = {
      ...binding,
      sourceVersionOrder: "ordered-integer" as const,
    };
    const declaration = { ...context.declarations[0], binding: versionBinding };
    const old = {
      ...observed("old", "A", "X"),
      declaration: versionBinding,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "1" },
    };
    const variant = {
      ...observed("variant", "B", "Y"),
      declaration: versionBinding,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "1" },
    };
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      sourceVersion: _sourceVersion,
      ...base
    } = old;
    const del = {
      ...base,
      kind: "owner-delete" as const,
      parents: [],
      batchId: "erase-batch",
      revision: { ...old.revision, operationId: "erase" },
    };
    const resolution = {
      ...base,
      kind: "owner-resolve" as const,
      candidates: [ref("old", "A")],
      choice: ref("old", "A"),
      resolvedValue: {
        kind: "upsert" as const,
        data: old.data,
        blobs: old.blobs,
        contentHash: old.contentHash,
      },
      revision: { ...old.revision, operationId: "resolution-payload" },
    };
    const expired = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 1,
        finalizedAt: () => T0,
      },
      [registration, old, variant, resolution, del],
    );
    expect(expired.conflicts.flatMap((issue) => issue.operations)).toEqual([]);
    expect(expired.records[0].candidates).toEqual([]);
    expect(JSON.stringify(expired)).not.toContain('"text":"old"');
    expect(JSON.stringify(expired)).not.toContain('"text":"Y"');
    expect(expired.payloadErasures[0].operationReferences).toEqual(
      [
        ref("old", "A"),
        ref("resolution-payload", "A"),
        ref("variant", "B"),
      ].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    );
    const marker = expired.records[0].suppressionMarker!;
    expect(marker.erasedPayloads).toContainEqual(
      expect.objectContaining({ operationId: "resolution-payload" }),
    );
    const alternateHash = `sha256:${"e".repeat(64)}`;
    const markerWithoutFinality = {
      ...marker,
      erasedPayloads: marker.erasedPayloads
        .map((payload) => ({
          ...payload,
          finalizedAt: null,
        }))
        .concat({
          writerId: "A",
          operationId: "old",
          contentHash: alternateHash,
          observedAt: old.emittedAt,
          finalizedAt: null,
        }),
    };
    const replayedWithFinality = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 2,
        finalizedAt: () => T0,
        suppressionMarkers: [markerWithoutFinality],
      },
      [registration, old, del],
    );
    expect(
      replayedWithFinality.records[0].suppressionMarker?.erasedPayloads,
    ).toContainEqual(
      expect.objectContaining({
        operationId: "old",
        contentHash: old.contentHash,
        finalizedAt: T0,
      }),
    );
    expect(
      replayedWithFinality.records[0].suppressionMarker?.erasedPayloads,
    ).toContainEqual(
      expect.objectContaining({
        operationId: "old",
        contentHash: alternateHash,
        finalizedAt: null,
      }),
    );
    expect(
      replayedWithFinality.records[0].suppressionMarker?.erasedPayloads,
    ).not.toContainEqual(
      expect.objectContaining({
        operationId: "old",
        contentHash: old.contentHash,
        observedAt: old.emittedAt,
        finalizedAt: null,
      }),
    );
    const reverseReplayWithFinality = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 2,
        finalizedAt: () => T0,
        suppressionMarkers: [markerWithoutFinality],
      },
      [del, old, registration],
    );
    expect(reverseReplayWithFinality.records[0].suppressionMarker).toEqual(
      replayedWithFinality.records[0].suppressionMarker,
    );
    const compactedResolutionReload = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 1,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [registration, del],
    );
    expect(JSON.stringify(compactedResolutionReload)).not.toContain(
      '"text":"old"',
    );
    expect(compactedResolutionReload.records[0].suppressionMarker).toEqual(
      marker,
    );
    const restoreAfterCompaction = {
      ...del,
      kind: "owner-restore" as const,
      parents: [ref("erase", "A")],
      revision: { ...del.revision, operationId: "restore-after-compaction" },
    };
    const freshAfterCompaction = {
      ...observed("fresh-after-compaction", "C", "fresh", 32),
      declaration: versionBinding,
      frontier: {
        A: {
          wallMs: restoreAfterCompaction.revision.wallMs,
          logical: restoreAfterCompaction.revision.logical,
        },
      },
    };
    const restoredWithErasedResolution = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 32 * day,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [
        registration,
        del,
        restoreAfterCompaction,
        freshAfterCompaction,
        resolution,
      ],
    );
    expect(restoredWithErasedResolution.records[0].payloadRetained).toBe(true);
    expect(
      restoredWithErasedResolution.payloadErasures[0].operationReferences,
    ).toContainEqual(ref("resolution-payload", "A"));
    expect(
      restoredWithErasedResolution.payloadErasures[0].operationReferences,
    ).not.toContainEqual(ref("fresh-after-compaction", "C"));
    expect(JSON.stringify(restoredWithErasedResolution.pending)).not.toContain(
      '"text":"old"',
    );
    const replayedAfterCompaction = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 1,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [registration, old, variant, resolution, del],
    );
    expect(replayedAfterCompaction.records[0].candidates).toEqual([]);
    const late = {
      ...observed("late-after-delete", "C", "late"),
      declaration: versionBinding,
    };
    const latePlan = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 2,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [registration, del, late],
    );
    expect(latePlan.records[0].candidates).toEqual([]);
    expect(latePlan.records[0].suppressionMarker?.observations).toContainEqual(
      expect.objectContaining({
        operationId: "late-after-delete",
        writerId: "C",
      }),
    );
    expect(latePlan.payloadErasures[0].operationReferences).toContainEqual(
      ref("late-after-delete", "C"),
    );

    const skewedOld = {
      ...old,
      revision: { ...old.revision, writerId: "B", wallMs: T0 + 100 * day },
    };
    const restore = {
      ...del,
      kind: "owner-restore" as const,
      revision: {
        ...del.revision,
        operationId: "restore",
        wallMs: T0 + 31 * day,
      },
      parents: [ref("erase", old.revision.writerId)],
    };
    const restoredWithoutFreshEvidence = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 31 * day,
        finalizedAt: () => T0,
      },
      [registration, skewedOld, del, restore],
    );
    const restored = restoredWithoutFreshEvidence.records[0];
    expect(restored.payloadRetained).toBe(false);
    expect(restored.current).toBeNull();
    expect(restored.suppressionMarker?.identity).toEqual(restored.identity);
    expect(
      restoredWithoutFreshEvidence.payloadErasures[0].operationReferences,
    ).toContainEqual(ref("old", "B"));
    expect(restored.suppressionMarker?.erasedPayloads).toContainEqual(
      expect.objectContaining({ operationId: "old", writerId: "B" }),
    );
    const observedAfterRestore = {
      ...observed("new-after-restore", "C", "fresh", 32),
      declaration: versionBinding,
      frontier: {
        A: {
          wallMs: restore.revision.wallMs,
          logical: restore.revision.logical,
        },
      },
    };
    const restoredPlan = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 31 * day,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [registration, old, del, restore, observedAfterRestore],
    );
    const restoredWithNewEvidence = restoredPlan.records[0];
    expect(restoredWithNewEvidence.ownerControl).toBe("visible");
    expect(restoredWithNewEvidence.current?.revision.operationId).toBe(
      "new-after-restore",
    );
    expect(restoredWithNewEvidence.payloadRetained).toBe(true);
    expect(restoredPlan.payloadErasures[0].operationReferences).toContainEqual(
      ref("old", "A"),
    );
    expect(
      restoredPlan.payloadErasures[0].operationReferences,
    ).not.toContainEqual(ref("new-after-restore", "C"));
    const markerAfterRestore = restoredWithNewEvidence.suppressionMarker!;
    expect(markerAfterRestore.erasedOperations).toContainEqual(ref("old", "A"));
    expect(markerAfterRestore.erasedOperations).not.toContainEqual(
      ref("new-after-restore", "C"),
    );
    const replayedAfterRestore = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 31 * day,
        finalizedAt: () => T0,
        suppressionMarkers: [markerAfterRestore],
      },
      [registration, del, restore, observedAfterRestore],
    ).records[0];
    expect(replayedAfterRestore.current?.revision.operationId).toBe(
      "new-after-restore",
    );
    expect(replayedAfterRestore.payloadRetained).toBe(true);

    const postRestoreResolution = {
      ...resolution,
      revision: {
        ...resolution.revision,
        writerId: "D",
        operationId: "fresh-resolution-after-restore",
        wallMs: restore.revision.wallMs + 2,
      },
      candidates: [ref("new-after-restore", "C")],
      choice: ref("new-after-restore", "C"),
      resolvedValue: {
        kind: "upsert" as const,
        data: observedAfterRestore.data,
        blobs: observedAfterRestore.blobs,
        contentHash: observedAfterRestore.contentHash,
      },
      frontier: {
        A: {
          wallMs: restore.revision.wallMs,
          logical: restore.revision.logical,
        },
        C: {
          wallMs: observedAfterRestore.revision.wallMs,
          logical: observedAfterRestore.revision.logical,
        },
      },
    };
    const restoredWithFreshResolution = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 31 * day,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [
        registration,
        old,
        del,
        restore,
        observedAfterRestore,
        postRestoreResolution,
      ],
    );
    expect(
      restoredWithFreshResolution.records[0].current?.revision.operationId,
    ).toBe("fresh-resolution-after-restore");
    expect(restoredWithFreshResolution.records[0].payloadRetained).toBe(true);
    expect(
      restoredWithFreshResolution.payloadErasures[0].operationReferences,
    ).not.toContainEqual(ref("fresh-resolution-after-restore", "D"));

    const secondDelete = {
      ...del,
      batchId: "erase-second-batch",
      revision: {
        ...del.revision,
        operationId: "erase-second-epoch",
        writerId: "B",
        wallMs: restore.revision.wallMs + 3,
      },
    };
    const secondRestore = {
      ...restore,
      revision: {
        ...restore.revision,
        operationId: "restore-second-epoch",
        writerId: "C",
        wallMs: restore.revision.wallMs + 4,
      },
      parents: [ref("erase-second-epoch", "B")],
    };
    const beforeSecondRestore = {
      ...observed("between-restores", "D", "too-old", 32),
      declaration: versionBinding,
      frontier: {
        A: {
          wallMs: restore.revision.wallMs,
          logical: restore.revision.logical,
        },
      },
    };
    const freshAfterSecondRestore = {
      ...observed("after-second-restore", "E", "fresh-again", 34),
      declaration: versionBinding,
      frontier: {
        A: {
          wallMs: restore.revision.wallMs,
          logical: restore.revision.logical,
        },
        C: {
          wallMs: secondRestore.revision.wallMs,
          logical: secondRestore.revision.logical,
        },
      },
    };
    const multipleEpochs = planReplicaMerge(
      {
        ...context,
        declarations: [declaration],
        now: T0 + 33 * day,
        finalizedAt: () => T0,
        suppressionMarkers: [marker],
      },
      [
        registration,
        old,
        del,
        restore,
        beforeSecondRestore,
        secondDelete,
        secondRestore,
        freshAfterSecondRestore,
      ],
    );
    expect(multipleEpochs.records[0].payloadRetained).toBe(true);
    expect(multipleEpochs.records[0].current?.revision.operationId).toBe(
      "after-second-restore",
    );
    expect(
      multipleEpochs.payloadErasures[0].operationReferences,
    ).toContainEqual(ref("between-restores", "D"));
    expect(
      multipleEpochs.payloadErasures[0].operationReferences,
    ).not.toContainEqual(ref("after-second-restore", "E"));
  });
  it("confirms versioned complete-scan deletes before they participate in source ordering", () => {
    const versionBinding = {
      ...binding,
      sourceVersionOrder: "ordered-integer" as const,
    };
    const declaration = { ...context.declarations[0], binding: versionBinding };
    const current = {
      ...observed("current", "B", "X"),
      declaration: versionBinding,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "11" },
    };
    const first = {
      ...sourceDelete("scan-first", "A", 1),
      declaration: versionBinding,
      origin: "complete-scan" as const,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "12" },
    };
    const pending = plan([current, first], { declarations: [declaration] })
      .records[0];
    expect(pending.current?.revision.operationId).toBe("current");
    expect(pending.state).toBe("unsettled");
    const second = {
      ...sourceDelete("scan-second", "A", 1, 1),
      declaration: versionBinding,
      origin: "complete-scan" as const,
      confirmationOf: ref("scan-first", "A"),
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "12" },
    };
    const confirmed = plan([current, first, second], {
      declarations: [declaration],
    }).records[0];
    expect(confirmed.current?.kind).toBe("source-delete");
    expect(confirmed.state).toBe("settled");
    expect(confirmed.refreshRequested).toBe(false);
    const receivedConfirmation = {
      ...second,
      revision: {
        ...second.revision,
        writerId: "B",
        wallMs: T0,
        logical: 0,
      },
      frontier: {
        A: {
          wallMs: first.revision.wallMs,
          logical: first.revision.logical,
        },
      },
    };
    expect(
      plan([current, first, receivedConfirmation], {
        declarations: [declaration],
      }).records[0].current?.kind,
    ).toBe("source-delete");
  });
  it("compares declared RFC3339 versions and resolution observations by instant", () => {
    const rfcBinding = {
      ...binding,
      sourceVersionOrder: "ordered-rfc3339" as const,
    };
    const declaration = { ...context.declarations[0], binding: rfcBinding };
    const a = {
      ...observed("rfc-a", "A", "X"),
      declaration: rfcBinding,
      sourceVersion: {
        domain: "cursor",
        incarnation: "e1",
        value: "2026-10-21T10:00:00+02:00",
      },
    };
    const b = {
      ...observed("rfc-b", "B", "Y"),
      declaration: rfcBinding,
      sourceVersion: {
        domain: "cursor",
        incarnation: "e1",
        value: "2026-10-21T07:30:00Z",
      },
    };
    expect(
      plan([a, b], { declarations: [declaration] }).records[0].current?.revision
        .operationId,
    ).toBe("rfc-a");
    const invalid = {
      ...a,
      revision: { ...a.revision, operationId: "invalid-rfc" },
      sourceVersion: { ...a.sourceVersion, value: "October 21 2026" },
    };
    expect(
      plan([invalid], { declarations: [declaration] }).rejected,
    ).toContainEqual(
      expect.objectContaining({ reason: "invalid_source_version" }),
    );
    const preciseEarlier = {
      ...a,
      revision: { ...a.revision, operationId: "precise-earlier" },
      sourceVersion: { ...a.sourceVersion, value: "2026-10-21T10:00:00.0001Z" },
    };
    const preciseLater = {
      ...b,
      revision: { ...b.revision, operationId: "precise-later" },
      sourceVersion: { ...b.sourceVersion, value: "2026-10-21T10:00:00.0002Z" },
    };
    expect(
      plan([preciseEarlier, preciseLater], { declarations: [declaration] })
        .records[0].current?.revision.operationId,
    ).toBe("precise-later");
    const invalidCalendar = {
      ...a,
      revision: { ...a.revision, operationId: "invalid-calendar" },
      sourceVersion: {
        ...a.sourceVersion,
        value: "2026-02-30T10:00:00Z",
      },
    };
    expect(
      plan([invalidCalendar], { declarations: [declaration] }).rejected,
    ).toContainEqual(
      expect.objectContaining({ reason: "invalid_source_version" }),
    );
    const emittedEarlier = {
      ...observed("emitted-earlier", "A", "X"),
      declaration: rfcBinding,
      revision: {
        ...observed("emitted-earlier", "A", "X").revision,
        logical: 100,
      },
      emittedAt: "2026-10-21T10:00:00.0001Z",
    };
    const emittedLater = {
      ...observed("emitted-later", "B", "Y"),
      declaration: rfcBinding,
      revision: { ...observed("emitted-later", "B", "Y").revision, logical: 1 },
      emittedAt: "2026-10-21T10:00:00.0002Z",
    };
    expect(
      plan([emittedEarlier, emittedLater], {
        declarations: [declaration],
        finalizedAt: () => undefined,
      }).records[0].current?.revision.operationId,
    ).toBe("emitted-later");

    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      sourceVersion: _sourceVersion,
      ...base
    } = a;
    const resolution = {
      ...base,
      kind: "owner-resolve" as const,
      candidates: [ref("rfc-a", "A"), ref("rfc-b", "B")],
      choice: ref("rfc-a", "A"),
      resolvedValue: {
        kind: "upsert" as const,
        data: a.data,
        blobs: a.blobs,
        contentHash: a.contentHash,
      },
      revision: { ...a.revision, operationId: "rfc-resolution" },
    };
    const timeA = "2026-10-21T10:00:00.0001Z";
    const timeB = "2026-10-21T10:00:00.0002Z";
    const resolved = plan(
      [{ ...a, emittedAt: timeA }, { ...b, emittedAt: timeB }, resolution],
      { declarations: [declaration] },
    ).records[0].current;
    expect(resolved?.kind).toBe("upsert");
    expect(resolved?.emittedAt).toBe(timeB);
  });
  it("preserves append-only deletion rejection and full-history conflict quarantine", () => {
    const appendOnly = { ...binding, semantics: "append_only" as const };
    const declaration = { ...context.declarations[0], binding: appendOnly };
    const deleted = {
      ...sourceDelete("append-delete", "A", 0),
      declaration: appendOnly,
    };
    expect(
      plan([deleted], { declarations: [declaration] }).rejected,
    ).toContainEqual(expect.objectContaining({ reason: "append_only_delete" }));
    const orderedBinding = {
      ...appendOnly,
      sourceVersionOrder: "ordered-integer" as const,
    };
    const orderedDeclaration = { ...declaration, binding: orderedBinding };
    const old = {
      ...observed("append-old", "A", "X"),
      declaration: orderedBinding,
    };
    const newer = {
      ...observed("append-new", "B", "Y", 1),
      declaration: orderedBinding,
      sourceVersion: { domain: "cursor", incarnation: "e1", value: "2" },
    };
    expect(
      plan(
        [
          {
            ...old,
            declaration: orderedBinding,
            sourceVersion: { domain: "cursor", incarnation: "e1", value: "1" },
          },
          newer,
        ],
        { declarations: [orderedDeclaration] },
      ).records[0].state,
    ).toBe("quarantined");
  });
  it("erases expired records across connection deletion and generation retirement", () => {
    const item = observed("lifecycle-payload", "A", "X");
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...base
    } = item;
    const deletion = {
      ...base,
      kind: "owner-delete" as const,
      parents: [],
      batchId: "lifecycle-delete-batch",
      revision: { ...item.revision, operationId: "lifecycle-delete" },
    };
    const expiredContext = {
      ...context,
      now: T0 + OWNER_DELETE_GRACE_PERIOD_MS + 1,
      finalizedAt: (batchId: string) =>
        batchId === "lifecycle-delete-batch" ? T0 : T0 + 100 * day,
    };
    const connectionDelete = {
      ...registration,
      kind: "connection-delete" as const,
      revision: { ...registration.revision, operationId: "delete-connection" },
    };
    const connectionPlan = planReplicaMerge(expiredContext, [
      registration,
      item,
      deletion,
      connectionDelete,
    ]);
    expect(connectionPlan.records).toHaveLength(1);
    expect(connectionPlan.records[0].current).toBeNull();
    expect(connectionPlan.records[0].candidates).toEqual([]);
    expect(appView(connectionPlan.records[0])).toBeNull();
    expect(connectionPlan.payloadErasures).toHaveLength(1);
    expect(
      connectionPlan.payloadErasures[0].operationReferences,
    ).toContainEqual(ref("lifecycle-payload", "A"));
    expect(
      connectionPlan.suppressed
        .flatMap((entry) => entry.operations)
        .filter((op) => op.kind === "upsert" || op.kind === "owner-resolve"),
    ).toEqual([]);
    const markerWithLateReplay = connectionPlan.records[0].suppressionMarker!;
    const lateHiddenReplay = planReplicaMerge(
      { ...expiredContext, suppressionMarkers: [markerWithLateReplay] },
      [
        registration,
        deletion,
        connectionDelete,
        item,
        observed("hidden-late", "C", "late"),
      ],
    );
    expect(lateHiddenReplay.payloadErasures).toHaveLength(1);
    expect(lateHiddenReplay.payloadErasures[0].operationReferences).toEqual(
      expect.arrayContaining([
        ref("lifecycle-payload", "A"),
        ref("hidden-late", "C"),
      ]),
    );
    expect(
      lateHiddenReplay.records[0].suppressionMarker?.erasedPayloads,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ operationId: "lifecycle-payload" }),
        expect.objectContaining({ operationId: "hidden-late" }),
      ]),
    );

    const reset = {
      ...registration,
      kind: "connection-reset" as const,
      previousGeneration: 1,
      generation: 2,
      revision: { ...registration.revision, operationId: "reset-generation" },
    };
    const oldItem = { ...item, generation: 1 };
    const oldDeletion = { ...deletion, generation: 1 };
    const oldItemGenerationTwo = {
      ...observed("lifecycle-payload-g2", "B", "X"),
      generation: 2,
    };
    const oldDeletionGenerationTwo = {
      ...deletion,
      generation: 2,
      revision: {
        ...deletion.revision,
        writerId: "B",
        operationId: "lifecycle-delete-g2",
      },
    };
    const resetTwo = {
      ...reset,
      previousGeneration: 2,
      generation: 3,
      revision: { ...reset.revision, operationId: "reset-generation-three" },
    };
    const retiredInputs = [
      registration,
      reset,
      resetTwo,
      oldItem,
      oldDeletion,
      oldItemGenerationTwo,
      oldDeletionGenerationTwo,
    ];
    const generationPlan = planReplicaMerge(expiredContext, retiredInputs);
    expect(
      generationPlan.payloadErasures.map(
        (erasure) => erasure.identity.generation,
      ),
    ).toEqual([1, 2]);
    const reverseGenerationPlan = planReplicaMerge(
      expiredContext,
      [...retiredInputs].reverse(),
    );
    expect(
      reverseGenerationPlan.payloadErasures.map((erasure) => [
        erasure.identity.generation,
        erasure.operationReferences.map((reference) => reference.operationId),
      ]),
    ).toEqual(
      generationPlan.payloadErasures.map((erasure) => [
        erasure.identity.generation,
        erasure.operationReferences.map((reference) => reference.operationId),
      ]),
    );
    expect(
      generationPlan.suppressed
        .flatMap((entry) => entry.operations)
        .filter((op) => op.kind === "upsert" || op.kind === "owner-resolve"),
    ).toEqual([]);
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
    expect(
      receiveHlc(
        { wallMs: 1_000_000, logical: 4, writerId: "remote", operationId: "r" },
        10,
        300_000,
      ),
    ).toEqual({
      revision: { wallMs: 300_010, logical: 0 },
      clockAhead: true,
    });
    expect(plan([observed("a", "A", "X")]).records[0].flags).toEqual([]);
  });
  it("N22-N25: held mismatched data, explicit account separation, and unmapped identity fail closed", () => {
    const held = {
      ...observed("held", "B", "Y"),
      upstreamAccount: { issuer: "https://github.com", subject: "gh:2002" },
    };
    expect(plan([held]).quarantined).toHaveLength(1);
    const unboundPrincipal = planReplicaMerge(
      { ...context, connectorPrincipals: [] },
      [registration, observed("unmapped", "A", "X")],
    );
    expect(unboundPrincipal.quarantined[0]?.reason).toBe(
      "missing_connector_principal_binding",
    );
    expect(unboundPrincipal.records).toEqual([]);
    const separateConnection = { ...held, connectionId: "connection-b" };
    const separateRegister = {
      ...registration,
      connectionId: "connection-b",
      upstreamAccount: separateConnection.upstreamAccount,
      revision: { ...registration.revision, operationId: "register-b" },
    };
    const separate = planReplicaMerge(
      {
        ...context,
        connectorPrincipals: [
          ...context.connectorPrincipals,
          {
            sourceId: identity.sourceId,
            connectionId: "connection-b",
            upstreamAccount: separateConnection.upstreamAccount,
          },
        ],
      },
      [registration, separateRegister, separateConnection],
    );
    expect(separate.records).toHaveLength(1);
    expect(appView(separate.records[0])).not.toBeNull();
    expect(plan([observed("a", "A", "X")]).records).toHaveLength(1);
    expect(resolveLocalInstance(identity, [])).toBeUndefined();
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
      confirmationOf: ref("scan", "A"),
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
    const close = [observed("a", "A", "X"), sourceDelete("b", "B", 0, 1)];
    const first = plan(close).records[0];
    const throttled = plan(close, { reobservedRecords: [first.identity] })
      .records[0];
    expect(throttled.refreshRequested).toBe(false);
    expect(throttled.state).toBe("unsettled");
    expect(appView(throttled)).toBeNull();
  });
});

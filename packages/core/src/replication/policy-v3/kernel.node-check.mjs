import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  planAdmittedReplicaMerge as plan,
  appView,
  ownerView,
  OWNER_DELETE_GRACE_PERIOD_MS as grace,
} from "./policy-kernel.ts";
import { canonicalJson } from "./canonical.ts";
import {
  conformanceContext as context,
  reducerVectors,
} from "./reducer-vectors.ts";
import { identity, binding, registration, T0, upsert } from "./fixtures.ts";
const record = (ops, ctx = context) =>
  plan(ctx, [registration, ...ops]).records[0];
const ref = (op) => ({
  writerId: op.revision.writerId,
  operationId: op.revision.operationId,
});
const old = upsert("old", 10000, "X", "A", T0);
const fresh = upsert("fresh", 1, "Y", "B", T0 + 600000);
const del = {
  ...identity,
  kind: "source-delete",
  declaration: binding,
  recordKey: old.recordKey,
  emittedAt: new Date(T0).toISOString(),
  contentHash: old.contentHash,
  origin: "source-event",
  revision: { wallMs: T0, logical: 1, writerId: "A", operationId: "del" },
};
const owner = (kind, id, parents = []) => ({
  ...identity,
  kind,
  declaration: binding,
  recordKey: old.recordKey,
  parents,
  batchId: id,
  revision: { wallMs: T0, logical: 1, writerId: "owner", operationId: id },
});
for (const v of reducerVectors)
  test(`trusted kernel order/replay: ${v.name}`, () => {
    const expected = plan(context, v.operations);
    const orders = [
      v.operations,
      [...v.operations].reverse(),
      v.operations.slice(1).concat(v.operations.slice(0, 1)),
      v.operations.flatMap((op) => [op, op]),
    ];
    for (const order of orders) {
      for (let i = 0; i <= order.length; i++) {
        const prefix = order.slice(0, i);
        assert.deepEqual(
          plan(context, prefix),
          plan(context, [...prefix].reverse()),
        );
        assert.deepEqual(
          plan(context, prefix),
          plan(context, [...prefix, ...prefix]),
        );
      }
      assert.deepEqual(plan(context, order), expected);
    }
  });
test("N01 observation freshness beats a busy writer", () =>
  assert.equal(record([old, fresh]).current.revision.operationId, "fresh"));
test("N02 reversed devices still choose observed time", () =>
  assert.equal(
    record([
      { ...old, emittedAt: fresh.emittedAt },
      { ...fresh, emittedAt: old.emittedAt },
    ]).current.revision.operationId,
    "old",
  ));
test("five-minute disagreement boundary is inclusive", () => {
  assert.equal(
    record([old, upsert("b", 1, "Y", "B", T0 + 300000)]).state,
    "unsettled",
  );
  assert.equal(
    record([old, upsert("b", 1, "Y", "B", T0 + 300001)]).state,
    "settled",
  );
});
test("known raw frontier precedes capped observation tie", () => {
  const future = {
    ...old,
    revision: { ...old.revision, wallMs: T0 + 100000000 },
  };
  const after = {
    ...fresh,
    emittedAt: old.emittedAt,
    frontier: {
      A: { wallMs: future.revision.wallMs, logical: future.revision.logical },
    },
  };
  assert.equal(record([future, after]).current.revision.operationId, "fresh");
  assert.equal(record([future, after]).state, "settled");
});
test("no finality cap exists before finality", () => {
  const future = {
    ...fresh,
    batchId: "future",
    emittedAt: new Date(T0 + 100000000).toISOString(),
  };
  assert.equal(
    record([old, future], { ...context, finalizedAt: () => undefined }).current
      .revision.operationId,
    "fresh",
  );
  assert.equal(
    record([old, future], {
      ...context,
      finalizedAt: (id) => (id === "future" ? T0 - 1 : T0),
    }).current.revision.operationId,
    "old",
  );
});
test("confirmed-only app view differs from owner local unsettled preview", () => {
  const r = record([old, upsert("b", 1, "Y", "B", T0)]);
  assert.equal(r.state, "unsettled");
  assert.ok(ownerView(r));
  assert.equal(appView(r, { confirmed: true }), null);
});
test("source-delete disagreement shows no app or owner upsert", () => {
  const r = record([
    { ...old, revision: { ...old.revision, writerId: "C" } },
    del,
  ]);
  assert.equal(r.state, "unsettled");
  assert.equal(appView(r, { confirmed: true }), null);
  assert.equal(ownerView(r), null);
});
test("owner remove wins; restore clears only writer-qualified named removal", () => {
  const d = owner("owner-delete", "same-id");
  const other = { ...d, revision: { ...d.revision, writerId: "other" } };
  const restore = owner("owner-restore", "restore", [ref(d)]);
  assert.equal(record([old, d, other, restore]).ownerControl, "deleted");
  assert.equal(record([old, d, restore]).ownerControl, "visible");
});
test("grace date changes value availability, never current selection or state", () => {
  const d = owner("owner-delete", "delete");
  const before = record([old, d], {
    ...context,
    finalizedAt: () => T0,
    now: T0 + grace - 1,
  });
  const after = record([old, d], {
    ...context,
    finalizedAt: () => T0,
    now: T0 + grace,
  });
  assert.deepEqual(before.current, after.current);
  assert.equal(before.state, after.state);
  assert.ok(before.value);
  assert.equal(after.value, null);
  assert.equal(after.payloadRetained, false);
  assert.equal("data" in after.current, false);
  assert.equal("blobs" in after.current, false);
  assert.ok(after.suppressionMarker);
});
test("forward-skew restore finality before grace retains payload", () => {
  const d = owner("owner-delete", "delete");
  const restore = {
    ...owner("owner-restore", "restore", [ref(d)]),
    revision: {
      wallMs: T0 + grace + 60000,
      logical: 1,
      writerId: "owner",
      operationId: "restore",
    },
  };
  const r = record([old, d, restore], {
    ...context,
    now: T0 + grace + 1,
    finalizedAt: (id) => (id === "restore" ? T0 + grace - 60000 : T0),
  });
  assert.equal(r.payloadRetained, true);
  assert.equal(r.ownerControl, "visible");
});
test("backward-clock restore finalized at exact deadline cannot recover erased payload", () => {
  const d = owner("owner-delete", "delete");
  const restore = owner("owner-restore", "restore", [ref(d)]);
  const r = record([old, d, restore], {
    ...context,
    now: T0 + grace + 1,
    finalizedAt: (id) => (id === "restore" ? T0 + grace : T0),
  });
  assert.equal(r.payloadRetained, false);
  assert.equal(r.value, null);
  assert.ok(r.current);
});
test("same-incarnation counter restart is unsettled against deletion", () => {
  const declared = { ...binding, sourceVersionOrder: "ordered-integer" };
  const ctx = {
    ...context,
    declarations: [{ ...context.declarations[0], binding: declared }],
  };
  const d = {
    ...del,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "12" },
  };
  const recreated = {
    ...fresh,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "1" },
  };
  const r = record([d, recreated], ctx);
  assert.equal(r.state, "unsettled");
  assert.equal(appView(r, { confirmed: true }), null);
  assert.equal(
    record(
      [
        d,
        {
          ...recreated,
          sourceVersion: { ...recreated.sourceVersion, incarnation: "new" },
        },
      ],
      ctx,
    ).state,
    "settled",
  );
});
test("ordered source version dominance beats late observed stale upsert", () => {
  const declared = { ...binding, sourceVersionOrder: "ordered-integer" };
  const ctx = {
    ...context,
    declarations: [{ ...context.declarations[0], binding: declared }],
  };
  const a = {
    ...old,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "12" },
  };
  const b = {
    ...fresh,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "11" },
  };
  assert.equal(record([a, b], ctx).current.revision.operationId, "old");
});
test("equality-only versions detect contradiction but never impose lexical order", () => {
  const declared = { ...binding, sourceVersionOrder: "equality-only" };
  const ctx = {
    ...context,
    declarations: [{ ...context.declarations[0], binding: declared }],
  };
  const a = {
    ...old,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "z" },
  };
  const b = {
    ...fresh,
    declaration: declared,
    sourceVersion: { domain: "cursor", incarnation: "same", value: "a" },
  };
  assert.equal(record([a, b], ctx).current.revision.operationId, "fresh");
  assert.equal(
    record([a, { ...b, sourceVersion: a.sourceVersion }], ctx).state,
    "conflict",
  );
});
test("unconfirmed complete-scan deletion waits for causally later second scan", () => {
  const scan = { ...del, origin: "complete-scan" };
  assert.equal(record([old, scan]).state, "unsettled");
  const second = {
    ...scan,
    confirmationOf: ref(scan),
    revision: { ...scan.revision, logical: 2, operationId: "scan2" },
  };
  assert.equal(record([scan, second]).current.kind, "source-delete");
  assert.equal(record([scan, second]).state, "settled");
});
test("wrong account connection deletion cannot remove good account records", () => {
  const d = {
    ...identity,
    kind: "connection-delete",
    revision: { ...fresh.revision },
    upstreamAccount: { issuer: "other", subject: "other" },
  };
  const r = record([old, d]);
  assert.equal(r.ownerControl, "visible");
  assert.ok(appView(r, { confirmed: true }));
});
test("exact serializer preserves own keys, rejects holes and matches both wire goldens", () => {
  const data = JSON.parse('{"__proto__":{"k":1},"constructor":"value"}');
  assert.equal(
    canonicalJson(data),
    '{"__proto__":{"k":1},"constructor":"value"}',
  );
  assert.throws(() => canonicalJson(new Array(1)), /array hole/);
  for (const file of [
    new URL("../__fixtures__/envelope-v1.json", import.meta.url),
    new URL("./__fixtures__/envelope-v3.json", import.meta.url),
  ]) {
    const v = JSON.parse(readFileSync(file, "utf8"));
    assert.equal(canonicalJson(v.envelope), v.encoded);
  }
});
test("wrong-method deletion is quarantined without suppressing registered method", () => {
  const d = {
    ...identity,
    kind: "connection-delete",
    methodId: "wrong-method",
    revision: { ...fresh.revision, operationId: "wrong-method-delete" },
  };
  const result = plan(context, [registration, old, d]);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].ownerControl, "visible");
  assert.ok(
    result.quarantined.some(
      (x) => x.reason === "incompatible_connection_binding",
    ),
  );
});
test("unbound-source deletion does not poison bound connection identity", () => {
  const d = {
    ...identity,
    kind: "connection-delete",
    sourceId: "wrong-source",
    revision: { ...fresh.revision, operationId: "wrong-source-delete" },
  };
  const result = plan(context, [registration, old, d]);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].ownerControl, "visible");
});
test("wrong-account collision does not equivocate valid account operation", () => {
  const wrong = {
    ...old,
    upstreamAccount: { issuer: "wrong", subject: "wrong" },
  };
  const result = plan(context, [registration, old, wrong]);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].current.revision.operationId, "old");
});
import { createAdmittedReplicaReducer as createReducer } from "./admitted-reducer.ts";
const options = {
  replication: { enabled: true },
  budget: { maxOperations: 100, maxCanonicalBytes: 1000000 },
};
for (const v of reducerVectors)
  test(`admitted reducer every prefix: ${v.name}`, () => {
    for (const order of [
      v.operations,
      [...v.operations].reverse(),
      v.operations.flatMap((op) => [op, op]),
    ]) {
      const reducer = createReducer(context, options);
      const prefix = [];
      for (const op of order) {
        prefix.push(op);
        assert.equal(reducer.push([op]).status, "accepted");
        assert.deepEqual(reducer.plan, plan(context, prefix));
      }
    }
  });
test("admitted reducer defaults off", () => {
  const reducer = createReducer(context, { budget: options.budget });
  assert.equal(reducer.push([old]).reason, "replication_disabled");
  assert.equal(reducer.operationCount, 0);
  assert.equal(reducer.plan, undefined);
});
test("admitted reducer count overflow has no partial commit", () => {
  const reducer = createReducer(context, {
    ...options,
    budget: { ...options.budget, maxOperations: 2 },
  });
  reducer.push([registration]);
  const before = reducer.plan;
  assert.equal(reducer.push([old, fresh]).reason, "operation_capacity");
  assert.equal(reducer.operationCount, 1);
  assert.deepEqual(reducer.plan, before);
});
test("admitted reducer canonical byte bound is exact UTF-8", () => {
  const size = new TextEncoder().encode(canonicalJson(registration)).byteLength;
  const reducer = createReducer(context, {
    ...options,
    budget: { ...options.budget, maxCanonicalBytes: size },
  });
  assert.equal(reducer.push([registration]).status, "accepted");
  assert.equal(reducer.canonicalBytes, size);
  assert.equal(
    reducer.push([upsert("unicode", 1, "é😀")]).reason,
    "byte_capacity",
  );
  assert.equal(reducer.operationCount, 1);
});
test("admitted reducer snapshots and receipts are detached", () => {
  const reducer = createReducer(context, options);
  const mutable = structuredClone(old);
  const outcome = reducer.push([registration, mutable]);
  const before = reducer.plan;
  mutable.data.text = "mutated";
  outcome.plan.records.length = 0;
  reducer.retainedOperations().length = 0;
  assert.deepEqual(reducer.plan, before);
  assert.equal(reducer.operationCount, 2);
});
test("admitted reducer context reproject is atomic", () => {
  const reducer = createReducer(context, options);
  reducer.push([registration, old, fresh]);
  const before = reducer.plan;
  assert.equal(
    reducer.reproject({
      ...context,
      finalizedAt: () => {
        throw new Error("verification unavailable");
      },
    }).reason,
    "invalid_evidence",
  );
  assert.deepEqual(reducer.plan, before);
  assert.equal(reducer.operationCount, 3);
});

test("app projection defaults closed until host explicitly confirms", () => {
  const r = record([old]);
  assert.equal(r.state, "settled");
  assert.equal(appView(r), null);
  assert.equal(appView(r, { confirmed: false }), null);
  assert.ok(appView(r, { confirmed: true }));
});
test("post-erasure fresh evidence needs raw remote frontier, not capped local clock", () => {
  const d = owner("owner-delete", "delete");
  const expired = record([old, d], {
    ...context,
    now: T0 + grace + 1,
    finalizedAt: () => T0,
  });
  const restore = {
    ...owner("owner-restore", "restore", [ref(d)]),
    revision: {
      wallMs: T0 + 100 * 86400000,
      logical: 4,
      writerId: "owner",
      operationId: "restore",
    },
  };
  const after = {
    ...upsert("fresh-after-restore", 1, "fresh", "B", T0 + 31 * 86400000),
    batchId: "fresh-after-restore-batch",
  };
  const raw = {
    ...after,
    frontier: { owner: { wallMs: restore.revision.wallMs, logical: 4 } },
  };
  const ctx = {
    ...context,
    now: T0 + 32 * 86400000,
    finalizedAt: (id) =>
      id === "restore" || id === "fresh-after-restore-batch"
        ? T0 + 31 * 86400000
        : T0,
    suppressionMarkers: [expired.suppressionMarker],
  };
  const kept = record([old, d, restore, raw], ctx);
  assert.equal(kept.value.revision.operationId, "fresh-after-restore");
  assert.equal(kept.payloadRetained, true);
  const clamped = {
    ...raw,
    frontier: { owner: { wallMs: after.revision.wallMs, logical: 4 } },
  };
  const refused = record([old, d, restore, clamped], ctx);
  assert.equal(refused.value, null);
  assert.equal(refused.payloadRetained, false);
});
test("admitted reducer late authenticated finality reprojects the unchanged exact set", () => {
  const reducer = createReducer(
    { ...context, finalizedAt: () => undefined },
    options,
  );
  const a = { ...old, batchId: "a" };
  const b = { ...fresh, batchId: "b" };
  reducer.push([registration, a, b]);
  assert.equal(reducer.plan.records[0].current.revision.operationId, "fresh");
  const next = { ...context, finalizedAt: (id) => (id === "b" ? T0 - 1 : T0) };
  assert.equal(reducer.reproject(next).status, "accepted");
  assert.equal(reducer.plan.records[0].current.revision.operationId, "old");
  assert.equal(reducer.operationCount, 3);
  assert.deepEqual(reducer.plan, plan(next, [registration, a, b]));
});
test("documented research behavior: a dominated disagreement can leave equal-content maxima unsettled", () => {
  const b = upsert("b-y", 1, "Y", "B", T0);
  const a = {
    ...upsert("a-x", 1, "X", "A", T0 + 1000),
    frontier: { B: { wallMs: b.revision.wallMs, logical: b.revision.logical } },
  };
  const c = upsert("c-x", 1, "X", "C", T0 + 2000);
  const r = record([b, a, c]);
  assert.equal(r.current.revision.operationId, "c-x");
  // Owner clarification is pending; keep research's conservative state rather
  // than silently weakening uncertainty based on an inferred grouping rule.
  assert.equal(r.state, "unsettled");
  assert.equal(appView(r, { confirmed: true }), null);
});
test("admitted reducer snapshots caller-owned principal/declaration/marker facts", () => {
  const mutable = {
    ...context,
    connectorPrincipals: structuredClone(context.connectorPrincipals),
    declarations: context.declarations.map((x) => ({
      ...x,
      binding: structuredClone(x.binding),
    })),
    reobservedRecords: [],
  };
  const reducer = createReducer(mutable, options);
  reducer.push([registration, old]);
  mutable.connectorPrincipals[0].upstreamAccount.subject = "changed";
  mutable.declarations[0].binding.stream = "changed";
  mutable.declarations.length = 0;
  reducer.push([fresh]);
  assert.deepEqual(reducer.plan, plan(context, [registration, old, fresh]));
});
test("admitted reducer does not retroactively read changed finality without reproject", () => {
  const table = new Map([
    ["a", T0],
    ["b", T0 + 600000],
  ]);
  const ctx = { ...context, finalizedAt: (id) => table.get(id) };
  const reducer = createReducer(ctx, options);
  const a = { ...old, batchId: "a" };
  const b = { ...fresh, batchId: "b" };
  reducer.push([registration, a, b]);
  const before = reducer.plan;
  table.set("b", T0 - 1);
  reducer.push([a]);
  assert.deepEqual(reducer.plan, before);
  assert.equal(reducer.reproject(ctx).status, "accepted");
  assert.equal(reducer.plan.records[0].current.revision.operationId, "old");
});
test("retention never exposes a value with a different identity than current metadata", () => {
  const futureOld = {
    ...old,
    batchId: "unfinalized-old",
    emittedAt: new Date(T0 + 200 * 86400000).toISOString(),
  };
  const d = owner("owner-delete", "delete");
  const ctx = {
    ...context,
    now: T0 + grace + 1,
    finalizedAt: (id) => (id === "unfinalized-old" ? undefined : T0),
  };
  const expired = record([futureOld, d], ctx);
  const restore = {
    ...owner("owner-restore", "restore", [ref(d)]),
    revision: {
      wallMs: T0 + 100 * 86400000,
      logical: 4,
      writerId: "owner",
      operationId: "restore",
    },
  };
  const fresh = {
    ...upsert("restored-fresh", 1, "fresh", "B", T0 + 31 * 86400000),
    frontier: { owner: { wallMs: restore.revision.wallMs, logical: 4 } },
  };
  const r = record([futureOld, d, restore, fresh], {
    ...ctx,
    now: T0 + 32 * 86400000,
    finalizedAt: (id) =>
      id === "unfinalized-old"
        ? undefined
        : id === "restore"
          ? T0 + 31 * 86400000
          : T0 + 32 * 86400000,
    suppressionMarkers: [expired.suppressionMarker],
  });
  assert.equal(r.current.revision.operationId, "old");
  assert.equal(r.value, null);
  assert.equal(appView(r, { confirmed: true }), null);
  assert.ok(r.flags.includes("selected-payload-unavailable"));
});

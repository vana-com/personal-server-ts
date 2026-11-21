/** Exact admitted operation scenarios shared by portable/Node/Lite tests. */
import type { ReplicaOperation } from "./envelope.js";
import { binding, identity, registration, T0, upsert } from "./fixtures.js";
import type { MergeContext } from "./policy-kernel.js";
export const conformanceContext: MergeContext = {
  owner: identity.owner,
  connectorPrincipals: [
    {
      sourceId: identity.sourceId,
      connectionId: identity.connectionId,
      upstreamAccount: identity.upstreamAccount,
    },
  ],
  declarations: [
    { sourceId: identity.sourceId, binding, validateData: () => true },
  ],
  finalizedAt: () => T0 + 86_400_000,
  now: T0,
};
export const conformanceBudget = {
  maxOperations: 100,
  maxCanonicalBytes: 1_000_000,
};
export const conformanceEnabled = {
  replication: { enabled: true },
  budget: conformanceBudget,
};
const ref = (operation: ReplicaOperation) => ({
  writerId: operation.revision.writerId,
  operationId: operation.revision.operationId,
});
const a = upsert("a", 10_000, "old", "A", T0);
const b = upsert("b", 1, "new", "B", T0 + 600_000);
const near = upsert("near", 1, "near", "C", T0 + 600_001);
const owner = (
  kind: "owner-hide" | "owner-delete" | "owner-restore",
  id: string,
  parents: ReturnType<typeof ref>[] = [],
): ReplicaOperation => ({
  ...identity,
  kind,
  declaration: binding,
  recordKey: a.recordKey,
  parents,
  revision: {
    wallMs: T0 + 700_000,
    logical: 0,
    writerId: "owner-device",
    operationId: id,
  },
});
const hide = owner("owner-hide", "hide");
const deletion = owner("owner-delete", "remove");
const restore = owner("owner-restore", "restore", [ref(hide), ref(deletion)]);
const resolution: ReplicaOperation = {
  ...identity,
  kind: "owner-resolve",
  declaration: binding,
  recordKey: a.recordKey,
  candidates: [ref(a), ref(b)],
  choice: ref(b),
  resolvedValue: {
    kind: "upsert",
    data: b.data,
    blobs: b.blobs,
    contentHash: b.contentHash,
  },
  revision: {
    wallMs: T0 + 800_000,
    logical: 1,
    writerId: "owner-device",
    operationId: "resolve",
  },
};
const competing: ReplicaOperation = {
  ...resolution,
  choice: ref(a),
  resolvedValue: {
    kind: "upsert",
    data: a.data,
    blobs: a.blobs,
    contentHash: a.contentHash,
  },
  revision: {
    ...resolution.revision,
    writerId: "other-owner-device",
    operationId: "other-resolve",
  },
};
const scan: ReplicaOperation = {
  ...identity,
  kind: "source-delete",
  origin: "complete-scan",
  declaration: binding,
  recordKey: a.recordKey,
  emittedAt: new Date(T0 + 900_000).toISOString(),
  contentHash: a.contentHash,
  revision: {
    wallMs: T0 + 900_000,
    logical: 1,
    writerId: "scanner",
    operationId: "scan",
  },
};
const secondScan: ReplicaOperation = {
  ...scan,
  confirmationOf: ref(scan),
  revision: { ...scan.revision, logical: 2, operationId: "second-scan" },
};
const reset: ReplicaOperation = {
  ...identity,
  kind: "connection-reset",
  generation: 2,
  previousGeneration: 1,
  revision: { ...a.revision, operationId: "reset" },
};
export const reducerVectors: {
  name: string;
  operations: ReplicaOperation[];
}[] = [
  {
    name: "observation time versus operation volume",
    operations: [registration, a, b, near],
  },
  {
    name: "late registration and raw causal frontier",
    operations: [
      a,
      {
        ...b,
        frontier: {
          A: { wallMs: a.revision.wallMs, logical: a.revision.logical },
        },
      },
      registration,
    ],
  },
  {
    name: "named removals with restore arriving before parents",
    operations: [registration, restore, a, hide, b, deletion],
  },
  {
    name: "late named resolution dependencies",
    operations: [registration, resolution, b, a],
  },
  {
    name: "competing owner resolutions",
    operations: [registration, resolution, competing, a, b],
  },
  {
    name: "complete scan confirmation arriving before scan",
    operations: [registration, a, secondScan, scan],
  },
  {
    name: "lifecycle reset with late new-generation evidence",
    operations: [registration, a, { ...b, generation: 2 }, reset],
  },
  {
    name: "cross-key operation-id equivocation",
    operations: [
      registration,
      a,
      b,
      {
        ...a,
        recordKey: "other-key",
        data: { id: "other-key", text: "collision" },
      },
    ],
  },
  {
    name: "wrong-account delete cannot suppress legitimate data",
    operations: [
      registration,
      a,
      {
        ...identity,
        kind: "connection-delete",
        upstreamAccount: { issuer: "other", subject: "other" },
        revision: { ...b.revision, operationId: "wrong-account-delete" },
      },
    ],
  },
  {
    name: "explicit connection deletion",
    operations: [
      registration,
      a,
      {
        ...identity,
        kind: "connection-delete",
        revision: { ...b.revision, operationId: "connection-delete" },
      },
    ],
  },
];

import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  type OperationReference,
  type ReplicaOperation,
} from "./envelope.js";
import { binding, identity, registration, T0 } from "./fixtures.js";
import { appView, ownerView, planReplicaMerge } from "./merge-plan.js";
import type { DeclarationBinding } from "./envelope.js";

const ACCOUNT = { issuer: "https://github.com", subject: "gh:1001" };
const X = { id: "k", first: "old", second: 1 };
const Y = { id: "k", first: "new", second: 2 };
const Z = { id: "k", first: "third", second: 3 };
type Symbolic = {
  id: string;
  w: string;
  kind: "observation" | "owner-delete" | "owner-restore" | "resolution";
  value?: "X" | "Y" | "Z" | "DEL";
  v?: string | null;
  L: string;
  extra?: Record<string, unknown>;
  parents?: string[];
  refs?: string[];
  event?: "receive" | "reset-projection" | "assert";
  to?: string;
  ids?: string[];
  expected?: Expected;
};
type Expected = {
  groups: string;
  sourceDisplay: string;
  conflict: boolean;
  visible: string;
  pending: string;
  quarantine: string;
};
const O = (
  id: string,
  w: string,
  value: Symbolic["value"],
  v: string | null = null,
  L: number | string = 10,
  extra: Record<string, unknown> = {},
): Symbolic => ({ id, w, kind: "observation", value, v, L: String(L), extra });
const H = (
  id: string,
  w: string,
  parents: string[] = [],
  L = 20,
): Symbolic => ({ id, w, kind: "owner-delete", parents, L: String(L) });
const T = (
  id: string,
  w: string,
  parents: string[] = [],
  L = 30,
): Symbolic => ({ id, w, kind: "owner-restore", parents, L: String(L) });
const R = (
  id: string,
  w: string,
  value: Symbolic["value"],
  refs: string[],
  v: string | null = null,
  L = 30,
): Symbolic => ({ id, w, kind: "resolution", value, refs, v, L: String(L) });
const recv = (to: string, ids: string[]): Symbolic => ({
  event: "receive",
  to,
  ids,
  id: "",
  w: "",
  kind: "observation",
  L: "0",
});
const reset = (to: string): Symbolic => ({
  event: "reset-projection",
  to,
  id: "",
  w: "",
  kind: "observation",
  L: "0",
});
const at = (to: string, expected: Expected): Symbolic => ({
  event: "assert",
  to,
  expected,
  id: "",
  w: "",
  kind: "observation",
  L: "0",
});
const E = (
  groups: string,
  sourceDisplay: string,
  conflict = false,
  visible = sourceDisplay,
  pending = "",
  quarantine = "",
): Expected => ({
  groups,
  sourceDisplay,
  conflict,
  visible,
  pending,
  quarantine,
});
const fixtures: [string, Symbolic[], Expected, string][] = [
  [
    "01",
    [O("a", "A", "X"), O("b", "B", "Y")],
    E("a|b", "Y", true),
    "Concurrent unversioned different snapshots remain alternatives; writer bytes break the display tie.",
  ],
  [
    "02",
    [O("a", "A", "X"), O("b", "B", "X")],
    E("a+b", "X"),
    "Same content observed twice coalesces presentation, not provenance.",
  ],
  [
    "03",
    [O("a", "A", "X"), O("a", "A", "X")],
    E("a", "X"),
    "Identical op replay is set-idempotent.",
  ],
  [
    "04",
    [O("a", "A", "X", "d:11", 99), O("b", "B", "Y", "d:12", 1)],
    E("b", "Y"),
    "Verified source revision outranks higher Lamport.",
  ],
  [
    "05",
    [O("a", "A", "X", "d:12", 1), O("b", "B", "Y", "d:11", 99)],
    E("a", "X"),
    "A stale late scrape cannot beat newer source evidence.",
  ],
  [
    "06",
    [O("a", "A", "X", "d:12"), O("b", "B", "X", "d:12")],
    E("a+b", "X"),
    "Equal revision/equal normalized payload coalesces.",
  ],
  [
    "07",
    [O("a", "A", "X", "d:12"), O("b", "B", "Y", "d:12")],
    E("a|b", "Y", true),
    "Equal maximum revision with unequal content is a conflict.",
  ],
  [
    "08",
    [O("a", "A", "X", "d:11"), O("b", "B", "X", "d:12")],
    E("b", "X"),
    "Equal content still advances source evidence; old provenance is history.",
  ],
  [
    "09",
    [O("a", "A", "X", "d:12"), O("b", "B", "Y", null, 11)],
    E("a|b", "Y", true),
    "Having a version does not outrank an unversioned candidate.",
  ],
  [
    "10",
    [O("a", "A", "X", "d:999"), O("b", "B", "Y", "q:1")],
    E("a|b", "Y", true),
    "Distinct version domains are incomparable.",
  ],
  [
    "11",
    [
      O("a", "A", "X", null, 10, { opaque: "z9" }),
      O("b", "B", "Y", null, 11, { opaque: "a1" }),
    ],
    E("a|b", "Y", true),
    "Opaque revision lexical order is not chronology.",
  ],
  [
    "12",
    [
      O("a", "A", "X", null, 10, { opaque: "same" }),
      O("b", "B", "Y", null, 11, { opaque: "same" }),
    ],
    E("a|b", "Y", true),
    "Equal opaque evidence and unequal payload cannot hide disagreement.",
  ],
  [
    "13",
    [
      O("a", "A", "X", "d:11", 99),
      O("b", "B", "Y", "d:12", 1),
      O("c", "C", "Z", null, 50),
    ],
    E("b|c", "Z", true),
    "Three-way source reduction precedes fallback; no non-transitive pairwise mixed comparator.",
  ],
  [
    "14",
    [O("a", "A", "X"), O("b", "B", "Y"), O("c", "C", "Z")],
    E("a|b|c", "Z", true),
    "Three offline writers converge without losing siblings.",
  ],
  [
    "15",
    [O("a", "A", "X"), O("b", "B", "X"), O("c", "C", "X")],
    E("a+b+c", "X"),
    "Three equal snapshots preserve all observations without false conflict.",
  ],
  [
    "16",
    [
      O("a", "A", "X", "d:11"),
      O("b", "B", "Y", "d:12"),
      O("c", "C", "Z", "d:13"),
    ],
    E("c", "Z"),
    "Three-device source maxima are independent of delivery order.",
  ],
  [
    "17",
    [
      O("a", "A", "X", "d:12", 100, { collectedAt: "2099-01-01T00:00:00Z" }),
      O("b", "B", "Y", "d:13", 1, { collectedAt: "2000-01-01T00:00:00Z" }),
    ],
    E("b", "Y"),
    "Future clock skew cannot defeat source precedence.",
  ],
  [
    "18",
    [
      O("a", "A", "X", null, 11, { collectedAt: "2000-01-01T00:00:00Z" }),
      O("b", "B", "Y", null, 10, { collectedAt: "2099-01-01T00:00:00Z" }),
    ],
    E("a|b", "X", true),
    "Unversioned display uses logical order, never collection wall time.",
  ],
  [
    "19",
    [O("a", "A", "X", null, 9), O("b", "B", "Y", null, 10)],
    E("a|b", "Y", true),
    "Lamport numbers compare numerically, not string-lexically.",
  ],
  [
    "20",
    [
      O("a", "A", "X", null, "9007199254740993"),
      O("b", "B", "Y", null, "9007199254740992"),
    ],
    E("a|b", "X", true),
    "Cross-runtime integer precision must not collapse adjacent large counters.",
  ],
  [
    "21",
    [O("a", "A", "X"), recv("B", ["a"]), O("b", "B", "Y", null, 11)],
    E("a|b", "Y", true),
    "Observing the earlier scrape locally does not establish source freshness.",
  ],
  [
    "22",
    [O("a", "A", "X", "d:12"), recv("B", ["a"]), O("b", "B", "Y", "d:11", 11)],
    E("a", "X"),
    "A causally later response from a stale upstream cache is still stale.",
  ],
  [
    "23",
    [O("a", "A", "X"), O("b", "B", "Y"), recv("C", ["a", "b", "a", "b"])],
    E("a|b", "Y", true),
    "Whole batch replay has no new candidates or conflict multiplicity.",
  ],
  [
    "24",
    [O("a", "A", "X", "d:11"), O("b", "B", "DEL", "d:12")],
    E("b", "DEL"),
    "Authoritative newer source deletion wins.",
  ],
  [
    "25",
    [O("a", "A", "DEL", "d:12"), O("b", "B", "X", "d:11", 99)],
    E("a", "DEL"),
    "Unknown-key tombstone survives late stale first upsert.",
  ],
  [
    "26",
    [O("a", "A", "DEL", "d:12"), O("b", "B", "Y", "d:13")],
    E("b", "Y"),
    "Comparable newer upsert explicitly permits source resurrection.",
  ],
  [
    "27",
    [O("a", "A", "DEL", "d:12"), O("b", "B", "Y", null, 99)],
    E("a|b", "DEL", true),
    "Unversioned upsert cannot silently resurrect a source tombstone.",
  ],
  [
    "28",
    [O("a", "A", "DEL", "d:12"), O("b", "B", "Y", "q:13", 99)],
    E("a|b", "DEL", true),
    "Incompatible incarnation cannot automatically resurrect.",
  ],
  [
    "29",
    [O("a", "A", "DEL", "d:12"), O("b", "B", "Y", "d:12", 99)],
    E("a|b", "DEL", true),
    "Equal source version delete/upsert is conservatively hidden conflict.",
  ],
  [
    "30",
    [O("a", "A", "DEL"), O("b", "B", "DEL")],
    E("a+b", "DEL"),
    "Equal deletion kind/content coalesces; both provenance entries survive.",
  ],
  [
    "31",
    [O("a", "A", "DEL"), O("b", "B", "Y", "d:100", 99)],
    E("a|b", "DEL", true),
    "A versioned upsert does not outrank an unversioned delete.",
  ],
  [
    "32",
    [
      O("a", "A", "X", "d:11"),
      O("b", "B", "DEL", "d:12"),
      O("c", "C", "Y", "d:13"),
    ],
    E("c", "Y"),
    "Three-stage source delete/recreate works under every delivery permutation.",
  ],
  [
    "33",
    [
      O("a", "A", "DEL", "d:12"),
      O("b", "B", "Y", "d:13"),
      O("c", "C", "Z", null, 99),
    ],
    E("b|c", "Z", true),
    "A dominated source delete must not keep valid resurrection hidden.",
  ],
  [
    "34",
    [O("a", "A", "X"), H("h", "B")],
    E("a", "X", false, "HIDDEN"),
    "Concurrent owner removal suppresses observations, not their history.",
  ],
  [
    "35",
    [H("h", "A"), recv("B", ["h"]), O("b", "B", "Y", "d:99", 99)],
    E("b", "Y", false, "HIDDEN"),
    "Later scrape after seeing owner removal still cannot restore.",
  ],
  [
    "36",
    [O("a", "A", "X"), H("h", "B"), recv("A", ["h"]), T("t", "A", ["h"])],
    E("a", "X"),
    "Explicit causally subsequent restore clears the observed owner delete.",
  ],
  [
    "37",
    [O("a", "A", "X"), H("h", "B"), T("t", "C")],
    E("a", "X", false, "HIDDEN"),
    "Concurrent owner restore loses to unseen delete.",
  ],
  [
    "38",
    [
      O("a", "A", "X"),
      H("h", "B"),
      H("j", "C"),
      recv("A", ["h"]),
      T("t", "A", ["h"]),
    ],
    E("a", "X", false, "HIDDEN"),
    "Restoring one known delete does not clear another offline delete.",
  ],
  [
    "39",
    [
      O("a", "A", "X"),
      H("h", "B"),
      H("j", "C"),
      recv("A", ["h", "j"]),
      T("t", "A", ["h", "j"]),
    ],
    E("a", "X"),
    "Restore after both deletes clears both causal maxima.",
  ],
  [
    "40",
    [
      O("a", "A", "X"),
      H("h", "B"),
      recv("A", ["h"]),
      T("t", "A", ["h"]),
      recv("C", ["h", "t"]),
      H("j", "C", ["t"], 40),
    ],
    E("a", "X", false, "HIDDEN"),
    "A later explicit owner delete hides restored state again.",
  ],
  [
    "41",
    [H("h", "A"), O("b", "B", "DEL", "d:12"), O("c", "C", "Y", "d:13")],
    E("c", "Y", false, "HIDDEN"),
    "Source resurrection cannot override owner suppression.",
  ],
  [
    "42",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"]),
    ],
    E("r", "X"),
    "Explicit resolution suppresses exactly named alternatives.",
  ],
  [
    "43",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"]),
      O("c", "A", "Z", null, 40),
    ],
    E("c|r", "Z", true),
    "Resolution does not cover an unseen concurrent observation.",
  ],
  [
    "44",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"]),
      recv("A", ["b", "r"]),
      O("c", "A", "Z", null, 40),
    ],
    E("c|r", "Z", true),
    "Seeing a resolution does not let an incomparable scrape inherit its ancestry.",
  ],
  [
    "45",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("A", ["b"]),
      recv("B", ["a"]),
      R("r", "A", "X", ["a", "b"]),
      R("s", "B", "Y", ["a", "b"]),
    ],
    E("r|s", "Y", true),
    "Concurrent contradictory resolutions remain siblings.",
  ],
  [
    "46",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("A", ["b"]),
      recv("B", ["a"]),
      R("r", "A", "X", ["a", "b"]),
      R("s", "B", "X", ["a", "b"]),
    ],
    E("r+s", "X"),
    "Concurrent equivalent resolutions coalesce without losing provenance.",
  ],
  [
    "47",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"]),
      recv("A", ["b", "r"]),
      R("s", "A", "Y", ["r"], null, 40),
    ],
    E("s", "Y"),
    "Resolution transitive closure suppresses ancestors, not only direct refs.",
  ],
  [
    "48",
    [
      O("a", "A", "X", "d:12"),
      O("b", "B", "Y", "d:12"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"], "d:12"),
      O("c", "A", "Z", "d:13", 40),
    ],
    E("c", "Z"),
    "Newer comparable source evidence supersedes a versioned resolution.",
  ],
  [
    "49",
    [
      O("a", "A", "DEL"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "Y", ["a", "b"]),
    ],
    E("r", "Y"),
    "Explicit resolution can restore incomparable source state.",
  ],
  [
    "50",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "DEL", ["a", "b"]),
    ],
    E("r", "DEL"),
    "Explicit resolution can choose deletion.",
  ],
  [
    "51",
    [
      O("a", "A", "X"),
      O("b", "B", "Y"),
      recv("C", ["a", "b"]),
      R("r", "C", "X", ["a", "b"]),
      recv("A", ["r"]),
      at("A", E("a", "X", false, "X", "r")),
      recv("A", ["b"]),
      at("A", E("r", "X")),
    ],
    E("r", "X"),
    "Resolution received before its dependency is pending; delivery unblocks it deterministically.",
  ],
  [
    "52",
    [
      O("a", "A", "X"),
      R("r", "C", "Y", ["a", "missing"]),
      recv("B", ["r"]),
      at("B", E("", "NONE", false, "NONE", "r")),
    ],
    E("a", "X", false, "X", "r"),
    "Permanently missing dependency never fabricates a completed resolution; pending is converged state.",
  ],
  [
    "53",
    [O("a", "A", "X"), H("h", "B"), recv("C", ["a", "h"]), reset("C")],
    E("a", "X", false, "HIDDEN"),
    "Projection reset then complete immutable-log rebuild preserves owner suppression; not a generation migration.",
  ],
  [
    "54",
    [
      O("a", "A", "X"),
      O("b", "B", "Y", "d:99", 99, { admission: "cross-account" }),
    ],
    E("a", "X", false, "X", "", "b"),
    "Cross-account observation is retained quarantined and hidden, never merged.",
  ],
  [
    "55",
    [O("b", "B", "Y", "d:99", 99, { admission: "unmapped-instance" })],
    E("", "NONE", false, "NONE", "", "b"),
    "Unmapped connector instance fails closed while preserving owner-resolvable evidence.",
  ],
  [
    "56",
    [
      O("a", "A", "X"),
      O("b", "B", "X", null, 10, {
        payloadOverride: { second: 1, first: "old", id: "k" },
      }),
    ],
    E("a+b", "X"),
    "Object key ordering is canonical; equal content must not generate a false conflict.",
  ],
];

const unsettled = new Set([
  "01",
  "09",
  "10",
  "11",
  "13",
  "14",
  "19",
  "20",
  "23",
  "27",
  "28",
  "31",
  "33",
  "43",
]);
const conflicts = new Set(["07", "12", "29", "45"]);
// Fixture 18 is the sole display reversal: Y's later observation survives the finality cap.
const changedDisplays: Record<string, string> = { "18": "Y" };
const changedVisible: Record<string, string> = { "18": "Y" };
const contextFor = (
  order: DeclarationBinding["sourceVersionOrder"],
): Parameters<typeof planReplicaMerge>[0] => ({
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
      binding: { ...binding, ...(order ? { sourceVersionOrder: order } : {}) },
      validateData: () => true,
    },
  ],
  finalizedAt: (batchId) => finality.get(batchId),
  now: T0,
});
const finality = new Map<string, number>();
const dataFor = (
  value: Symbolic["value"],
  extra: Record<string, unknown> = {},
) => {
  if (value === "DEL") return null;
  const override = extra.payloadOverride;
  return (
    override && typeof override === "object"
      ? override
      : { ...(value === "Y" ? Y : value === "Z" ? Z : X) }
  ) as Record<string, unknown>;
};
const sourceTime = (op: Symbolic): number => {
  const extra = op.extra ?? {};
  const raw = extra.t ?? extra.collectedAt;
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") return Date.parse(raw);
  return T0;
};
const accountFor = (op: Symbolic) => {
  const extra = op.extra ?? {};
  const account = extra.account;
  if (account === "gh:2002" || extra.admission === "cross-account")
    return { ...ACCOUNT, subject: "gh:2002" };
  if (extra.admission === "unmapped-instance")
    return { ...ACCOUNT, subject: "unmapped-instance" };
  return ACCOUNT;
};
function buildOperations(
  timeline: Symbolic[],
  order: DeclarationBinding["sourceVersionOrder"],
): ReplicaOperation[] {
  const known = new Map<string, ReplicaOperation>();
  const seen = new Map<string, Map<string, ReplicaOperation>>();
  for (const device of ["A", "B", "C"]) seen.set(device, new Map());
  const recordBase = (symbol: Symbolic) => {
    const batchId = `batch-${symbol.id}`;
    const account = accountFor(symbol);
    return {
      ...identity,
      upstreamAccount: account,
      batchId,
      frontier: Object.fromEntries(
        [...(seen.get(symbol.w) ?? new Map())].map(([writer, op]) => [
          writer,
          { wallMs: op.revision.wallMs, logical: op.revision.logical },
        ]),
      ),
      revision: {
        wallMs: sourceTime(symbol),
        logical:
          BigInt(symbol.L) <= BigInt(Number.MAX_SAFE_INTEGER)
            ? Number(symbol.L)
            : BigInt(symbol.L).toString(),
        writerId: symbol.w,
        operationId: symbol.id,
      },
      declaration: {
        ...binding,
        ...(order ? { sourceVersionOrder: order } : {}),
      },
      recordKey: "k",
    };
  };
  const ownerBase = {
    ...identity,
    upstreamAccount: ACCOUNT,
    batchId: "batch-owner",
    frontier: {},
    declaration: {
      ...binding,
      ...(order ? { sourceVersionOrder: order } : {}),
    },
    recordKey: "k",
  };
  for (const symbol of timeline) {
    if (symbol.event === "receive") {
      for (const id of symbol.ids ?? []) {
        const received = known.get(id);
        if (received)
          seen.get(symbol.to!)!.set(received.revision.writerId, received);
      }
      continue;
    }
    if (symbol.event === "reset-projection" || symbol.event === "assert")
      continue;
    const base = recordBase(symbol);
    let operation: ReplicaOperation;
    if (symbol.kind === "observation") {
      const data = dataFor(symbol.value, symbol.extra);
      const version =
        symbol.v ??
        (typeof symbol.extra?.opaque === "string" ? symbol.extra.opaque : null);
      if (data === null) {
        operation = {
          ...base,
          kind: "source-delete",
          origin: "source-event",
          emittedAt: new Date(sourceTime(symbol)).toISOString(),
          contentHash: `sha256:${"c".repeat(64)}`,
          ...(version === null
            ? {}
            : {
                sourceVersion: {
                  domain: symbol.v?.split(":")[0] ?? "opaque",
                  incarnation: "e1",
                  value: symbol.v?.split(":")[1] ?? version,
                },
              }),
        } as ReplicaOperation;
      } else {
        operation = {
          ...base,
          kind: "upsert",
          data,
          blobs: [],
          emittedAt: new Date(sourceTime(symbol)).toISOString(),
          contentHash: `sha256:${"c".repeat(64)}`,
          ...(version === null
            ? {}
            : {
                sourceVersion: {
                  domain: symbol.v?.split(":")[0] ?? "opaque",
                  incarnation: "e1",
                  value: symbol.v?.split(":")[1] ?? version,
                },
              }),
        } as ReplicaOperation;
      }
    } else if (
      symbol.kind === "owner-delete" ||
      symbol.kind === "owner-restore"
    ) {
      operation = {
        ...ownerBase,
        batchId: `batch-${symbol.id}`,
        frontier: base.frontier,
        revision: base.revision,
        kind: symbol.kind,
        parents: symbol.parents ?? [],
      } as ReplicaOperation;
    } else {
      const chosen = timeline.find(
        (candidate) =>
          candidate.id ===
          (symbol.refs ?? []).find(
            (id) =>
              timeline.find((item) => item.id === id)?.value === symbol.value,
          ),
      );
      operation = {
        ...ownerBase,
        batchId: `batch-${symbol.id}`,
        frontier: base.frontier,
        revision: base.revision,
        kind: "owner-resolve",
        candidates: symbol.refs ?? [],
        choice: chosen?.id ?? symbol.refs?.[0] ?? symbol.value ?? "",
        resolvedValue:
          symbol.value === "DEL"
            ? {
                kind: "source-delete",
                contentHash: `sha256:${"c".repeat(64)}`,
              }
            : {
                kind: "upsert",
                data: dataFor(symbol.value, {})!,
                blobs: [],
                contentHash: `sha256:${"c".repeat(64)}`,
              },
        ...(symbol.v
          ? {
              version: {
                domain: symbol.v.split(":")[0],
                incarnation: "e1",
                value: symbol.v.split(":")[1],
              },
            }
          : {}),
      } as ReplicaOperation;
    }
    const extra = symbol.extra ?? {};
    if (extra.admission === "unmapped-instance")
      operation = { ...operation, connectionId: "unmapped-instance" };
    if (extra.finalizedAt !== undefined)
      finality.set(operation.batchId, Number(extra.finalizedAt));
    else finality.set(operation.batchId, sourceTime(symbol));
    known.set(symbol.id, operation);
    seen.get(symbol.w)!.set(symbol.w, operation);
  }
  const values = [...known.values()];
  const reference = (
    value: string | OperationReference,
  ): OperationReference => {
    const operationId = typeof value === "string" ? value : value.operationId;
    const target = values.find(
      (operation) => operation.revision.operationId === operationId,
    );
    if (!target) return { writerId: "missing", operationId };
    return {
      writerId: target.revision.writerId,
      operationId: target.revision.operationId,
    };
  };
  const withReferences = values.map((operation) => {
    if (
      operation.kind === "owner-hide" ||
      operation.kind === "owner-delete" ||
      operation.kind === "owner-restore"
    )
      return { ...operation, parents: operation.parents.map(reference) };
    if (operation.kind === "owner-resolve")
      return {
        ...operation,
        candidates: operation.candidates.map(reference),
        choice: reference(operation.choice),
      };
    if (operation.kind === "source-delete" && operation.confirmationOf)
      return {
        ...operation,
        confirmationOf: reference(operation.confirmationOf),
      };
    return operation;
  });
  return [registration, ...withReferences];
}
function summarize(
  operations: ReplicaOperation[],
  order: DeclarationBinding["sourceVersionOrder"],
) {
  const plan = planReplicaMerge(contextFor(order), operations);
  const record = plan.records[0];
  const candidates = record?.candidates ?? [];
  const hasDelete = candidates.some(
    (candidate) => candidate.kind === "source-delete",
  );
  let display = "NONE";
  if (record?.current) {
    if (
      (record.state === "unsettled" || record.state === "conflict") &&
      hasDelete
    )
      display = "DEL";
    else if (record.current.kind === "source-delete") display = "DEL";
    else if (record.current.kind === "upsert")
      display = String(
        (record.value?.kind === "upsert"
          ? record.value.data.first
          : undefined) === "new"
          ? "Y"
          : (record.value?.kind === "upsert"
                ? record.value.data.first
                : undefined) === "third"
            ? "Z"
            : "X",
      );
  }
  const quarantine = plan.quarantined
    .flatMap((issue) => issue.operations.map((op) => op.revision.operationId))
    .sort()
    .join(",");
  const pending = plan.pending
    .flatMap((issue) => issue.operations.map((op) => op.revision.operationId))
    .sort()
    .join(",");
  return {
    plan,
    record,
    display,
    quarantine,
    pending,
    visible: !record
      ? "NONE"
      : ownerView(record)
        ? display
        : record.ownerControl === "visible"
          ? "NONE"
          : "HIDDEN",
  };
}
function candidateGroups(
  record: ReturnType<typeof summarize>["record"],
): string {
  const grouped = new Map<string, string[]>();
  for (const candidate of record?.candidates ?? []) {
    const payload = canonicalJson(
      candidate.kind === "upsert"
        ? { kind: candidate.kind, data: candidate.data, blobs: candidate.blobs }
        : { kind: candidate.kind },
    );
    grouped.set(payload, [
      ...(grouped.get(payload) ?? []),
      candidate.revision.operationId,
    ]);
  }
  return [...grouped.values()]
    .map((ids) => ids.sort().join("+"))
    .sort()
    .join("|");
}
function assertFixtureProjection(
  operations: ReplicaOperation[],
  order: DeclarationBinding["sourceVersionOrder"],
  expected: Expected,
  id: string,
): void {
  const result = summarize(operations, order);
  const display = changedDisplays[id] ?? expected.sourceDisplay;
  if (result.record) {
    expect(appView(result.record)).toBeNull();
    if (result.record.state !== "settled")
      expect(appView(result.record, { confirmed: true })).toBeNull();
  }
  expect(candidateGroups(result.record)).toBe(expected.groups);
  expect(result.display).toBe(display);
  if (expected.groups !== "")
    expect(result.record?.state).toBe(
      conflicts.has(id)
        ? "conflict"
        : unsettled.has(id)
          ? "unsettled"
          : "settled",
    );
  expect(result.visible).toBe(
    expected.visible === "HIDDEN"
      ? "HIDDEN"
      : (changedVisible[id] ?? (display === "DEL" ? "NONE" : display)),
  );
  expect(result.pending).toBe(expected.pending);
  expect(result.quarantine).toBe(expected.quarantine);
}
function assertIntermediateProjections(
  timeline: Symbolic[],
  operations: ReplicaOperation[],
  order: DeclarationBinding["sourceVersionOrder"],
  fixtureId: string,
): void {
  const byId = new Map(operations.map((op) => [op.revision.operationId, op]));
  const available = new Map<string, Set<string>>(
    ["A", "B", "C"].map((device) => [device, new Set<string>()]),
  );
  for (const event of timeline) {
    if (event.event === "receive") {
      (event.ids ?? []).forEach((id) => available.get(event.to!)!.add(id));
      continue;
    }
    if (event.event === "reset-projection") continue;
    if (event.event !== "assert") {
      available.get(event.w)!.add(event.id);
      continue;
    }
    const projection = [
      ...[...available.get(event.to!)!].flatMap((id) => {
        const operation = byId.get(id);
        return operation ? [operation] : [];
      }),
    ];
    assertFixtureProjection(
      [registration, ...projection],
      order,
      event.expected!,
      fixtureId,
    );
  }
}
function permutations<T>(values: T[]): T[][] {
  if (values.length < 2) return [values];
  return values.flatMap((value, index) =>
    permutations(values.filter((_, i) => i !== index).map((x) => x)).map(
      (rest) => [value, ...rest],
    ),
  );
}
function canonicalPlan(value: unknown): string {
  return canonicalJson(JSON.parse(JSON.stringify(value)));
}

describe.each(fixtures)(
  "three-device ordering fixture %s",
  (id, timeline, expected, invariant) => {
    it(invariant, () => {
      finality.clear();
      const order = timeline.some((op) => op.extra?.opaque !== undefined)
        ? "equality-only"
        : timeline.some((op) => op.v !== null && op.v !== undefined)
          ? "ordered-integer"
          : undefined;
      const operations = buildOperations(timeline, order);
      if (id === "18") {
        for (const operation of operations) {
          if (operation.kind === "upsert") finality.set(operation.batchId, T0);
        }
      }
      // Fixture 20 carries the decimal counter as text to preserve its exact value.
      if (id === "20")
        expect(
          operations.find((operation) => operation.revision.operationId === "a")
            ?.revision.logical,
        ).toBe("9007199254740993");
      const adjustedDisplay = changedDisplays[id] ?? expected.sourceDisplay;
      const expectedState = conflicts.has(id)
        ? "conflict"
        : unsettled.has(id)
          ? "unsettled"
          : "settled";
      const result = summarize(operations, order);
      assertIntermediateProjections(timeline, operations, order, id);
      if (id === "55") {
        expect(result.quarantine).toContain("b");
        expect(result.plan.records).toHaveLength(0);
        const ids = new Map(
          operations.map((op) => [
            canonicalJson([op.revision.writerId, op.revision.operationId]),
            op,
          ]),
        );
        const unique = [...ids.values()];
        const expectedPlan = canonicalPlan(result.plan);
        for (const delivery of [unique, [...unique].reverse()])
          expect(
            canonicalPlan(summarize([registration, ...delivery], order).plan),
          ).toBe(expectedPlan);
        expect(
          canonicalPlan(
            summarize([registration, ...unique, ...unique], order).plan,
          ),
        ).toBe(expectedPlan);
        return;
      }
      expect(result.display).toBe(adjustedDisplay);
      expect(candidateGroups(result.record)).toBe(expected.groups);
      expect(result.record?.state).toBe(expectedState);
      expect(result.record?.ownerControl).toBe(
        expected.visible === "HIDDEN" ? "deleted" : "visible",
      );
      const expectedVisible =
        expected.visible === "HIDDEN"
          ? "HIDDEN"
          : (changedVisible[id] ??
            (adjustedDisplay === "DEL" ? "NONE" : adjustedDisplay));
      expect(result.visible).toBe(expectedVisible);
      if (unsettled.has(id)) expect(result.record?.refreshRequested).toBe(true);
      if (conflicts.has(id))
        expect(result.record?.refreshRequested).toBe(false);
      if (id === "54") expect(result.quarantine).toContain("b");
      if (id === "52") expect(result.pending).toContain("r");

      const unique = [
        ...new Map(
          operations.map((op) => [
            canonicalJson([op.revision.writerId, op.revision.operationId]),
            op,
          ]),
        ).values(),
      ];
      const expectedView = canonicalPlan(result.plan);
      const allOrders = permutations(unique);
      for (let index = 0; index < allOrders.length; index++) {
        const delivery = allOrders[index];
        const permuted = summarize([registration, ...delivery], order);
        expect(canonicalPlan(permuted.plan)).toBe(expectedView);
        if (index < 3) {
          const replayed = summarize(
            [registration, ...delivery, ...delivery],
            order,
          );
          expect(canonicalPlan(replayed.plan)).toBe(expectedView);
        }
      }
    });
  },
  30_000,
);

/**
 * Pure copy-promotion decision, contract v3.1
 * (~/.tmp/cutover-handoff/replica-copy-promotion-contract-1021-v3.md):
 * v2 §2 rules 1-6 and §5 pure tests, amendments B, C, D, G and I.
 */
import { describe, expect, it } from "vitest";
import {
  decideCopyPromotion,
  indexEvidenceFromFacts,
  replicaCopyKey,
  type CopyDecisionInput,
  type Hex,
  type IndexEvidence,
  type RetainedCopy,
} from "./copy-promotion.js";
import { replicaChainCommitment } from "./dpv2.js";

const h = (digit: string) => `0x${digit.repeat(64)}` as Hex;
/** A copy of `count` fragments whose commitments are derived from `seed`. */
function copy(seed: string, count = 2): RetainedCopy {
  const fragmentCommitments = Array.from({ length: count }, (_, i) =>
    replicaChainCommitment(h(seed), h(String(i))),
  );
  return {
    copyKey: replicaCopyKey(fragmentCommitments),
    fragmentCommitments,
    validity: "valid",
  };
}
const committed = (commitment: Hex, eligible = true): IndexEvidence => ({
  kind: "committed",
  commitment,
  eligible,
});
/** Evidence that finalizes exactly `c` at every index. */
const proving = (c: RetainedCopy, eligible = true) =>
  new Map(
    c.fragmentCommitments.map((commitment, i) => [
      i,
      committed(commitment, eligible),
    ]),
  );
const input = (patch: Partial<CopyDecisionInput>): CopyDecisionInput => ({
  id: "w:b",
  disposition: { state: "open" },
  copies: [],
  evidence: new Map(),
  refetch: { attempts: 0, budget: 5 },
  ...patch,
});
const sorted = (...keys: Hex[]) => [...keys].sort();

const A = copy("a");
const B = copy("b");
const C = copy("c");

describe("copyKey", () => {
  it("is keccak over the domain tag and the commitments in index order, lowercase 0x", () => {
    expect(A.copyKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(replicaCopyKey([...A.fragmentCommitments])).toBe(A.copyKey);
    expect(replicaCopyKey([...A.fragmentCommitments].reverse())).not.toBe(
      A.copyKey,
    );
    expect(
      replicaCopyKey(
        A.fragmentCommitments.map(
          (c) => c.toUpperCase().replace("0X", "0x") as Hex,
        ),
      ),
    ).toBe(A.copyKey);
  });
});

describe("rules 1-6", () => {
  it("rule 1: a terminal disposition stays terminal and quarantines every valid copy", () => {
    expect(
      decideCopyPromotion(
        input({
          disposition: { state: "terminal", reason: "finalized_conflict" },
          copies: [B, A],
          evidence: proving(A),
        }),
      ),
    ).toEqual({
      kind: "terminal",
      reason: "finalized_conflict",
      quarantine: sorted(A.copyKey, B.copyKey),
    });
  });
  it("rule 1: any contradiction is terminal", () => {
    expect(
      decideCopyPromotion(
        input({
          copies: [A],
          evidence: new Map([
            [0, committed(A.fragmentCommitments[0]!)],
            [1, { kind: "contradiction" }],
          ]),
        }),
      ),
    ).toEqual({
      kind: "terminal",
      reason: "finalized_conflict",
      quarantine: [A.copyKey],
    });
  });
  it("rule 2: a promoted copy reconciles idempotently and late copies are quarantined", () => {
    expect(
      decideCopyPromotion(
        input({
          disposition: { state: "promoted", copyKey: A.copyKey },
          copies: [A, C, B],
          evidence: proving(A),
        }),
      ),
    ).toEqual({
      kind: "reconcile_promoted",
      copyKey: A.copyKey,
      quarantine: sorted(B.copyKey, C.copyKey),
    });
  });
  it("rule 2 (I): unknown or ineligible evidence after promotion never demotes", () => {
    for (const evidence of [new Map(), proving(A, false)])
      expect(
        decideCopyPromotion(
          input({
            disposition: { state: "promoted", copyKey: A.copyKey },
            copies: [A],
            evidence,
          }),
        ),
      ).toEqual({
        kind: "reconcile_promoted",
        copyKey: A.copyKey,
        quarantine: [],
      });
  });
  it("rule 2: a finalized fact disproving the promoted copy is terminal, including the promoted copy (B)", () => {
    expect(
      decideCopyPromotion(
        input({
          disposition: { state: "promoted", copyKey: A.copyKey },
          copies: [A, B],
          evidence: proving(B),
        }),
      ),
    ).toEqual({
      kind: "terminal",
      reason: "finalized_conflict",
      quarantine: sorted(A.copyKey, B.copyKey),
    });
  });
  it("rule 2 (G): a promoted key missing from the retained copies is terminal", () => {
    expect(
      decideCopyPromotion(
        input({
          disposition: { state: "promoted", copyKey: A.copyKey },
          copies: [B],
          evidence: new Map(),
        }),
      ),
    ).toEqual({
      kind: "terminal",
      reason: "finalized_conflict",
      quarantine: [B.copyKey],
    });
  });
  it("rule 3: two proven copies fail closed", () => {
    const twin: RetainedCopy = { ...A, copyKey: B.copyKey };
    expect(
      decideCopyPromotion(input({ copies: [A, twin], evidence: proving(A) }))
        .kind,
    ).toBe("terminal");
  });
  it("rule 4: exactly one proven copy is promoted; the rest are copy conflicts", () => {
    expect(
      decideCopyPromotion(input({ copies: [C, A, B], evidence: proving(B) })),
    ).toEqual({
      kind: "promote",
      copyKey: B.copyKey,
      quarantine: sorted(A.copyKey, C.copyKey),
    });
  });
  it("rule 5: every copy disproved with known finality re-fetches, then asks the owner at the budget", () => {
    const target = copy("z");
    const evidence = proving(target);
    expect(
      decideCopyPromotion(
        input({
          copies: [A, B],
          evidence,
          refetch: { attempts: 4, budget: 5 },
        }),
      ),
    ).toEqual({ kind: "refetch", quarantine: sorted(A.copyKey, B.copyKey) });
    expect(
      decideCopyPromotion(
        input({
          copies: [A, B],
          evidence,
          refetch: { attempts: 5, budget: 5 },
        }),
      ),
    ).toEqual({
      kind: "owner",
      reason: "copy_conflict_unresolved",
      quarantine: sorted(A.copyKey, B.copyKey),
    });
  });
  it("rule 5 does not fire while a copy is not yet disproved: wait", () => {
    const evidence = new Map([[0, committed(B.fragmentCommitments[0]!)]]);
    // A is disproved at index 0; B matches index 0 and index 1 is unknown.
    expect(decideCopyPromotion(input({ copies: [A, B], evidence }))).toEqual({
      kind: "wait",
      on: "finality",
      quarantine: sorted(A.copyKey, B.copyKey),
    });
  });
  it("rule 6 (B): a single waiting copy stays pending; two or more are copy conflicts", () => {
    expect(decideCopyPromotion(input({ copies: [A] }))).toEqual({
      kind: "wait",
      on: "finality",
      quarantine: [],
    });
    expect(decideCopyPromotion(input({ copies: [B, A] }))).toEqual({
      kind: "wait",
      on: "finality",
      quarantine: sorted(A.copyKey, B.copyKey),
    });
  });
});

describe("§5 pure cases and amendments", () => {
  it("is invariant under permutation and duplication of copies", () => {
    const evidence = proving(B);
    const orders = [
      [A, B, C],
      [C, B, A],
      [B, B, A, C, A],
    ];
    const decisions = orders.map((copies) =>
      decideCopyPromotion(input({ copies, evidence })),
    );
    for (const decision of decisions) expect(decision).toEqual(decisions[0]);
  });
  it("zero copies: unknown and absent wait; committed finality re-fetches (I: wait |V|=0 quarantines none)", () => {
    expect(decideCopyPromotion(input({}))).toEqual({
      kind: "wait",
      on: "finality",
      quarantine: [],
    });
    expect(
      decideCopyPromotion(
        input({ evidence: new Map([[0, { kind: "absent" }]]) }),
      ),
    ).toEqual({ kind: "wait", on: "finality", quarantine: [] });
    expect(decideCopyPromotion(input({ evidence: proving(A) }))).toEqual({
      kind: "refetch",
      quarantine: [],
    });
  });
  it("absent never disproves: a copy waits while its registration is not finalized", () => {
    const evidence = new Map<number, IndexEvidence>([
      [0, { kind: "absent" }],
      [1, committed(A.fragmentCommitments[1]!)],
    ]);
    expect(decideCopyPromotion(input({ copies: [A], evidence })).kind).toBe(
      "wait",
    );
  });
  it("a corrupt copy that claims matching commitments is never promoted nor listed", () => {
    const corrupt: RetainedCopy = { ...A, validity: "corrupt" };
    const decision = decideCopyPromotion(
      input({ copies: [corrupt, B], evidence: proving(A) }),
    );
    expect(decision).toEqual({ kind: "refetch", quarantine: [B.copyKey] });
  });
  it("a copy that is a prefix by count is disproved through its index-0 commitment", () => {
    const whole = copy("a", 3);
    const prefix = copy("p", 2); // the fragment count is in every plaintext
    expect(
      decideCopyPromotion(
        input({ copies: [prefix], evidence: proving(whole) }),
      ),
    ).toEqual({ kind: "refetch", quarantine: [prefix.copyKey] });
  });
  it("(I) a matching but ineligible commitment is neither proof nor disproval: no first promotion while Inactive", () => {
    expect(
      decideCopyPromotion(input({ copies: [A], evidence: proving(A, false) })),
    ).toEqual({ kind: "wait", on: "finality", quarantine: [] });
  });
  it("(I) a different commitment disproves whatever its status", () => {
    expect(
      decideCopyPromotion(input({ copies: [A], evidence: proving(B, false) })),
    ).toEqual({ kind: "refetch", quarantine: [A.copyKey] });
  });
  it("never reads anything but copies, evidence, disposition and refetch counts", () => {
    const decision = decideCopyPromotion(
      input({ copies: [B, A], evidence: proving(A) }),
    );
    expect(Object.keys(decision).sort()).toEqual([
      "copyKey",
      "kind",
      "quarantine",
    ]);
  });
});

describe("indexEvidenceFromFacts (D)", () => {
  const authority = {
    chainId: 14800,
    registry: h("2").slice(0, 42),
    owner: "0xowner",
  };
  const fact = (
    blockNumber: bigint,
    currentVersion: string,
    commitment: Hex,
    patch: Partial<Parameters<typeof indexEvidenceFromFacts>[0][number]> = {},
  ) => ({
    ...authority,
    currentVersion,
    status: currentVersion === "0" ? "None" : "Active",
    commitment,
    blockNumber,
    blockHash: `0x${blockNumber.toString(16).padStart(64, "0")}` as Hex,
    eligible: currentVersion === "1",
    ...patch,
  });
  const zero = h("0");
  it("no fact is unknown; a latest version-0 fact is absent; a latest version-1 fact is committed", () => {
    expect(indexEvidenceFromFacts([])).toEqual({ kind: "unknown" });
    expect(indexEvidenceFromFacts([fact(5n, "0", zero)])).toEqual({
      kind: "absent",
    });
    expect(
      indexEvidenceFromFacts([fact(5n, "0", zero), fact(9n, "1", h("a"))]),
    ).toEqual({ kind: "committed", commitment: h("a"), eligible: true });
  });
  it("the latest fact by block number decides eligibility", () => {
    expect(
      indexEvidenceFromFacts([
        fact(9n, "1", h("a"), { status: "Inactive", eligible: false }),
        fact(7n, "1", h("a")),
      ]),
    ).toEqual({ kind: "committed", commitment: h("a"), eligible: false });
  });
  it("contradictions are absorbing: two version-1 commitments, a version above 1, a later version 0, a forked block", () => {
    expect(
      indexEvidenceFromFacts([fact(5n, "1", h("a")), fact(6n, "1", h("b"))]),
    ).toEqual({ kind: "contradiction" });
    expect(indexEvidenceFromFacts([fact(5n, "2", h("a"))])).toEqual({
      kind: "contradiction",
    });
    expect(
      indexEvidenceFromFacts([fact(5n, "1", h("a")), fact(8n, "0", zero)]),
    ).toEqual({ kind: "contradiction" });
    expect(
      indexEvidenceFromFacts([
        fact(5n, "1", h("a")),
        fact(5n, "1", h("a"), { blockHash: h("f") }),
      ]),
    ).toEqual({ kind: "contradiction" });
  });
  it("at one block, the later observation decides: eligibility follows the live head, not the block", () => {
    expect(
      indexEvidenceFromFacts([
        fact(5n, "1", h("a"), { eligible: false }),
        fact(5n, "1", h("a")),
      ]),
    ).toEqual({ kind: "committed", commitment: h("a"), eligible: true });
    expect(
      indexEvidenceFromFacts([
        fact(5n, "1", h("a")),
        fact(5n, "1", h("a"), { eligible: false }),
      ]),
    ).toEqual({ kind: "committed", commitment: h("a"), eligible: false });
  });
  it("an earlier version-0 fact before version 1 is not a contradiction", () => {
    expect(
      indexEvidenceFromFacts([fact(3n, "0", zero), fact(5n, "1", h("a"))]).kind,
    ).toBe("committed");
  });
});

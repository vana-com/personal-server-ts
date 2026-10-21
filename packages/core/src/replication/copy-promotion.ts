import { encodeAbiParameters, keccak256 } from "viem";

/**
 * Batch-copy promotion, contract v3.1
 * (replica-copy-promotion-contract-1021-v3.md). Two or more payloads can claim
 * one batch identity (writer, batch); each is a copy, named by `copyKey`. Only
 * verified finalized chain facts choose between them. Pure: no I/O, no clock.
 */

export type Hex = `0x${string}`;

/**
 * keccak256(abi.encode(string "pdpp.replica.copy.v1", bytes32[] commitments)),
 * commitments in fragment index order. Always recomputed locally from the
 * fragments' (dataHash, metadataHash) commitments, never taken from a sender.
 */
export function replicaCopyKey(fragmentCommitments: readonly Hex[]): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "string" }, { type: "bytes32[]" }],
      [
        "pdpp.replica.copy.v1",
        fragmentCommitments.map((c) => c.toLowerCase() as Hex),
      ],
    ),
  ).toLowerCase() as Hex;
}

export interface RetainedCopy {
  copyKey: Hex;
  /** Per fragment index; length is the copy's declared fragment count. */
  fragmentCommitments: readonly Hex[];
  /** Storage never passes a corrupt input (it is a reject); ignored if it does. */
  validity: "valid" | "corrupt";
}

/** What the finalized chain says about one fragment index. */
export type IndexEvidence =
  /** Never verified, or the last attempt was unavailable. */
  | { kind: "unknown" }
  /** Finalized currentVersion 0, status None: not registered yet. */
  | { kind: "absent" }
  /**
   * Finalized currentVersion 1, any status. `eligible`: the registration
   * state was "confirmed" at that fact (status Active, matching live head).
   */
  | { kind: "committed"; commitment: Hex; eligible: boolean }
  /** Absorbing, derived from the fact history. */
  | { kind: "contradiction" };

export type CopyDisposition =
  | { state: "open" }
  | { state: "promoted"; copyKey: Hex }
  | { state: "terminal"; reason: string };

export interface CopyDecisionInput {
  id: string;
  disposition: CopyDisposition;
  /** All retained copies of `id`. */
  copies: readonly RetainedCopy[];
  /** By fragment index. */
  evidence: ReadonlyMap<number, IndexEvidence>;
  refetch: { attempts: number; budget: number };
}

/** Every quarantine list is sorted, unique, and names only valid copies. */
export type CopyDecision =
  | { kind: "terminal"; reason: "finalized_conflict"; quarantine: Hex[] }
  | { kind: "wait"; on: "finality"; quarantine: Hex[] }
  | { kind: "promote"; copyKey: Hex; quarantine: Hex[] }
  | { kind: "reconcile_promoted"; copyKey: Hex; quarantine: Hex[] }
  | { kind: "refetch"; quarantine: Hex[] }
  | { kind: "owner"; reason: "copy_conflict_unresolved"; quarantine: Hex[] };

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/**
 * The one copy-promotion rule (contract v2 §2 with amendments B, G and I).
 * First matching rule wins:
 * 1. terminal disposition or any contradiction → terminal;
 * 2. promoted p: p missing or disproved → terminal, else reconcile_promoted;
 * 3. more than one proven copy → terminal (needs a hash collision);
 * 4. exactly one proven copy → promote;
 * 5. every copy disproved and finality known → refetch, then owner at budget;
 * 6. otherwise → wait for finality.
 * Never arrival order, size, counter, deadline or hint. The predecessor check
 * is the caller's precondition, not part of this decision.
 */
export function decideCopyPromotion(input: CopyDecisionInput): CopyDecision {
  const byKey = new Map<string, RetainedCopy>();
  for (const copy of input.copies)
    if (copy.validity === "valid")
      byKey.set(copy.copyKey.toLowerCase(), {
        ...copy,
        copyKey: copy.copyKey.toLowerCase() as Hex,
      });
  const valid = [...byKey.values()].sort((a, b) =>
    a.copyKey < b.copyKey ? -1 : a.copyKey > b.copyKey ? 1 : 0,
  );
  const keys = valid.map((copy) => copy.copyKey);
  const except = (key: Hex) => keys.filter((k) => k !== key);
  const terminal = (): CopyDecision => ({
    kind: "terminal",
    reason: "finalized_conflict",
    quarantine: keys,
  });
  const facts = (copy: RetainedCopy) =>
    copy.fragmentCommitments.map(
      (commitment, index) =>
        [commitment, input.evidence.get(index) ?? { kind: "unknown" }] as const,
    );
  const proven = (copy: RetainedCopy) =>
    facts(copy).every(
      ([commitment, evidence]) =>
        evidence.kind === "committed" &&
        evidence.eligible &&
        same(evidence.commitment, commitment),
    );
  const disproved = (copy: RetainedCopy) =>
    facts(copy).some(
      ([commitment, evidence]) =>
        evidence.kind === "committed" && !same(evidence.commitment, commitment),
    );

  const evidence = [...input.evidence.values()];
  if (
    input.disposition.state === "terminal" ||
    evidence.some((e) => e.kind === "contradiction")
  )
    return terminal();
  if (input.disposition.state === "promoted") {
    const promoted = byKey.get(input.disposition.copyKey.toLowerCase());
    if (!promoted || disproved(promoted)) return terminal();
    return {
      kind: "reconcile_promoted",
      copyKey: promoted.copyKey,
      quarantine: except(promoted.copyKey),
    };
  }
  const provenCopies = valid.filter(proven);
  if (provenCopies.length > 1) return terminal();
  if (provenCopies.length === 1) {
    const key = provenCopies[0]!.copyKey;
    return { kind: "promote", copyKey: key, quarantine: except(key) };
  }
  if (valid.every(disproved) && evidence.some((e) => e.kind === "committed"))
    return input.refetch.attempts < input.refetch.budget
      ? { kind: "refetch", quarantine: keys }
      : { kind: "owner", reason: "copy_conflict_unresolved", quarantine: keys };
  return {
    kind: "wait",
    on: "finality",
    quarantine: valid.length >= 2 ? keys : [],
  };
}

/** One verified finalized fact for one fragment scope (contract F2). */
export interface FinalizedFact {
  chainId: number;
  registry: string;
  owner: string;
  currentVersion: string;
  status: string;
  commitment: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  /** replicaRegistrationState(...) === "confirmed" when the fact was verified. */
  eligible: boolean;
}

/**
 * The evidence of one fragment index from its verified fact history
 * (amendment D). Contradiction is absorbing: two version-1 commitments, a
 * version above 1, a version-0 fact later than a version-1 fact, one block
 * number with two hashes, or facts from two authorities. Otherwise the fact
 * with the highest block number decides.
 */
export function indexEvidenceFromFacts(
  facts: readonly FinalizedFact[],
): IndexEvidence {
  if (!facts.length) return { kind: "unknown" };
  const authority = (f: FinalizedFact) =>
    `${f.chainId} ${f.registry.toLowerCase()} ${f.owner.toLowerCase()}`;
  if (new Set(facts.map(authority)).size > 1) return { kind: "contradiction" };
  const versions = facts.map((f) => BigInt(f.currentVersion));
  if (versions.some((v) => v > 1n)) return { kind: "contradiction" };
  const committedFacts = facts.filter((f) => f.currentVersion === "1");
  if (new Set(committedFacts.map((f) => f.commitment.toLowerCase())).size > 1)
    return { kind: "contradiction" };
  const hashes = new Map<bigint, string>();
  for (const f of facts) {
    const seen = hashes.get(f.blockNumber);
    if (seen !== undefined && seen !== f.blockHash.toLowerCase())
      return { kind: "contradiction" };
    hashes.set(f.blockNumber, f.blockHash.toLowerCase());
  }
  const firstCommitted = committedFacts.reduce<bigint | undefined>(
    (low, f) =>
      low === undefined || f.blockNumber < low ? f.blockNumber : low,
    undefined,
  );
  if (
    firstCommitted !== undefined &&
    facts.some(
      (f) => f.currentVersion === "0" && f.blockNumber > firstCommitted,
    )
  )
    return { kind: "contradiction" };
  const latest = facts.reduce((a, b) =>
    b.blockNumber > a.blockNumber ? b : a,
  );
  return latest.currentVersion === "1"
    ? {
        kind: "committed",
        commitment: latest.commitment.toLowerCase() as Hex,
        eligible: latest.eligible,
      }
    : { kind: "absent" };
}

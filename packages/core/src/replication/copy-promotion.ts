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
 * commitments in slot order. A manifest-carried batch has one slot: its
 * manifest. Always recomputed locally from the verified (dataHash,
 * metadataHash) pairs, never taken from a sender.
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

/** What the finalized chain says about one registered slot of a copy. */
export type IndexEvidence =
  /** Never verified, or the last attempt was unavailable. */
  | { kind: "unknown" }
  /** Finalized currentVersion below the slot: not registered yet. */
  | { kind: "absent" }
  /**
   * Finalized currentVersion at or above the slot, any status. `eligible`:
   * the registration state was "confirmed" at that fact (status Active,
   * agreeing live head).
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
/** Completed non-matching re-downloads before the owner decides (contract F4). */
export const REPLICA_REFETCH_BUDGET = 5;

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

/** One verified finalized fact for one registered slot (contract F2). */
export interface FinalizedFact {
  chainId: number;
  registry: string;
  owner: string;
  /** The slot's version. Its commitment is write-once on chain. */
  version: string;
  currentVersion: string;
  status: string;
  commitment: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  /** replicaRegistrationState(...) === "confirmed" when the fact was verified. */
  eligible: boolean;
}

/**
 * The evidence of one slot from its verified fact history (amendment D).
 * Versions append, so a currentVersion above the slot is normal. A slot's
 * commitment is write-once, so contradiction is absorbing: two commitments
 * for the slot, an absent fact later than a committed one, facts about two
 * slots, one block number with two hashes, or facts from two authorities.
 * Otherwise the fact with the highest block number decides, and among facts
 * at that block the last observed. `facts` must be in observation order.
 */
export function indexEvidenceFromFacts(
  facts: readonly FinalizedFact[],
): IndexEvidence {
  if (!facts.length) return { kind: "unknown" };
  const authority = (f: FinalizedFact) =>
    `${f.chainId} ${f.registry.toLowerCase()} ${f.owner.toLowerCase()}`;
  if (new Set(facts.map(authority)).size > 1) return { kind: "contradiction" };
  if (new Set(facts.map((f) => f.version)).size > 1)
    return { kind: "contradiction" };
  const slot = BigInt(facts[0]!.version);
  const committed = (f: FinalizedFact) => BigInt(f.currentVersion) >= slot;
  const committedFacts = facts.filter(committed);
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
    facts.some((f) => !committed(f) && f.blockNumber > firstCommitted)
  )
    return { kind: "contradiction" };
  // Facts arrive in observation order. At one block, a later observation
  // supersedes: eligibility follows the live head, which can change while
  // the finalized block does not.
  const latest = facts.reduce((a, b) =>
    b.blockNumber >= a.blockNumber ? b : a,
  );
  return committed(latest)
    ? {
        kind: "committed",
        commitment: latest.commitment.toLowerCase() as Hex,
        eligible: latest.eligible,
      }
    : { kind: "absent" };
}

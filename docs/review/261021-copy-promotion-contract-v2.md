# Replica batch-copy promotion contract, v2 (2026-10-21)

Status: draft v2. It replaces v1 (`replica-copy-promotion-contract-1021.md`, including v1's "Write-side shapes" section). Nothing gets built on it until a fresh cross-family review passes.
Decision (unchanged): fingerprint-pinned promotion, approved by the lead.
v1 review: `~/.tmp/dot-dc49x/design-copy-promotion-contract-1021.full.md`. Where v2 answers one of its findings, the finding number appears as **[Rn]**.
Code facts below are cited at #438 355fbf31 (`origin/tnunamak/replica-visibility-policy-1021`).

## 0. What the chain actually binds [R3]

- **Each fragment is its own DPv2 data point.**
  - Its scope is `${REPLICA_SCOPE_PREFIX}.${writer}_${batch}.${index}` (core replication/transport.ts `replicaScope`).
  - It is registered with `expectedVersion = 1`.
  - DataRegistryV2 stores only `commitment = keccak256(abi.encode(bytes32 dataHash, bytes32 metadataHash))` (dpv2.ts `replicaChainCommitment`). It does not store the preimages.
- **Each fragment's hashes bind the whole batch.**
  - `dataHash = keccak256(fragment plaintext)` (transport.ts:194).
  - The plaintext is a strict `replicaFragmentSchema` object that carries owner, writer, batch, sequence, previous (predecessor), the whole-envelope `digest`, totalBytes, `count`, `index` and offset.
  - So one fragment's commitment binds the fragment count, the envelope digest and the predecessor link of its copy.
- **Consequence.** At most one version-1 commitment can be finalized per fragment scope. `currentVersion > 1` is already classified as `conflict` (dpv2.ts `replicaRegistrationState`). Two different copies of one batch differ in every fragment, because `digest` is in every fragment. So at most one copy can match the finalized commitments of all its scopes.

### Identifiers (exact definitions)

| Name | Definition | Use |
|---|---|---|
| `fragmentCommitment[i]` | `replicaChainCommitment(dataHash_i, metadataHash_i)`, lowercase `0x` + 64 hex | equal to what DataRegistryV2 stores for scope i, v1 |
| `copyKey` | `keccak256(abi.encode(string "pdpp.replica.copy.v1", bytes32[] fragmentCommitment[0..count-1]))`, lowercase `0x` hex. Array order is fragment index; length is the copy's declared `count`. | retention key and promotion selector |
| `envelopeDigest` | existing `sha256:<hex>` over the canonical envelope JSON (Lite `canonical-store.ts:62-66`; transport `digest`) | import receipt identity; Lite's existing fingerprint |

- `copyKey` is not the same as `envelopeDigest`. Both are retained, and the two are linked in one direction only: a valid copy's fragments embed its `envelopeDigest`.
- The finalized target is never turned into a `copyKey` from the chain, because the preimages aren't there. Selection compares per-index commitments (§2).
- Existing call sites change as follows:
  - Lite `stagePending`/`promotePending` start keying by `copyKey`, and keep `envelopeDigest` in the receipt.
  - The Node inbox keeps `data_hash`/`metadata_hash` per fragment, which are the inputs to `fragmentCommitment`.

## 1. Durable facts

All tables below are new, belong to the replica migration family, and touch no main table.

**F1. Retained copies**
```sql
CREATE TABLE pdpp_replica_copies (
  id TEXT NOT NULL,                 -- batch identity (writer, batch) as passed by the host today
  copy_key TEXT NOT NULL,           -- §0
  writer_id TEXT NOT NULL, batch_id TEXT NOT NULL,
  fragment_count INTEGER NOT NULL,
  fragment_commitments_json TEXT NOT NULL,   -- ["0x…", …] index order, length = fragment_count
  envelope_digest TEXT,             -- NULL only when validity='corrupt' and no envelope could be parsed
  envelope_json TEXT,               -- NULL when validity='corrupt'; never served to any reader
  blobs_json TEXT,
  validity TEXT NOT NULL CHECK (validity IN ('valid','corrupt')),
  corrupt_reason TEXT CHECK ((validity='corrupt') = (corrupt_reason IS NOT NULL)),
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','quarantined')),
  reason TEXT CHECK (reason IS NULL OR reason IN ('copy_conflict','corruption','finalized_conflict')),
  CHECK ((state = 'quarantined') = (reason IS NOT NULL)),
  CHECK (validity = 'valid' OR (state = 'quarantined' AND reason = 'corruption')),
  PRIMARY KEY (id, copy_key)
);
-- bytes: pdpp_replica_copy_bytes(id, copy_key, blob_id, bytes, PRIMARY KEY(id, copy_key, blob_id))
```
- **Validity is fixed at staging and never changes [R2].** `valid` means all of the following passed, as they do today:
  - envelope schema;
  - per-fragment binding;
  - chunk hashes and complete assembly (transport.ts:96-120, 209-250);
  - Lite envelope validation (canonical-store.ts:1040-1049);
  - every fragment's bytes hash to its own claimed `dataHash`/`metadataHash`.
- Anything else is `corrupt`. A corrupt copy is retained for diagnostics only. Its `envelope_json` is NULL, so no read path can treat it as a validated envelope.
- **Reasons can only move up in precedence:** `corruption` > `finalized_conflict` > `copy_conflict`. No transition lowers a reason. The one exception is that the promoted copy goes to `state='confirmed', reason=NULL`. Only a `valid` copy can be promoted, and the SQL CHECKs enforce that.

**F2. Finalized evidence history (append-only) [R1][R4]**
```sql
CREATE TABLE pdpp_replica_finalized_facts (
  chain_id INTEGER NOT NULL, registry TEXT NOT NULL, owner TEXT NOT NULL,
  scope TEXT NOT NULL, fragment_index INTEGER NOT NULL, id TEXT NOT NULL,
  current_version TEXT NOT NULL, status TEXT NOT NULL, commitment TEXT NOT NULL,
  block_number TEXT NOT NULL, block_hash TEXT NOT NULL, observed_at INTEGER NOT NULL,
  PRIMARY KEY (chain_id, registry, scope, block_hash)
);  -- with no-update/no-delete triggers, like the other replica evidence tables
```
- **Only a completed verification is appended.** That means `evidence(scope)` returned a `chain` object after its pinned-block re-check (evidence.ts:221-248).
- **Not facts, never appended:**
  - `ReplicaEvidenceUnavailableError`, which includes a finalized block changing during verification;
  - Gateway optimistic-head rollback (`pending`);
  - `chain = null`.

  These count as *unknown*.
- **Contradiction (absorbing)** exists when any of the following holds:
  - two facts for the same `(chain_id, registry, owner, scope)` have `current_version='1'` and different `commitment`;
  - any fact has `current_version > 1`;
  - a fact comes from a different `(chain_id, registry, owner)` than the receiver's configured authority. This is refused at insert time and recorded as a diagnostic; it never counts as a fact.

**F3. Batch disposition (absorbing states) [R1][R5]**
```sql
CREATE TABLE pdpp_replica_batch_disposition (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('open','promoted','terminal')),
  promoted_copy_key TEXT, terminal_reason TEXT,
  CHECK ((state='promoted') = (promoted_copy_key IS NOT NULL)),
  CHECK ((state='terminal') = (terminal_reason IS NOT NULL))
);
```
- `open → promoted`, `open → terminal` and `promoted → terminal` are the only transitions.
- Nothing ever leaves `terminal`. A retry, restart, new copy or new fact cannot clear it.

**F4. Coordinator work (existing `pdpp_transport_import_work`, owned by the coordinator) [R5]**
- Per batch `id`, it holds: `refetch_attempts`, `refetch_budget` (default 5), `outcome`, `dependency`, `next_eligible`.
- `Wait(owner)` with reason `copy_conflict_unresolved` is persisted here, so it survives restart.

## 2. The pure decision

```ts
type RetainedCopy = { copyKey: Hex; fragmentCommitments: readonly Hex[]; validity: "valid" | "corrupt" };
type IndexEvidence =
  | { kind: "unknown" }                                   // never verified, or last attempt unavailable
  | { kind: "absent" }                                    // finalized currentVersion=0, status None
  | { kind: "committed"; commitment: Hex }                // finalized currentVersion=1 (any status)
  | { kind: "contradiction" };                            // derived from F2 history
type CopyDecisionInput = {
  id: string;
  disposition: { state: "open" } | { state: "promoted"; copyKey: Hex } | { state: "terminal"; reason: string };
  copies: readonly RetainedCopy[];                         // all retained copies for id
  evidence: ReadonlyMap<number, IndexEvidence>;            // by fragment index, from F2 (latest fact per index; contradiction if F2 says so)
  refetch: { attempts: number; budget: number };
};
type CopyDecision =
  | { kind: "terminal"; reason: "finalized_conflict"; quarantine: Hex[] }
  | { kind: "wait"; on: "finality"; quarantine: Hex[] }
  | { kind: "promote"; copyKey: Hex; quarantine: Hex[] }
  | { kind: "reconcile_promoted"; copyKey: Hex; quarantine: Hex[] }   // idempotent; late copies
  | { kind: "refetch"; quarantine: Hex[] }
  | { kind: "owner"; reason: "copy_conflict_unresolved"; quarantine: Hex[] };
function decideCopyPromotion(input: CopyDecisionInput): CopyDecision;
```

**Normalization.**
- Copies are de-duplicated by `copyKey` and sorted by `copyKey`.
- Every `quarantine` list is sorted and unique, and holds only `valid` copies other than the selected or promoted one.
- Corrupt copies never appear in any output. They stay `corruption`.
- The decision does not depend on replay multiplicity or arrival order [review totality checklist].

A valid copy `c` is **proven** when every index `i < c.fragmentCommitments.length` has evidence `committed` and that commitment equals `c.fragmentCommitments[i]`.
A valid copy `c` is **disproved** when some index `i < c.fragmentCommitments.length` has evidence `committed` with a different commitment. `absent` (not registered as of the finalized block) never disproves a copy, because registration may simply not have finalized yet.

**Rules, in order. The first match wins.**
1. `disposition.state = terminal`, or any evidence is `contradiction` → `terminal`. [R1]
2. `disposition.state = promoted` with copy `p`:
   - if `p` is now disproved → `terminal` (a finalized fact contradicts what was promoted);
   - otherwise → `reconcile_promoted(p)`. Evidence `unknown` after promotion never demotes confirmed data. [R4]
3. More than one valid copy is proven → `terminal`. This can't happen without a hash collision; fail closed.
4. Exactly one valid copy is proven → `promote(that copy)`.
5. Every valid copy is disproved (this includes the case of zero valid copies), and at least one index has evidence `committed`:
   - if `refetch.attempts < refetch.budget` → `refetch`;
   - otherwise → `owner`.

   Finality is already known here, but no retained copy can satisfy it. [R3] (*known finality, unknown preimage*)
   A copy that is not yet disproved can still become proven, so rule 5 does not fire while one exists. That case is a `wait`.
6. Otherwise → `wait(finality)`.

Rules 1–6 never use arrival order, size, Lamport counter or HLC, retry deadline, or head hint. [contract rule 5]

**Quarantine while waiting [R6].**
- `wait` with exactly one valid copy: the quarantine list is empty, so that copy stays `pending`. This is today's behaviour: the owner preview shows it, and grants see it only under the existing include-pending policy.
- `wait` with two or more valid copies: all of them go into `quarantine` as `copy_conflict`.

**Predecessor [R4].** Promotion also needs the predecessor batch `(writer, sequence-1)` to be `promoted`. The coordinator holds a proven copy as `Wait(predecessor)` until then (S2 behaviour). The decision function does not check predecessors; that job stays in the coordinator's precondition, so it is not duplicated.

## 3. Durable transitions (coordinator + receiver) [R5]

Each row is one SQLite transaction. Every transition is idempotent under replay.

| Trigger | Transaction effects |
|---|---|
| **Stage copy** (download/import of a complete set, or Lite stage) | Insert the F1 row (validity fixed now). Load inputs, `decide`, and apply its quarantine list (raising reasons only). If disposition is `promoted`, the new copy is quarantined `copy_conflict` (or `corruption`) in this same transaction, and the confirmed copy and ack are untouched. Then `onDependencyChanged(id)`. |
| **Evidence verified** for a scope | Append the F2 fact (or record a contradiction). Then `onDependencyChanged(id)`. |
| **Coordinator step** for `id` (due) | `decide` → `promote`: `receiver.promote({credential, id, copyKey})`, below. `refetch`: `attempts += 1`, schedule a re-download of all scopes of `id` with backoff. A fetch that yields only already-retained or non-matching copies counts as that attempt's failure; a new `copyKey` does not reset `attempts`. `owner`: persist `Wait(owner)`. Resumes only on a new F2 fact or on staging a copy that decides `promote`. `wait`: `Wait(finality)` with the finality schedule. `terminal`: set disposition `terminal`, raise every valid copy to `finalized_conflict`, persist `Quarantine(finalized_conflict)`. `reconcile_promoted`: apply quarantine; no import, no second ack. |
| **`promote({credential, id, copyKey})`** | 1. Authenticate. 2. Re-load F1/F2/F3 *inside the transaction* and re-run `decide`; abort unless it still returns `promote(copyKey)` (preserves Lite's in-transaction guard, canonical-store.ts:474-484). 3. Import that copy. 4. Set it `confirmed`, `reason=NULL`. 5. Apply the quarantine list. 6. Set disposition `promoted`. 7. Write the import receipt keyed `(id)` with `copy_key` and `envelope_digest`. A receipt for `id` with a different `copy_key` is an invariant violation, which aborts and sets `terminal`. 8. Ack. |
| Bare `promote({credential, id})` | Refused when more than one copy of `id` is retained. With exactly one copy, behaves as `promote(id, thatCopyKey)`, re-checked by `decide` in step 2. |
| Lite public `import` without a promotion input (canonical-store.ts:1209-1215) | In replicated mode, refused whenever any F1 row exists for `id`. Otherwise it requires a host-supplied `copyKey` and goes through the same in-transaction `decide`. No bypass. |

Pending refs and blob-active refs (Lite 909; 979-983) and Node pending bytes are re-keyed from `id` to `(id, copy_key)`. Withdrawing one copy never touches another copy's bytes.

## 4. Read side: a policy change, listed per call site [R6]

The #438 lane implements this. It is a deliberate policy change, not something that already fits the current signature.

| Current behaviour (355fbf31) | Replaced by |
|---|---|
| `visibility-policy.ts:15-25` hides every quarantined row from both readers and takes no reason | A reason-aware rule. `copy_conflict` → owner sees it, marked `{visibility:'conflicted', status:'copy conflict'}`; grants never see it, **whatever the include-pending configuration**. `finalized_conflict` → grants never; owner sees a diagnostic marker `{visibility:'conflicted', status:'integrity conflict'}` with **no values**. `corruption` → hidden from both. |
| `visibility-policy.ts:37-47` `conflicted` with status "account conflict", owner-only, local origin | Unchanged. Received account conflicts are not widened. |
| Grant include-pending (`visibility-policy.ts:6-14, 24`) | Unchanged for ordinary `pending`. It never applies to the three reasons above. |
| Lite point read / preview, one row per key (`canonical-store.ts:68-80, 1018-1026`) and `record-reducer.ts:37-53` | Conflict copies are **not** inputs to the reducer or to canonical materialization. Owners get both marked values through a separate owner-only read, `readCopyConflicts(id) → [{copyKey, reason, values}]`. Grants keep reading the confirmed predecessor or the promoted copy. |
| `merge-plan.ts:83-99, 123-126` (same-operation variants suppress a connection) | Unchanged. Quarantined copies are never planner input, so conflicting copies of one batch cannot trigger the connection-wide variant suppression. Only the promoted copy is imported. |

**Not replaced:** record ordering (merge-plan.ts:195-229, revision.ts, completion.ts `selectStreamCompletion`). `CopyDecision` selects transport copies only; record ordering stays its own contract, which is being rebuilt as HLC by lane impl-426-ordering-rule-1021.

## 5. Tests (red first)

**Pure decision.** One test per rule 1–6, plus:
- permutation and duplication invariance;
- zero copies with `unknown`, `absent` and `committed` evidence;
- one corrupt copy that claims matching commitments → never promoted;
- a copy that is a prefix by count → disproved through the index-0 commitment.

**Transitions (Node SQLite and Lite):**
- every crash point of `promote`;
- restart between stage and promote;
- a late copy after promotion → quarantined, no second ack;
- an A-then-B finalized contradiction after promotion → terminal, and it stays terminal across a retry and a restart;
- the pinned block changes mid-verification → no fact, `wait`;
- a Gateway head rollback → no fact;
- status Inactive after promotion → confirmed data stays;
- refetch A, B, C, D with no match → owner after the budget; `attempts` not reset by new keys; survives restart; a matching copy staged later → promote;
- successor `Wait(predecessor)` → imports after the predecessor's promotion;
- a corrupt copy keeps `corruption` through every transition;
- a reason never lowers;
- Lite direct import refused when F1 rows exist.

**Read side (#438 lane):** the four cases from v1, plus:
- grants never see `copy_conflict` with include-pending on;
- `finalized_conflict` shows no values;
- `corruption` is hidden from the owner too.

## 6. Out of scope
- Owner repair actions after `owner` or `terminal`.
- Retention retirement.
- CPU and byte bounds of re-download (C).

Verdict: REQUEST CHANGES.

One remaining implementation-blocking lifecycle decision, inherited from N5; no P0. The other remaining details are non-blocking. Review-only against assignment base 61281d5fd2415afa870aecc07fdf8141e55c7e6d; no edits, tests, Work/Codex tasks, model APIs or metered tools. Cancellation/authority checked immediately before submission: clear; owner_notes empty. Node receiver/transport/coordinator implementations were not read and their hooks are not verified.

References: V3 = docs/review/261021-copy-promotion-contract-v3.md; Lite = packages/lite/src/canonical-store.ts; core = packages/core/src/replication/.

Per-N disposition

| Item | Status | Evidence |
|---|---|---|
| N1 withdrawal/visibility | Resolved at contract level | V3:248-258 mandates atomic connection quarantine, cursor expiry, every read surface including confirmed blobs, and pending-preview blob withdrawal. Existing Lite-hook claim needs correction, below. |
| N2 exact branch outputs | Resolved, minor omission | V3:260-272 specifies reasons and membership, includes promoted p on terminal, exempts duplicate promoted staging. Explicit zero-copy wait row is missing but uniquely empty. |
| N3 corrupt-first poisoning | Resolved | V3:274-284 separates rejects from validated-key retention and checks duplicate consistency. Invalid input cannot occupy the valid key. |
| N4 authority/eligibility | Resolved at policy level | V3:286-294 restores replicaRegistrationState confirmed gating, keeps post-promotion availability separate, orders facts by block, detects same-height forks and committed-to-absent rollback, adds owner to PK. |
| N5 predecessor | Partial, BLOCKING | V3:296-302 fixes root/identity/digest and transactional checks, but only defines blocking future promotion, not invalidation of an already-promoted successor. |
| N6 atomicity/replay | Resolved at contract level | V3:304-317 provides savepoint rollback plus committed terminal, receipt replay, durable ack/wake intents, attempt-id deduplication and stage-then-promote. |
| N7 validity/identity | Resolved, wording cleanup | V3:319-329 separates both hash computations, requires complete nonempty vectors, local key derivation, address binding, and missing-promoted-key fail-closed. Preserve original assembly/owner/schema checks. |

A: sound fail-closed choice

Connection-wide quarantine is a conservative, coherent alternative to reconstructing the world before a batch's deletes/resets. A expressly accepts collateral unavailability, applies withdrawal and cursor invalidation atomically, and forbids confirmed-blob bypass. This resolves the design gap; it does not prove the existing implementation already does it. No need to reopen HLC/record ordering or demand out-of-scope Node sources.

B: totality

All six decision kinds now have determinate quarantine membership for nonempty V. Empty V with unknown/absent evidence still takes wait, so add the explicit empty-set row. With committed evidence it takes refetch/owner and quarantines the empty set. Corrupt attempts no longer participate in V. A matching but ineligible commitment is neither proof nor disproval; it waits. Disproval still requires a different commitment, irrespective of status.

Remaining findings and minimal edits

1. P1 — BLOCKING: already-promoted descendants can remain served after their prerequisite becomes terminal. V3:249 quarantines only connections touched by the terminal batch; :299-301 checks prerequisites for promotion and assigns Wait(owner), without withdrawing already-imported successor effects. Example: P touches connection X; S names P's exact digest, touches Y, and promotes while P is promoted. Later contradictory finalized evidence makes P terminal. A hides X, but nothing makes S terminal or hides Y. Wait(owner) alone is a work disposition, not a read barrier. The prior N5 request explicitly included this later-terminal case (v2-review.md:34).

Minimal edit: define the treatment of already-promoted successors and their descendants when an ancestor becomes terminal. For the stated fail-closed policy, invalidate their serving eligibility and invoke A for their touched connections, with no visibility window while dependent work is queued. Unpromoted successors keep Wait(owner). If independently finalized successors are intentionally allowed to survive, state that exception explicitly and justify the predecessor check as promotion-time-only; the current text does not choose it. Add P→S→T with disjoint connections and terminal-after-all-promoted tests. This is a lifecycle policy choice, not merely a test assertion.

2. P2 — Non-blocking: distinguish the required Lite integration from an already-existing hook. V3:248-255 claims existing replicaIntegrityEpoch withdrawal machinery, but packages/lite/src/canonical-store.md:194-199 explicitly says Lite has no integrity-epoch capability; Lite:1273-1283 uses connection view revisions, and :1395-1399 currently bypasses checks for confirmed blobs. Name the Lite transaction-local quarantine/reconciliation and canonical/preview revision mapping, keeping A's required read gates. Tests must prove it; absence from today's source is not by itself a new contract blocker.

3. P2 — Non-blocking type/table/editorial alignment. V3:112-120 retains an evidence union with no eligibility/head distinction, while :287-288 requires one. Explicitly carry eligibility separately from immutable chain facts, or name the adapter/coordinator guard that supplies it; a matching inactive commitment must not become disproved. Add wait with |V|=0 to :265-266. At :326 limit lowercase 0x wording to EVM hashes; envelopeDigest/chunkDigest retain their sha256: encoding (transport.ts:12,25,30). State that G supplements, rather than replaces, the complete assembly and owner checks in :59-64.

After resolving finding 1, the remaining items warrant APPROVE-WITH-CHANGES, not another scope-expanding design round.

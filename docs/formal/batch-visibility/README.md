# Batch visibility: finite design model (unexecuted)
Pinned source: vana-com/personal-server-ts 03b809316abf86c4c9b429e63d64578c7e508524.
The BRIEF names df94f29aa2b48cc241ae6ac07c6d46d43817dd7f as the conceptual base;
source grounding here uses the assigned checkout, not an inferred older checkout.

## Status
TLC and SANY were NOT RUN. Java/jar availability was NOT probed. This worker
uses only authorized Dalan workspace reads/patches, not shell or metered tools.
No checked state count, distinct count, depth, counterexample length, or successful
verification is claimed. All eight configs are unexecuted host acceptance gates.
The model and configs are a private patch, not a production implementation.

BRIEF line 27 was returned as "[redacted secret]". Line 26 before it is blank;
line 28 after it is blank. Nearest nonblank visible predecessor is line 25, the
RUN paragraph requesting TLC (-workers 2), exact results, or an explicit not-run
statement and SANY if available. There is no visible nonblank successor.
TODO in the spec marks this unknown obligation. No reconstruction or alternate
read route was attempted. Any questions present only in that line remain unanswered.

## Source grounding and abstraction
- run-intake.ts:89 and :515-546 stage run_rows and advance last_batch atomically;
  the latter is ingestion sequencing, NOT an asserted connector checkpoint.
- run-end.ts:198-240 derives full proof and decides replace, :263-280 stages accepted
  upserts and explicit deletes for merge.
- replace.ts:20-28 requires full_inventory, mutable_state, successful stream,
  full_refresh, coverage and producer proof. The model assumes mutable_state and
  full_refresh and makes successful proof an explicit Prove action.
- merge.ts:18-42 distinguishes effective SEEN observation from published content
  stamp; :97-128 documents ordering and pending explicit-delete protection.
- merge.ts:267-281 preserves observations at/after the replacement cutoff.
  :285-312 commits explicit deletion stamps; :315-330 describes dropping rows
  of a refused/discarded run. Failed model runs drop staging, not previously
  committed observations. Refusal after publication is a separate excluded case.
- apply.ts:520-522 applies the head omissionCutoff; merge.ts:212-261 describes
  remote omission and promotion of later local observations.
- schema.ts:20-32 stores rows and ordered changes; :54-73 stores runs and staging.
- stream-sync/intake.ts:62-67 declares the five coverage strategies. This bounded
  model covers full_inventory and checkpoint_window only.
- Style: PublishSnapshot.tla uses a finite history and constant-selected design;
  RegistryPoke.tla separates state transitions from property predicates.

All paths above are under packages/core/src/ except the two formal model examples.

## State and design choices
K has three keys; values have two non-absent values. Each batch contains one
arbitrarily selected source key, once per run, so batch order is arbitrary.
ChangeSource may alter values/membership before or during runs. Begin reserves a
fixed run observation stamp; W can upsert or explicitly delete any key at any time
with a newer stamp. A scalar rank abstracts the total lexicographic (o,r) order,
not wall-clock synchronization. TODAY stages until successful End; PROPOSED merges
batches immediately and keeps them on failure. Either can fail before proof.
Prove is allowed after every currently present source key has been seen, but does
not assert snapshot consistency across a changing source. Checkpoint events copy
only the merged batch set. TODAY advances its checkpoint at successful merge/end.
A checkpoint is a set of acknowledged batch identities, not a numeric external cursor.

Every committed action appends a store image plus deletion floor. Publish advances
R one commit at a time, permitting every prefix, including long lag. This abstracts
transactional publication/replay; it does not prove registry CAS, partition encoding,
crash recovery, transport, encryption, generation fencing, or concurrent collectors.
Publishing duplicate/no-op images is harmless but increases the state space.

Delete floors are retained indefinitely in this design model. This is a REQUIRED
anti-resurrection abstraction, not a claim that current SQL retains all explicit or
omission tombstones forever (merge.ts pending-delete protection is watermark-bound).
Implementers must prove an equivalent ordering/floor protocol before treating model
results as implementation evidence. Content/SEEN stamp compaction is collapsed to
the effective observation stamp. Source mutation itself is not a committed record.

## Properties and discrimination
P1 NoOmissionBeforeProof tracks actual omission removals, whether committed to D
or subsequently visible in any R prefix. P2 tracks removal by failed End only;
an independent W delete is not attributed to a failed run.
P3 compares each device with deletion floors in its own committed prefix, so a
lagging reader is not falsely called a resurrection. P4 compares pre-omission
later rows with post-End rows. P5 is the permitted quiescence invariant, not a
fairness/liveness claim: inactive run and fully replayed log imply both stores
equal an independent greatest-stamp oracle. P6 checks acknowledged batches are
included in merged batches.

Expected witnesses below are reasoning examples, NOT TLC results or measured
counterexample lengths. Exact/minimal lengths: UNAVAILABLE until host execution.
- m1.cfg: W seeds k1; Begin; Batch(k2) with k1 absent from that batch. Early omission
  violates P1 before proof. R can then publish that premature removal.
- m2.cfg: W seeds k1; Begin with source absent; Prove; End(FALSE). Failed replace
  violates P1 and P2.
- m3.cfg: Begin with source absent; W upserts k1; Prove; End(TRUE). Missing cutoff
  removes a later row, violating P4; after draining Publish, P5 also fails.
- m4.cfg: Begin with source k1; W deletes k1; Batch(k1). Unconditional old-stamp
  overwrite violates P3; after failure/end and draining publication, P5 fails.
TLC stops at the first invariant failure, so to observe subsequent P5 witnesses,
rerun a copied mutant config checking only TypeOK and StampConvergence.
P6 is NOT discriminated by these four mandated mutants: none advances checkpoints
ahead of merge. Add an independently authorized premature-checkpoint mutant for a
future discrimination test rather than pretending these four test that rule.

## Host gate
From this directory, with an independently available trusted tla2tools.jar:
```
java -cp /path/to/tla2tools.jar tla2sany.SANY BatchVisibility.tla
for cfg in TODAY-*.cfg PROPOSED-*.cfg m?.cfg; do
  java -cp /path/to/tla2tools.jar tlc2.TLC -workers 2 -config "$cfg" BatchVisibility.tla
done
```
Record each config's generated states, distinct states, depth, Error/No error
lines and measured counterexample length here. Baselines must pass; mutants must
fail semantically, not from parser/type/runtime errors. MaxSteps=8 bounds source,
writer and collector actions; Publish may drain after the bound. This is finite
bounded exploration, not an unbounded proof. Increase the bound separately and
report cost/results. Deadlock checking is disabled because exhaustion intentionally
stutters; no liveness property is asserted.

# Replication policy v3: versioned staging profile

This profile prevents busy devices from winning merely because they emitted more operations. It is **not runtime activation**: the existing, default-off `replication.enabled` path still uses v1. Steps 5–7 below must land before enabling a production v3 stream.

## Version coexistence (step 1)

- Existing `replication/envelope.ts`, `revision.ts`, `merge-plan.ts`, reducers, wire golden and tests remain unchanged. V1 retains its Lamport/origin ordering, exact bytes/digests, operation kinds, completion dependencies and rebaseline semantics.
- This directory is a separate profile. Its envelope has `version: 3`; neither decoder accepts the other version. No operation is rewritten, re-signed, rehashed or automatically translated between versions. A mixed-history migration is not defined here.
- V3 is exposed only by the additive `replication/policy-v3` staging API. Node/Lite adapters do not modify their existing canonical stores or indexes. Their missing/false `replication.enabled` option refuses work without reading operations.
- `canonical.ts` deliberately copies the exact v1 `exactJson` algorithm so the trusted-input kernel can run without loading an ingress schema dependency. Both golden vectors and own-key/sparse-array tests pin parity. Any future serializer change requires reviewing BOTH profiles and their byte/digest compatibility; do not silently replace v1.
- N01–N29 live beside v1 in `merge-plan.test.ts`; the research's three-device 01–56 scenarios remain in `three-device-ordering.test.ts`, including fixture 18's changed display. Research local-display expectations use `ownerView`; separate assertions enforce stricter app visibility.

## Schema and causal evidence (step 2)

Every v3 operation carries an issuer/subject `upstreamAccount`, batch identity and raw per-writer frontier. The envelope binds owner, batch, frontier, declaration and one writer. Transport may additionally supply its authenticated `writerId`. These consistency checks are NOT signature verification. A self-received writer frontier is rejected by the envelope decoder.

The host supplies exactly one verified connector principal per source/connection; login names are not identities. Account/source admission runs before global operation-ID equivocation facts so a foreign binding cannot erase the legitimate connection's view. Method mismatches are quarantined before deletion. Equivocation among admitted operations remains connection-wide, including cross-key collisions.

HLC uses exact logical counters (number or unsigned 64-bit decimal string). `nextHlc` caps observed remote wall time at local now + 300000 ms; `recordRawReceipt` and `observeRemoteClocks` separately preserve the **uncapped** remote causal frontier. The host must atomically persist the clock/frontier and surface clock warnings in step 5. Never store the capped local clock as a remote frontier.

V3 preserves blob-claim, stream-invalidate and stream-complete shapes, proofs and dependency digests, but this planner holds their effects as typed `host_effect_requires_v3_runtime` pending work. It does not verify blob bytes, mark completion or apply visibility. V1 continues to provide those guarantees unchanged. V3 rebaseline/copy-origin capture is deliberately not implemented; do not assign an old operation a fresh observation time or silently convert a v1 origin.

## Full-history oracle (step 3)

`planReplicaMerge` validates the v3 schema then calls the dependency-free `planAdmittedReplicaMerge` kernel. The latter is an INTERNAL trusted-input boundary, not an alternative parser: callers must already have authenticated/admitted operations. Pure input/context functions do not schedule, erase or commit anything.

Ordering is declared source-version dominance, then raw causal frontier/same-writer order, then observation time capped by authenticated batch finality, then exact HLC logical/writer/operation tie. Before finality the observation is uncapped. Different domains/incarnations are incomparable; equality-only versions detect contradictions but do not impose order. A later lower-version upsert in the same incarnation as a source deletion is retained as an unsettled incarnation-reuse witness rather than permanently dominated.

Close, incomparable differing values (inclusive 300000 ms) are unsettled, or conflict when the source is not reobservable. Equal-content observations do not create disagreement. Complete-scan deletion requires a declared capability and a second, causally later, writer-qualified agreeing scan. Partial absence is not an event. Re-observation requests are suppressed by the supplied `reobservedRecords` marker; durable per-day scheduling and marker lifecycle are step 7, not a wall-clock side effect of this oracle.

Owner hide/delete/restore uses writer-qualified explicit parents. A restore clears only named removals; concurrent unseen removals win. Source observations never clear owner removal. Resolutions require admitted same-record dependencies and retain conflicts between competing choices.

### Decision versus payload availability

`current` is **payload-free selected observation metadata** (including revision, content hash and emitted time); `value` is the optionally retained payload operation. `state` and `current` are computed without the grace clock. Advancing only `now` can remove `value`/candidate payloads and produce erasure instructions/markers, but cannot change the selected identity or policy state. `ownerView` is a local preview; `appView` requires an explicit `{ confirmed: true }` fact from the host (default false), plus `settled`, unsuppressed, retained upsert data. Finality is not inferred to be host confirmation. Neither grants authority nor represents host-confirmed ingestion until step 6 wires the confirmed-only host surface.

Delete grace is 30 days from delete **batch finality**. Only restore **batch finality strictly before the deadline** prevents expiry; a forward-skew HLC does not make a timely restore late. At the exact deadline it is late. Payload-free suppression markers prevent erased bytes from being replayed into `value`. The host must atomically persist markers and erase payloads; this patch performs neither. Post-compaction hosts must preserve decision metadata as well as suppression evidence, not infer a complete operation set from payloads left on disk. If retention filtering selects a different payload identity than `current`, `value` fails closed with `selected-payload-unavailable`. For example, an erased, unfinalized, forward-skewed old observation can hold a fresh post-restore value unavailable until verified finality/evidence resolves the policy selection. This availability limitation is intentional; step6 must not expose a mismatched payload or silently rewrite the selected decision.

## Exact bounded evidence (step 4)

The bounded reducer stores every distinct canonical operation variant, under caller-supplied finite operation-count AND UTF-8 canonical-byte budgets. It retains losers, named ancestors, unconfirmed scans, conflicting resolutions, cross-key equivocations and lifecycle history. It does **not** claim winner-only compaction is sufficient.

Proof for accepted prefixes: initially evidence is the empty set. For one atomic push, validate every input, add each distinct canonical encoding once, and check both capacities before mutation. If any check/projection fails, retain the entire old state. Otherwise evidence becomes exactly the union of the old evidence and the admitted input. By induction, projecting evidence equals the full-history oracle for EVERY accepted delivery prefix. Reprojection uses the same set with updated verified finality/declarations/markers. Detached receipts prevent caller mutation from rewriting evidence. Principal/declaration/re-observation/marker data and grace time are defensively copied. Accepted batch finality is cached atomically, including an explicit missing value, and changes only on `reproject`. A new batch is sampled on first acceptance. JavaScript predicate/provider closures cannot be cloned: `validateData` must remain pure and immutable, and the finality provider must return verified facts; replacing caller object properties does not alter captured function values.

This is bounded staging, **not constant-space compaction**, not an unbounded production index, and not a transport resource-admission boundary. Capacity refusal is not acknowledgement of the new set. Different delivery orders may reach capacity with different partial sets; the host must not expose either as a complete converged view or advance custody/checkpoints. Keep refused evidence durably pending until an authorized larger budget/index strategy exists. Transient JSON parsing/allocation and declaration/context size also require step 7 admission controls.

Node and Lite share this exact reducer. Their additive adapters are staging-only; the existing canonical-store/reducer paths and cursor epochs are not changed. Native validated-input kernel checks cover prefix equivalence. Authenticated wrapper/actual-storage/native repository suites remain a separate gate.

## Reproducible checks and explicit limits

Dependency-free Node24 checks (source loader resolves adjacent `.js` imports to the real `.ts` files, with no schema mocks):

```sh
node --experimental-loader ./packages/core/src/replication/policy-v3/node-source-loader.mjs \
  --test --test-concurrency=4 \
  ./packages/core/src/replication/policy-v3/kernel.node-check.mjs \
  ./packages/core/src/replication/policy-v3/revision.node-check.mjs
```

The initial implementation run passed 64/64. These are actual trusted-kernel/reducer and HLC tests, NOT Vitest, schema-admission, SQLite, IndexedDB, storage crash/reopen or authenticated transport tests. Three admission-order negative controls failed against the research-derived draft before the fix. The v1 large-counter control executes unchanged v1 ordering; missing v3 APIs on baseline are only feature-absence evidence, not behavioral red tests for all new features.

The normal Vitest suites are authored for envelope/schema, research policy vectors, three-device fixtures and Node/Lite prefix differential checks. Every eventual invocation MUST include `--maxWorkers=4`. No main test was deleted, changed or skipped. In the scoped source-only environment, `zod`, `vitest`, `typescript` and `prettier` were absent; root/package manifests, native test/build/lint configurations and broader dependency closure were outside the assignment's read scope. Thus repository/native aggregate tests, nightly authority/manifest (`REPLICA_ORACLE_NIGHTLY=1`), builds, lint/eslint and format:check were NOT RUN. This patch is not ready for runtime activation or acceptance until those gates pass.

## Required split before runtime enablement

5. Transactional Node/Lite capture, migration and rebaseline: persist principal, HLC/raw frontier and immutable operation bytes; preserve v1 origin ordering, writer rotation, stale attempts, flags, rollback/reopen and atomic capture/settlement. `storage/pdpp-records/portable.ts:3` already reexports the journal; `replication-journal.ts:3–20` is `CanonicalMutation` and explicitly says its sequence/record version are not replica revisions. Those contracts were read and remain unchanged.
6. Host projection and erasure: confirmed-only grants/app surfaces, explicit unsettled/owner controls, verified blobs/completion dependencies, cursor epochs, decision metadata and atomic payload-erasure/suppression markers. Never expose the owner preview as a confirmed grant.
7. Authenticated batch-finality association and durable typed re-observation/backoff, including admission bounds for frontier/parents/retained evidence and stale-attempt fencing. Hints and collected-at timestamps are not authenticated finality.
8. Run existing core/server/Lite/authority/manifest integration suites plus all v3 suites, native type/build/lint/format gates, and genuine baseline-to-candidate behavioral red/green evidence. Do not substitute the 64 trusted-input checks for this acceptance gate.

## Open research clarification (conservative behavior preserved)

B observes Y at t0; A observes X at t+1s and its raw frontier includes B; C observes X at t+2s without seeing B. B is not a causal maximum, and A/C have equal content. The research oracle still reports unsettled because it checks B's disagreement against current C rather than against only causal maxima. The brief's grouping wording could suggest settled X. This patch deliberately preserves the conservative unsettled result, pins the witness in the native checks, and asks the submitting owner to clarify; it does not silently weaken uncertainty.

# PDPP publication and read evidence: review context

This is evidence for scoped review of PR #455, not merge or release approval.
The historical F1 disclosure gate remains unresolved. New generated outputs and
projected dependency cycles are a separate repair scope. No migration, quarantine,
receipt scheme, automatic recompute, blanket denial, history deletion, grant change
or live operation is implemented here.

The complete preceding reports follow. Local filesystem paths are normalized;
original raw reports remain with the owner. Historical verdicts describe their
exact heads and briefs. The old-eab broader concerns were absent from earlier
briefs, so the 996d acceptance does not certify them.

Read only the new review's explicit source allow-list. Denied source references in
these historical reports are context, never instructions to retry those reads.
In particular, contract/token/job internals remain outside the new review scope.
Use authorized public boundaries and tests for evidence instead.

## Current contracts and responses

The original non-owner publication, origin union, classifier, exact own-write and
payment contracts below remain requirements. Prior F3 ownership occurs at common
acquisition before approval and must survive this repair.

The broader report's F1 is reproduced: a real owner compute over bank.transactions
returns source coordinates to a builder granted only the derived scope. The new
server-owned reserved lineage kind identifies future computed metadata. Envelope,
byte and versioned block representations share that policy; ordinary user-authored
sources remain content. Historical unmarked outputs lack a trusted immutable
compute discriminator. The pre-marker/lookalike fixtures demonstrate retained
source coordinates, which is an unresolved release blocker, not F1 closure.

The broader report's F2 is reproduced through requested/joined projected inputs
and projected intermediates: all four ran inference and published on 996d. Internal
read evidence now retains immutable dependency IDs and actual input-version
identities separately from presentation. Projection unions consumed inputs;
unused legacy siblings are excluded. Guard snapshots explicitly transfer evidence.
Both initial reads and graph traversal use it. Failed extraction fails compute.

A later boundary probe also reproduced generated source metadata in builder
compute's inference prompt. Compute now uses the same object renderer as HTTP,
after retaining its internal dependency facts. No compute own-write exception.

The parent owns historical preparation and any further existing-receipt evidence
investigation. Mutable latest registration state, payload shape, questionId,
lineage plus sources and producer strings are not historical compute identity.
Any future historical policy requires separately judged exact-version evidence;
no such interface or execution is approved by this repair.

## Original review brief (complete)

````text
Independent defensive code review only; return empty diff, no edits, commits, pushes, browser, deploy, or new model tasks. Repository vana-com/personal-server-ts PR455 head c57ec2d3f14a89138aa31d2ff37a96385e516f98, base bbf806e07b95b8fed68cda314d200b10fb5082e3 (PR457). Review only base..head, with latest repair 6614bbd6..head. Read allow-list is exactly scope_paths. Maker for latest repair: gpt-6.1-sol. Report the actual reviewer model if available; a different model is required for judged acceptance. Do not claim independence if unverifiable.

Outcome contract: on a PDPP-enabled server every non-owner write (JSON/binary/write session, lineage or none) and builder-registered compute is PDPP-origin. Explicit off (Lite) preserves legacy, unknown fails closed. Owner compute combines observed provenance of all inputs. Historical lineage without a well-formed legacy-origin marker is PDPP until recomputed/rewritten. No binding-history exposure lookup. Own-write read-back applies only to exact stored unprojected HTTP envelopes with server-stamped writer matching recovered signer; compute, joins, MCP blocks and jobs excluded.

Round5 findings and round6 responses:
P1 configured PDPP with no retained declarations had no resource routes and published legacy. Composition root now shares pdppConfigured with ingest and compute; createApp unknown fails closed.
P1 A-era generation-bound manifest classified old lineage as legacy, leaking through MCP. Manifest now carries pdppClassifier=2; only current classifier origin trusted; old sidecar falls back to generation-checked stored bytes under current classifier.
P2 own-write conversations projection joined legacy messages never written by reader. Projection inputs now go through a plain grantee guard, separate from own-write classification reads.
P2 unrelated reader got402, settled, then403. Read pipeline now authorizes and retains response before payment for all index provenance values. Authorized missing derivative still triggers compute.

Local evidence: actual real createServer and signed HTTP/MCP boundary tests reproduced7 failures on6614bbd6 with2 controls passing, then11 final cases pass. A separate compute-only toggle reproduced200/leaked marker vs403. Unknown createApp toggle reproduced200 vs403. Related8files254tests passed; package core/server tsc and changed-file eslint/prettier pass. Gateway/inference fake; real Node SQLite/filesystem. No fullsuite/install/liveOAuth/remote replica/latest A/B claim. A is independently changing byte redaction, representation identity and UTF8 pagination; do not turn A-owned preexisting findings into new D blockers unless D materially causes them. B owns branded read ports and bounded projection streams. Explicitly state integration limitations.

Look for missing actual-boundary tests, bypasses, stale classifier trust, exception projection/caching leaks, payment rereads after settlement, enabled-state inconsistency. Check preservation of current sidecars, writer historical versions, other-reader refusal, disabled compute/direct writes, unknown failclosed, and initial compute demand. Prefer finding root owners over line patches. Terse P0-P2 findings with concrete scenario and file:line; distinguish reproduced vs inspected. You may run bounded offline checks only if available; no dependency installation needed for a static review.

# Review rubric: design and architecture before lines

Paste this into every review brief, whether it goes to the dot, Opus, Sonnet or Sol. Use the following inline rubric, with Hickey's Simple Made Easy at the center. Meadows' leverage points add one idea and no more: a change higher in the system outweighs any amount of tuning lower down, so review the design before the lines.

Why it matters: line-level review kept circling defects that were really design defects. Examples:
- data-connectors #509 and dc#519 each took three patch rounds. dc#519 was fixed only when `InventoryEvidence` became the single owner of completeness.
- The replication backoff braided "waiting" with "error".
- The 8a test check couldn't see the fields that mattered.

## Questions, answered in order

1. **Goal.** Does the design serve the real goal, or a proxy such as passing tests or green CI? Is the problem framed correctly?
2. **Decomplecting (Hickey).** What is braided that should be independent? Check each pair:
   - state and value;
   - time and identity;
   - policy and mechanism;
   - domain logic and I/O;
   - parsing and execution;
   - representation and meaning;
   - waiting and error;
   - unrelated reasons for change.

   Simple (un-braided) is objective; easy (familiar) is taste, so optimize for simple. Splitting code into more files is not decomplecting (canon R5: relocation is not abstraction).
3. **Invariant ownership and information hiding.** Which single component owns each invariant: completeness, ordering, identity, authorization, durability, visibility? Do two places decide the same thing? Does each module hide one decision that's likely to change (Parnas)? Is the module deep: a small interface hiding real work (Ousterhout)?
4. **Explicit state and effects; information flow.** Are time, mutation, I/O, retries and caching visible and controlled? Does each decision see the state it needs? Is anything hidden, dropped, or reported as success when it's only partial? This covers logs that hide causes, diagnostics that drop reasons, and oracles blind to the fields that matter.
5. **Feedback loops.** Can a retry, backoff, poll, cursor or reconciliation stall, starve or run away? Does it converge? Is it observable?
6. **Fit to real data.** Real sizes and shapes: whole-object copies, memory, the shapes real services actually return. Fit the code to the data, not to a pretty abstraction.
7. **Local reasoning and honest names.** Can each unit be understood from its name, signature and tests? Is each name a true invariant?
8. **Then** parameters, buffers, and line-level correctness and tests. Behavior preservation is a gate (canon R2). Prove the diff; don't narrate it (R4).

## Required output

```
Verdict: MERGE | MERGE-WITH-NITS | DON'T MERGE
1 goal: <finding, or "no issue: why">
2 complected concerns: <...>
3 invariant owners (list each -> owner): <...>
4 state/effects/information flow: <...>
5 feedback loops: <...>
6 fit to real data: <...>
Lower-level findings (P0-P2, file:line): <...>
Would a different, simpler design make several of these findings disappear? <yes/no + which>
```

When the same kind of finding repeats across rounds, name the owning component and recommend the structural fix, not another patch (memory: `feedback-system-design-before-patch-rounds`).

````

## R6 exact c57 dot (unknown model)

```text
Exact head c57ec2d3f14a89138aa31d2ff37a96385e516f98. Verdict DON'T MERGE. Actual model unknown; different-model judged acceptance not certified. Root source-only review, no new agents/model tasks, tests, edits or installs.
1 Goal: correct origin and non-owner disclosure before paid effects; appropriate goal.
2 Concerns: publication policy is separated from writer claims, but mounted/configured state is still resolved differently by two composition paths. Retained response identity and payment identity remain separately selected.
3 Owners: origin classification→publication-origin/hasPdppOrigin; stored origin→ingestDataContract; old-manifest trust→trustedPdppOrigin classifier2; projection inputs→plain grantee storage; HTTP served-version/payment binding should have one selected-response owner.
4 Effects: actual guarded body is now read before settlement and retained, closing refusal-after-payment for static bodies. A second metadata selection after an await reopens version inconsistency (F2).
5 Feedback: stale-classifier manifests fail trust and rebuild from generation-checked bytes; no new retry loop found. Best-effort repair remains fallible.
6 Data: no whole-stream redesign demanded; bounded stream/projected-memory work belongs to B. Mutable block snapshot defect belongs to A and is excluded here.

F1 P1 — packages/server/src/app.ts462–467: createApp can publish legacy while PDPP is mounted. With deps.pdpp present, config.pdpp.enabled=false, and no explicit deps.pdppEnabled, the nullish chain selects false before checking mounted authority. The non-owner publication owner treats false as definitive disabled, so writes can get legacy origin despite a live PDPP surface. Previously app at6614bbd6 selected deps.pdpp!==undefined; current bootstrap helper pdpp/bootstrap.ts405–409 correctly ORs configured with mounted and configured.test.ts8–10 explicitly covers mounted+flagoff. createServer passes the shared function, but directly composed createApp does not. Fix default derivation to use same configured-or-mounted owner, preserving unknown failclosed and genuinely disabled Lite. Add actual createApp write test with mounted authority/configfalse. Source-supported scenario, not executed.

F2 P2 — packages/core/src/api/index.ts2115–2134,2224–2230; handleX402Cycle830,844–855: retained response A can be charged/attested as replacement/latest B. Unpinned GET selects and reads A (at selectedEntry.collectedAt), then enters payment with original atParam/fileIdParam, both absent. handleX402Cycle awaits gateway.getGrant before a new storage.findEntry without A's identity. A concurrent publication or demand-triggered recompute makes B latest during that await. Challenge/accessRecord uses B's version while response and servedFileId remain A. The new retained-body ordering makes this mismatch deterministic once the race occurs. Fix pass immutable selected response entry identity/version into payment, never reselect latest for a retained body. Test by publishing B during getGrant and assert challenge/settlement attestation version and returned body both remain A (or refuse before charge). Metadata identity must be bound even when no second body read occurs. No runtime reproduction claimed.

Round5 closure: configured-with-no-retained-declarations is fixed in createServer through shared pdppConfigured, but F1 remains alternate composition regression. Old classifier manifest trust closed statically: digest trustedPdppOrigin requires version2 and absent current classification takes checked-envelope fallback. Own-write joined projection exception closed in inspected resolver: reader-specific classification and plain grantee input reads distinct (legacy-projection126–134,265–269,534–541), per-reader caches; B still owns stronger mutable/cap identity. Unrelated-reader402→403 closed for body refusal by prepayment guarded read; F2 is a separate payment identity gap. Authorized missing derivative still calls notifyDataRead on404.

Simpler completion: share one enabled-state resolver and one selected-response descriptor between disclosure and payment rather than independently recomputing those invariants. Evidence: exact-SHA GitHub reads in allowed API, contracts, origin, lineage, storage/classifier/projection, compute, composition and selected tests; prior6614bbd6 app inspected for F1 comparison. Maker's254 tests and11 boundary cases are attributed only, not rerun. Not every scoped test line or baseline file compared. No live Gateway/inference, latest A/B or combined-stack acceptance. Owner note452056a4 read; A mutable-block issue not reclassified as D finding. Cancellation/authority and owner notes rechecked before finish; empty patch.

```

## R7 integrated eab7 dot (unknown model)

```text
Exact integrated eab7e8f8283bd06c7a5f02f78ae543d14799f295. Verdict MERGE within scoped static D review, no runtime/combined-final-stack or different-model acceptance certificate. Actual reviewer model unknown. Root review, no further agents/model tasks/tests/edits.
1 Goal: non-owner origin conservatism and paid-read correctness, not test-count proxy. 2 Decomposition: shared configured-state resolver removes duplicated mounted/configflag semantics; selected response identity now travels with body to payment rather than being rediscovered. Reader-aware own-write classification stays distinct from plain grantee projection inputs. 3 Owners: publication-origin/hasPdppOrigin own provenance; ingest stamps output; trustedPdppOrigin owns classifier freshness; readDataContract owns selected body+entry; payment consumes snapshot; A pager owns detached representation/cursors. 4 State/effects: selected index row cloned before body await; payment extracts primitives before getGrant await, no latest reselection for retained HTTP response. Origin decision occurs before settlement. 5 Convergence: older sidecar classification still rebuilds from checked owned envelope; no new retry-loop issue found. 6 Real data: whole-envelope/projection memory limits remain B's responsibility, not certified by D.
Prior F1 CLOSED: server/app.ts463–465 uses pdppIsConfigured(deps.config,deps.pdpp??deps.pdppAuth); bootstrap405–409 prioritizes mounted authority and returns undefined when no configuration, preserving unknown failclosed via nonOwnerPublicationIsPdpp. mounted+configfalse no longer selectsfalse. Shared helper used by composition; explicit configuredoff with nomount stillfalse.
Prior F2 CLOSED: contracts/data.ts639 clones selectedEntry before read await and returns it666; API2138–2140 retains result.entry/fileId;2231 passes selectedEntry to X402. Helper829–844 snapshots scope/datapoint/version before grant refresh849. Thus A's body and attestation remain A if B appears during getGrant. Default direct helper fallback also resolves before await. Test source data.test3044–3137 covers challenge and honestpaid proof with replacement during grant refresh, not just pure helper equality; tests were not run.
Earlier D closures retained in inspected source: originclassifier2 trusts only currentmanifest provenance; manifestBinding preserves A redaction alongside generation/classifier result. Projection resolver uses reader-aware exactunprojected classification but plain grantee projectionRaw for each actual input, per-reader viewcache. Buildercompute calls shared nonOwnerPublicationIsPdpp while ownercompute retains observed input union. Guarded HTTP body remains materialized before payment and authorizedmiss triggers derivative demand.
A integration checks: compared selected exact two-endpoint files against ffecd0ab (not merge-base). core/storage/blocks/page.ts and core/mcp/read-client.ts are byte-identical. D digest changes add classifier gating while retain redaction evidence; disclosure fallback still structuredClones object envelope at acquisition beforegeneration/authorization/build. TOC/pager metadata and boundedUTF8 contracts not relaxed. No new P0-P2 in inspected D integration seams.
Evidence/limits: exact-SHA GitHub reads of scoped composition,API,contracts,publication,compute,classifier,disclosure/projection and selectedtestsource; exact two-endpoint comparison limited to selected integrationfiles, not exhaustive everyfilefullrange. No dependency install, test/build/lint, network beyond repository, credential-source, browser, Work/Codex/modelAPI/meteredtools. Reported maker RED/GREEN and final test totals not independentlyexecuted. A sourceverdict doesnot prove Gateway/livepayment/OPFS/IndexedDB/wholefinalstack. B separatelyowned and notintegrated/certified here. No merge/release performed. Cancellation and notes rechecked clear beforefinish; emptypatch.
```

## R7 integrated eab7 Astra (F3 RED)

```text
Verdict: DON'T MERGE

Reviewed local HEAD eab7e8f8283bd06c7a5f02f78ae543d14799f295 in the reviewed checkout. Endpoint comparison: ffecd0ab75780101ad9b1b0f9d462053409e11c8 -> HEAD, two endpoints. Checkout stayed clean. Empty patch.

Reviewer provenance: gpt-6-astra, high reasoning effort, as identified by this session's injected T3 runtime_info. Maker was gpt-6.1-sol high per supplied brief. This is known different-model review at the harness-reported level; no independently retrieved provider receipt is claimed. No further agents/model calls, installs, Git mutations, browser, full suite, or live service tests.

1 goal: Correct goal: publication provenance and exact authorized disclosure before payment, not merely green tests. Most original policy defects are repaired; retained HTTP bodies still lack immutable ownership.
2 complected concerns: HTTP retains a storage-owned mutable value across payment. Time and body identity remain braided even though selected entry metadata is copied. A block fallback and pager already own their values, but HTTP does not.
3 invariant owners: configured state -> pdppIsConfigured; non-owner publication -> nonOwnerPublicationIsPdpp; observed source union -> compute/loadSource and legacy-projection; stored origin stamp -> ingest contracts; historical classifier trust -> trustedPdppOrigin/manifestBinding; disclosure -> withDisclosurePolicy; block ordering/representation -> shared pager; HTTP body plus payment identity -> incomplete readDataContract/GET boundary. That last boundary must own one immutable selected response.
4 state/effects/information flow: Reproduced below. The grant refresh sees a storage mutation after policy approval; payment settles once; serialization then emits the changed body. Capturing only IndexEntry does not preserve the approved data.
5 feedback loops: No additional cursor/retry stall found. Old classifier sidecars fall back to checked stored envelopes, with best-effort repair. Existing cursor and generation regression checks pass.
6 fit to real data: Node JSON reads normally return owned objects; the actual Lite IndexedDB fallback returns Map-owned objects. The HTTP path must support that actual adapter shape. Whole-envelope and stream budget improvements remain B-owned; no performance-scale claim.
7 local reasoning: The comment "retain the exact response" currently overstates the body ownership invariant. Readonly<IndexEntry> describes metadata only.

Lower-level finding F3, P1 — retained HTTP body can change after disclosure approval (reproduced).

Locations:
- packages/core/src/api/index.ts:2138 retains result.envelope directly, before the payment await at :2230 and later serialization/redaction at :2260.
- packages/core/src/contracts/data.ts:639 clones the entry, but :648/:668 read and return the borrowed envelope.
- packages/core/src/storage/disclosure-policy.ts:104 authorizes and returns raw.readEnvelope's object without owning it.
- Actual adapter: packages/lite/src/storage.ts:168 and :640 return the retained object.

Scenario: Seed a valid legacy envelope through createPersistentPsLiteStorage + createIndexedDbFallbackDataFileStore. Drive the real signed data HTTP route with a valid signed X-PAYMENT and a local Gateway double. At the second getGrant call (the payment refresh), mutate the store-owned envelope's nested marker and add native $pdpp metadata. The final head settles and returns the new PDPP marker, although only the original legacy body passed policy. This uses the same borrowed-object behavior accepted as material in A's fallback ownership work. It is a deterministic in-process storage mutation, not evidence of remote code execution or of a live production incident.

Raw head observations are in http-ownership-head.jsonl:
- control: status 200, grantCalls 2, settled 1, body marker authorized-original.
- legacy mutation: status 200, grantCalls 2, settled 1, body marker legacy-mutation-after-policy.
- PDPP mutation: status 200, grantCalls 2, settled 1, body marker pdpp-mutation-after-policy, native $pdpp included.

Independent probe: 2 failures / 1 passing control. The oracle requires no post-approval marker in the response, and any 200 response to contain authorized-original.

Causal comparison: the same probe with ONLY core/api/index.ts supplied in memory from ffecd0ab returns 403 GRANT_REQUIRED for the PDPP mutation, without the marker. Control remains 200/original. This comparison keeps final dependencies and is not a full-baseline validation. Baseline also settles once before refusal (the previously known ordering defect); it is not the recommended behavior. It isolates the new disclosure window caused by retaining the body earlier.

Owning invariant / required repair: Have the selected-response/disclosure boundary acquire an owned immutable envelope before checking policy, and carry that same approved body and its selected identity through payment and delivery. Do not merely add a late refusal after settlement, or clone only metadata. Keep the old refusal-before-payment and F2 identity tests, and add this borrowed-envelope payment-window regression. No patch was produced.

Original findings closure:
- R1/R2: inspected observed provenance union across owner compute and joined input reads, conservative historical lineage classification, and guarded selected reads. Existing focused boundary tests pass; HTTP ownership is the remaining F3 limitation.
- R3/R4: non-owner origin no longer relies on exposure/binding-history absence or app citations; enabled/unknown publications and builder compute use the shared publication policy. Explicit-disabled and owner legacy controls pass.
- R5 configured/no declarations and alternate unknown state: focused real createServer and createApp cases pass; F1 mounted authority + false config now uses the shared resolver and its actual route regression passes.
- R5 stale manifests: classifier 2 is required before origin trust; old classifier fixtures exercise fallback. Guarded MCP and inherited generation tests pass.
- R5 own-write projection and reader cache: exact writer readback, other writer refusal, joined-input refusal and cache eviction cases pass. Compute/MCP remain plain grantee reads.
- R5 static refusal-before-payment: both stale false/true index cases pass. F3 is a different mutable-body window after that decision.
- Original F2: challenge/settlement identity stays on retained A when B becomes latest; both signed HTTP regression cases pass. This closes reselection, not body aliasing.
- A fallback: all 18 actual Lite/MCP fallback ownership tests pass. A page.ts is byte-unchanged from e536. page/cursor/select, MCP read-client and Lite storage are unchanged vs ffecd. A representation redaction, full-block verification, cursor identity and UTF-8 controls pass. Two legacy fixtures gained writtenAt without dropping assertions. F3 is the separate D HTTP reordering regression, not a reopening of the repaired block fallback.
- B is not integrated here. Existing pager budgets and pinned-version contracts were inspected for preservation; no acceptance of B's pending brand/budget/stream work.

Reviewer-run evidence (Node v22.23.3):
- focused.log: 15 files / 393 tests passed (40.81s).
- boot.log: 3 real-bootstrap cases passed / 23 deliberately skipped (9.04s).
- http-ownership-head.log: 2 failed / 1 passed; full raw responses in http-ownership-head.jsonl.
- http-ownership-baseline.log: 2 passed / 1 skipped; full raw responses in http-ownership-baseline.jsonl; API-only comparative transform described above.
- diff-check.log: git diff --check clean.
- verification.json: exact HEAD, clean status, Node, provenance statement, preservation diffs.
- http-ownership.test.ts and probe.config.mjs: preserved reproduction outside the checkout; scaffold copied from existing signed HTTP tests, source imports point to the reviewed checkout. No checkout test edits.

Would a different, simpler design make several findings disappear? Yes. One owned prepared-response value should bind approved bytes and selected entry identity. It addresses the same missing owner behind F2/F3 without another independently timed selection or late policy check.

Limits: no new tsc/ESLint/format run (maker reports attributed only), no full suite, live OAuth/inference/Gateway/remote replica/browser tests, or whole-stack acceptance. Focused checks cannot prove all runtime compositions. High confidence in F3's deterministic reproduction and its API-ordering cause; no assertion that every caller can trigger the tested in-process mutation remotely. No dev servers remain. Evidence files under astra-final are intentionally retained.

```

## R8 exact996d dot (incomplete gate)

```text
Exact996d4944b3583e1cff8660f26d60f2e72787c2e6. Actual model unknown; cannot certify different-model independence. Verdict DON'T MERGE as incomplete full-review gate, not rejection of the F3 repair.
Read supplied full c57/eab7 dot/Astra reports. F3 CLOSED structurally: storage/disclosure-policy.ts99-110 structuredClones borrowed envelope immediately after acquisition and before authorizeEnvelope, returning the owned approved value. Not an HTTP-after-await clone or late403. routes/data.test.ts3044-3144 tests actual IndexedDB fallback alias (toBe(source)), both payment-refresh and guard-return/caller-resume windows, control/legacy/PDPP mutation. It asserts exact authorized-original response,200 and one settlement. The nested microtask seam specifically challenges a too-late caller clone. No tests rerun; supplied399+3 and red/green counts attributed only.
1 Goal: bind approved bytes and selected payment identity before paid effects; correct invariant.
2 Concerns: storage ownership now separated from later mutation/payment timing. Origin classification remains independent of citations. No new retry or provider coupling in this repair.
3 Owners: withDisclosurePolicy owns acquired approved envelope; publication-origin owns conservative origin; selected entry/payment binding remains contract/API-owned; classifier trust owns old-manifest fallback. Missing contract source prevents a fresh complete check of that link.
4 Effects/information: explicit owned object prevents demonstrated mutable-body window. Reviewed digest.ts current classifier gate and manifestBinding retain redaction evidence. Read selected compute/projection and legacy disclosure source, not all endpoints.
5 Feedback: no new loop in delta. Existing projection/sidecar behavior not performance-certified.
6 Real data: actual borrowed Lite object adapter is represented in test; structuredClone costs proportional memory, no bounded-memory claim or B integration acceptance.
7 Local reasoning: acquisition comment now accurately names invariant. Shared guard preferable to endpoint-specific late defenses.
8 Prior statuses: F3 structurally closed; F1 mounted authority and F2 retained version remain prior eab7 conclusions, not independently re-certified across every current path. Earlier R1-R5/A integration likewise not blanket current acceptance.
Other current review evidence: broader exact-eab7 report_8457f2a7-eea5-485f-9426-cd563961f095 raised generated sources metadata disclosure and projection hiding lineage from cycle walk. Current compute.ts600-604 still emits source scope/version/time and460-462 still reads lineage from served envelope; this review did not establish complete current boundary behavior or new reproduction, so these are unresolved cross-review concerns, NOT additional independently confirmed findings or duplicate new P1 claims. Parent should reconcile them before broad acceptance rather than infer F3 fix addresses them.
Blocker/limitations: prior denial for packages/core/src/contracts/data.ts remains; not retried via another tool or new assignment. Required full contract/payment re-audit cannot be completed here. No exhaustive two-endpoint comparison, edits, Git mutation, installs, tests, builds, model tasks, live Gateway/OAuth/inference/replica or combined stack checks. No merge/release action. Deliverable: precise F3 closure evidence and remaining acceptance limits, empty patch.
```

## R8 exact996d Astra (historically scoped acceptance)

```text
Verdict: MERGE — scoped review of repaired PR #455, not merge/release or whole-stack authorization.

Exact reviewed HEAD: 996d4944b3583e1cff8660f26d60f2e72787c2e6 in the reviewed checkout. Verified at entry and completion; checkout clean. Latest delta is eab7e8f8283bd06c7a5f02f78ae543d14799f295 -> HEAD. Integration comparisons used two endpoints ffecd0ab75780101ad9b1b0f9d462053409e11c8 -> HEAD, not a merge-base. Empty patch: patch.diff is zero bytes.

Reviewer provenance: gpt-6-astra, high reasoning effort, identified by this session's injected T3 runtime_info. Maker: gpt-6.1-sol high, as supplied in the brief. This provides different-model review at the harness-reported level; no independent provider receipt is claimed. The unknown-model dot reviews are not being counted as independent acceptance. The original e536 provider refusal remains a historical limitation, not an acceptance; this review tested the distinct repaired head.

1 goal: No issue. The repair preserves the actual approved response across asynchronous payment and delivery. It does not substitute a late refusal, metadata-only copy, adapter-only fix, or passing-test count for that outcome.
2 complected concerns: The borrowed storage value is detached before authorization. Time and mutable storage state no longer change the HTTP body after the disclosure decision. Selected response identity already travels with that body; payment consumes it rather than discovering latest again.
3 invariant owners: configured PDPP state -> pdppIsConfigured; non-owner publication -> nonOwnerPublicationIsPdpp; observed source provenance -> inputHasPdppOrigin plus compute/projection input union; publication stamps -> ingestDataContract; historical classifier trust -> trustedPdppOrigin/manifestBinding; envelope acquisition and approval -> withDisclosurePolicy.readAuthorized; selected body and entry -> readDataContract; payment binding -> handleX402Cycle's primitive snapshot; block verification/representation/paging -> shared pager. Reader-specific exact readback remains separate from plain-grantee projection input authorization.
4 state/effects/information flow: readAuthorized clones immediately after the storage await, authorizes that clone synchronously, and returns it. readDataContract copies the selected index entry before reading, then returns that entry with the same approved body. HTTP retains both before demand/payment. Reproduced successful mutation isolation, retained-version settlement, and refusal before settlement; also checked acquisition-time PDPP refusal.
5 feedback loops: No new retry, cursor, or reconciliation issue found. Historical-classifier sidecars still fall back to generation-checked envelope reconstruction; best-effort sidecar repair remains fallible, and subsequent reads still check binding. Representation identity and cursor refusal tests pass.
6 fit to real data: The fix covers the actual Lite Map-owned object adapter through the common guard. It does add a whole-envelope copy, including for adapters that already return owned objects. No scale/performance claim is made. B's separately owned byte/stream/budget work is neither integrated nor accepted here.
7 local reasoning: The acquisition comment now describes the implementation accurately. A detached snapshot is established at the policy boundary, rather than relying on downstream callers to remember a late clone.

Lower-level findings (P0-P2): None newly found. Prior F3 is CLOSED with independent runtime evidence.

F3 closure: packages/core/src/storage/disclosure-policy.ts:106-110 clones before authorizeEnvelope. packages/core/src/contracts/data.ts:639,648,666-668 carries the copied entry and approved envelope. packages/core/src/api/index.ts:2138-2140,2230-2231 retains them and passes selectedEntry to payment. Six real Lite + signed HTTP cases pass: control, legacy mutation and PDPP mutation at both payment refresh and guard-return/caller-resume. All six return 200, grantCalls=2, settled=1, and only authorized-original. No post-approval marker or injected $pdpp reaches the response.

The causal controls were independently rerun, in memory only: pinning just disclosure-policy.ts to eab7 produces 4 failed / 2 passed; adding only a late HTTP clone to that old guard produces 2 failed / 4 passed. The remaining failures are both caller-resume mutations. These are expected negative-control failures, not failures on reviewed HEAD. Normal runs explicitly unset PS455_ENVELOPE_RED, PS455_LATE_CLONE, PS455_RED, PS455_COMPUTE_RED and ASTRA_COMPARE_BASE.

An additional reviewer-authored probe uses the existing signed HTTP scaffold and actual Lite adapter, mutating the borrowed value before returning it to the guard. Control returns 200/original; a legacy change returns 200/legacy-at-acquisition; PDPP at acquisition returns 403 GRANT_REQUIRED, grantCalls=1, settled=0, without its marker. This confirms policy examines the acquired snapshot and does not grandfather a now-PDPP body based on stale metadata.

Prior finding closures and preservation:
- F1 configured/mounted composition: inspected closed. createApp uses pdppIsConfigured at app.ts:463-465; bootstrap shares its lazy configured signal with app and compute. Mounted authority wins in the resolver; explicit disabled without a mount stays false; missing state fails closed in publication policy. No new bootstrap or alternate-composition run in this review.
- F2 selected identity/payment: independently tested closed. The challenge offers version 1 while latest becomes 2. Paid delivery returns response-A with status 200, one settlement and latestVersion=2; the test also asserts posted accessRecord.version is 1. handleX402Cycle snapshots primitive identity before getGrant.
- R5 refusal before payment: independently tested closed for indexed pdppOrigin false and true. Both unsigned-payment challenge attempts and signed paid requests return 403, settled=0. This is preserved alongside the F3 snapshot fix.
- R1/R2 observed source union and conservative historical origin: inspected retained. Compute combines every loaded source; projection combines requested and joined inputs. hasPdppOrigin refuses historical lineage without well-formed explicit legacy origin. Historical false sidecars, including generation-bound ones, were independently exercised through real MCP read_scope/list_scope_blocks and refused.
- R3/R4 publication policy: inspected retained. Non-owner writes and builder compute use the shared configured publication decision, rather than treating app citations or absent exposure history as proof. Owner compute uses observed inputs. This round did not rerun the full publication matrix.
- Own-write projections/cache: inspected retained. Reader-aware classification is isolated by reader; projection inputs use the plain-grantee guard; compute explicitly uses plain grantee for builder registrations. No own-write exception was added to blocks. The full own-write/cache matrix is prior evidence, not newly rerun here.
- A fallback and representation: independently reran 18 actual Lite/MCP fallback ownership cases, 26 generation/representation/historical-classifier cases, and 25 MCP read-client cases: 69 passed. This includes redaction before paging/selection, TOC projection identity, stale layout/cursor refusal, multilingual one-byte paging and historical-classifier refusal. page.ts, mcp/read-client.ts and Lite storage.ts have empty endpoint diffs against ffecd; page.ts is also unchanged against e536. D manifestBinding preserves private redaction evidence while gating provenance on classifier 2.

Reviewer-run evidence, Node v22.23.3, Vitest v4.1.11:
- http-boundaries.log / .jsonl: 10 passed, 108 intentionally skipped; 12.36s. Six ownership, two identity, two prepayment-refusal cases.
- inherited-boundaries.log: 3 files, 69 passed; 9.17s.
- acquisition.log / .jsonl: 3 additional actual Lite + signed HTTP cases passed; 4.51s.
- pinned-eab7-negative.log / .jsonl: expected 4 failed / 2 passed; 7.58s.
- late-clone-negative.log / .jsonl: expected 2 failed / 4 passed; 4.32s.
- verification.json: exact HEAD, clean status, clean git diff --check, runtime version, provenance, preservation diffs, toggles, test summaries.

Raw observations include:
  payment-refresh/pdpp-mutation: status=200 grantCalls=2 settled=1 marker=authorized-original
  read-return/pdpp-mutation: status=200 grantCalls=2 settled=1 marker=authorized-original
  retained challenge: offeredVersion="1" latestVersion=2
  retained settlement: status=200 settled=1 returnedMarker=response-A latestVersion=2
  indexed origin false/true refusal: challenge=403 paidResponse=403 settled=0
  acquisition PDPP: status=403 grantCalls=1 settled=0 errorCode=GRANT_REQUIRED

82 positive checks ran on the exact current source. The maker's 399 focused + 3 boot, types, lint, format and hook results remain attributed evidence; they were not all repeated. The prior Astra 393 + 3 run is historical evidence, not a current rerun.

Would a different, simpler design make several findings disappear? No further redesign is required for these findings. The repair now supplies the missing structural ownership behind F2/F3: acquire and approve an owned body once, pair it with selected identity, and carry both through effects. A new response abstraction is not necessary to prove this bounded invariant.

Limits: bounded local/offline review; real signed HTTP/Lite/Node SQLite and MCP paths with local Gateway doubles, not live OAuth/Gateway/inference, OPFS/IndexedDB browser runtime, remote replicas, production load or all runtime compositions. No full suite, installs, source edits, Git mutations, new model tasks, browser, merge, release or PS459 work. Shared disclosure-policy overlap with B remains for its owner to integrate; this does not certify B or the final stack. High confidence in the repaired F3 boundary and tested preservation; no exhaustive correctness guarantee.

All test processes exited. Review-created cache and temporary fixtures were removed. Logs, configs, acquisition.test.ts, verification.json, this report and the empty patch are intentionally retained under evidence/astra-r8. PR #455 was linked to this review thread as required by the harness; no watcher was started.

```

## Broader old-eab dot report; concerns absent earlier briefs

```text
Review: vana-com/personal-server-ts #455, head eab7e8f8283bd06c7a5f02f78ae543d14799f295.

Architecture first
1. Goal: the byte-based disclosure guard, default-PDPP classification of non-owner publications, and OR-of-input-origins serve the actual anti-laundering goal, not merely a producer-label test. Finding F1 nevertheless leaves an alternate disclosure of source identity on ordinary, legacy-readable computed outputs.
2. Simplicity: provenance is braided into both user-visible answer data (sources/lineage) and server-only stamps ($lineage, producer). Projection replaces data to make a presentation view, while computation also uses that presentation view as its provenance input. F1 and F2 are consequences of this coupling, not insufficient file decomposition.
3. Invariant owners: authorizeLegacyRead is a coherent central disclosure decision; storage generation/digests bind block data and the classifier version prevents trusting obsolete classification. No additional confirmed defect in those inspected mechanisms. However, lineage completeness has no single end-to-end owner: compute publishes a second source list, redaction knows only reserved/mirrored fields, and projection discards stamps that compute later needs. F1/F2.
4. Explicit state/information flow: inputHasPdppOrigin preserves the row-or-bytes origin; projection explicitly accumulates origin across joined inputs; failed cited reads classify conservatively. No issue found in those specific origin paths. F2: lineage information is dropped across the same projection boundary, and the cycle checker interprets the absent statement as an empty edge set.
5. Feedback loops/real data: local scope scans are paged and the graph traversal has a visited set; inference retries have a finite configured schedule. The verified projected-source blind spot means the intended cross-replica feedback-loop guard does not cover all served inputs. Full resource/performance behavior was not executed.

A simpler shared design would address both findings: return a data value plus an internal provenance/dependency description from storage transforms. Projection should preserve/union dependency information separately from presentation bytes. Compute and the cycle checker consume that internal description; reader-specific disclosure renders only authorized provenance instead of relying on a blacklist of payload key spellings.

Ranked findings

F1 — P1: Computed derivative source identities bypass grantee lineage redaction.
Primary: packages/core/src/derivatives/compute.ts:600-604.
Related: packages/core/src/api/index.ts:1677-1715, 2260-2262.
Exact-head source:
https://github.com/vana-com/personal-server-ts/blob/eab7e8f8283bd06c7a5f02f78ae543d14799f295/packages/core/src/derivatives/compute.ts#L600-L604
https://github.com/vana-com/personal-server-ts/blob/eab7e8f8283bd06c7a5f02f78ae543d14799f295/packages/core/src/api/index.ts#L1677-L1715

Scenario: the owner computes coach.weekly from a legacy source such as bank.transactions, then gives another builder a read grant covering only coach.*. Legacy-only owner compute intentionally remains readable (derivative-origin.test.ts:246-257). The generated answer includes sources: [{ scope: "bank.transactions", version, collectedAt }]. GET applies redactEnvelopeForGrantee, which removes $writtenBy, $lineage and the mirrored lineage field, but leaves sources untouched. The recipient therefore learns the source scope and version/timestamp without a source grant. The scope plus known owner also reconstructs the data point ID that the redaction comment explicitly treats as sensitive. This defeats the grant-redacted lineage endpoint rather than leaking merely an arbitrary caller-provided field.
Fix: classify generated source metadata as internal provenance and redact or grant-filter it for non-owner reads. Preserve the full owner view. Do not globally strip arbitrary user-defined sources fields; identify server-computed records using trusted metadata. Apply the same rule wherever generated answers are served.
Missing regression: compute a real owner question over a legacy source, read its answer with a grant restricted to the derived scope, and assert the source scope/ID/version/timestamp do not appear, while the owner still sees them. Current source-origin integration controls establish readability but do not assert provenance redaction. routes/derivatives.test.ts:605-622 tests that a bare derived-scope reader cannot see sourceScopes on the status response, but does not cover the answer's parallel sources representation.

F2 — P2: Projection removes the lineage that the compute cycle guard must walk.
Primary: packages/core/src/storage/legacy-projection.ts:396-405.
Related: packages/core/src/derivatives/compute.ts:loadSource (readStoredLineage(envelope.data)), 568-578; assertNoLineageCycle also reads through deps.storage.readEnvelope.
Exact-head source:
https://github.com/vana-com/personal-server-ts/blob/eab7e8f8283bd06c7a5f02f78ae543d14799f295/packages/core/src/storage/legacy-projection.ts#L396-L405
https://github.com/vana-com/personal-server-ts/blob/eab7e8f8283bd06c7a5f02f78ae543d14799f295/packages/core/src/derivatives/compute.ts#L568-L578

Scenario: an owner-written/synced chatgpt.conversations version has valid projectable records and stored $lineage.sources containing the ID of coach.weekly (distinct namespaces satisfy the naming rule). An owner question computes coach.weekly from chatgpt.conversations using the served storage port. Projection replaces data with result.payload and intentionally drops server stamps. loadSource reads that projected payload, sees no $lineage, and passes an empty sourceLineage list to assertNoLineageCycle. No edge back to coach.weekly is visited, so inference and publication proceed instead of DERIVATIVE_CYCLE. The same blind spot exists for projected intermediates, and joined sibling dependencies are not supplied to the walker either. This defeats the existing cross-replica cycle protection and permits feedback/recomputation over its own derived output.
Fix: preserve internal lineage/dependencies through projection separately from public presentation data, including joined inputs, and make the guard traverse that information. At minimum read the requested version's stored lineage via the canonical stored view rather than treating the projection's absent stamp as a root; join dependencies also need accounting.
Missing regression: extend compute.test.ts:516-567 (currently only unprojected {v:1} source envelopes) with served withLegacyProjection storage, valid projectable conversation records carrying an edge back to the output, and a sibling/intermediate case. Assert failed DERIVATIVE_CYCLE, zero provider calls and no new output version.

Verification and limitations
- Static source tracing only. No tests, scripts, edits, workspace calls, model APIs, metered tools, publication, or deployment.
- All repository reads used GitHub fetch_file at the exact SHA, within the assignment allow-list.
- Substantive review concentrated on compute and its tests; lineage resolution/cited-origin; publication and legacy disclosure policy; projection and storage guard; provenance classifier/import boundary; API lineage/redaction/read flow; derivative-origin and route regression cases. Supporting inspection covered block digest/classification, MCP read paths, Node identity/index boundaries, download provenance propagation, attribution mirror checks and Lite wiring. Fetched supporting large files were inspected selectively, not exhaustively line-by-line.
- No PR diff was supplied, so findings describe behavior at this exact head; introduction in a particular commit is not established.
- Prior denied paths remain unread: packages/core/src/contracts/data.ts, packages/core/src/pdpp/tokens.ts, server jobs worker and worker tests. No denial retries or alternative access routes. Consequently publication-contract internals, token internals and job behavior are not certified.
- The already-closed mounted-PDPP configuration/payment-selection audit was not repeated. No claim of whole-PR approval.
- Fresh assignment check immediately before finish showed cancellation_requested=false, authority_revoked=false, compute_stopped=false and no owner notes.
```

## Complete preceding integrated brief and original D round responses

````text
Independent defensive review only of final repaired integrated PS#455. Return empty patch. No source edits, commits, pushes, deploy, dependency installs, fullsuite, browser or further model tasks. Actual maker gpt-6.1-sol high. State actual reviewer model if known; unknown cannot certify different-model acceptance.

Repository vana-com/personal-server-ts PR455 exact pushed HEAD eab7e8f8283bd06c7a5f02f78ae543d14799f295. A integrated e536bafc7d60717140c2b69aed58f7f4f3a9b4d0 then its single fallback fix ffecd0ab75780101ad9b1b0f9d462053409e11c8 cherry-picked. Review D delta using TWO ENDPOINT git diff ffecd0ab75780101ad9b1b0f9d462053409e11c8 HEAD (not triple-dot; ffecd was cherry-picked). D rebased repair e5123bfd3025db54a828010194a09e4baeb3c238 then F1/F2 repair3ccf958848e9a77d95f62d6da2f7909886a3057a then A pick eab7. Read allow-list exactly scope_paths. Preserve all A representation, classifier and B brand/budget contracts; B is separately owned and not integrated here. No PS459/merge/release authorization. Review goal/design before lines with inline rubric below. Bounded available offline tests permitted; no test pass claim if not run.

ORIGINAL D OUTCOME BRIEF: repair derivative provenance/publication and legacy read-back after legacy grant token bypass repair #452; stacked on generation safety A #457. On PDPP-enabled servers EVERY non-owner write (JSON/binary/write-session, with lineage or without) and builder-registered compute must be PDPP-origin. Owner compute combines observed provenance of ALL actual inputs including joined scopes. Explicit disabled (including Lite) preserves legacy; unknown state fails closed. Historical $lineage without well-formed legacy origin marker is PDPP until recomputed/rewritten. A builder citation is not evidence of all data consumed: remove old exposure/binding-history lookup rather than inferring that an app is clean from absent retained records. Own-write read-back is only exact stored unprojected HTTP version with server-stamped $writtenBy.builder equal to recovered reader signer; excludes compute, joined projections, MCP blocks and jobs. Non-owner policy must decide from generation-checked retained bytes BEFORE any payment effects. Current sidecars must not trust origin produced under obsolete classifier rules.

PRIOR ROUNDS AND RESPONSES (all remain acceptance requirements):
R1: owner compute lost provenance of observed joined inputs and unmarked historical derivatives. Response: collect observed origin over all compute reads/joins, mark derivative output, treat ambiguous historical lineage as PDPP.
R2: HTTP could rely on latest index false legacy while serving native joined PDPP input, old version, or unknown state. Response: authorize actual selected generation/envelope, classify lineage conservatively, guard projection inputs.
R3: app source citations do not prove consumption; V1/V2 and canonical view mismatch undermine cited-source lookup. Response: stop treating app citations as authority; classify non-owner publications by owner-configured policy.
R4: writer exposure/binding history cannot prove a clean app when store empty; builder compute was omitted. Response: removed old exposure lookup; one configured publication policy covers non-owner direct writes plus builder compute, with observed input union for owner compute. No app discovered performing this legacy own-write readback, but preserve exact contract.
R5 P1: pdpp.enabled=true but no retained declarations -> resource server unmounted -> legacy publication. Response R6: share configured signal with app and compute; do not use routes-mounted as sole enabled state. Explicit off vs unknown distinguished.
R5 P1: A-era generation-bound old manifest falsely says lineage output is legacy under older classifier. Response R6: manifest pdppClassifier=2, trustedPdppOrigin requires exact current classifier, otherwise classify checked stored bytes. Preserve classifier metadata in manifestBinding together with generation binding and A redaction.
R5 P2: own-write conversations projection joins a sibling never written by reader. Response R6: reader-specific exact unprojected classification distinct from plain grantee projection-input guard; reader caches isolated. Compute excluded.
R5 P2: unrelated legacy reader receives402, settles payment then403. Response R6: perform guarded read once before settlement and retain selected response; paid denial must never happen after effects. Missing authorized derivative still triggers compute demand.
R6 actual-boundary RED on original6614bbd6235d69d37191fd0c90b32654f3791a75:7failed/2controls passed: real createServer no-declarations publication/direct-write and compute variants leaked markers; generation-bound old manifests leaked through MCP read_scope and list_scope_blocks, unbound control refused; own-write joins returned other writer's marker; both indexed false/true cases settled once then403. Separate compute-only old signal returned200 vs403 while direct write refused. Alternate unknown createApp returned200 vs403. R6 GREEN11boundarycases; related254tests; types/lint/format. Gateway/inference mocked, real Node SQLite/filesystem/signed HTTP/MCP.

c57ec2d3f14a89138aa31d2ff37a96385e516f98 exact dot review: DON'T MERGE, actual model UNKNOWN, source-only, no tests performed. Full findings:
F1 P1 app.ts462-467 alternate createApp nullish chain chose config.pdpp.enabled=false ahead of mounted deps.pdpp, causing live PDPP composition to publish legacy. Root resolver was correct but duplicated semantics. Required actual mounted+configfalse createApp test and one state owner.
F2 P2 core/api/index.ts2115-2134/2224-2230 and handleX402Cycle830/844-855: retained response A selected before payment, then helper awaited gateway.getGrant and reselected latest with original absent at/fileId, so concurrent B publication charged/attested B while serving A, or rejected honest A proof. Required immutable selected response identity passed to payment and no reselection. Original review recognized R5 static closures but excluded A-owned mutable block issue. It did NOT certify whole stack or different-model independence.
R7 actual RED on rebased e512:3failures: mounted PDPP+configfalse non-owner signed write201 then unrelated read200 leaked marker; publication B in second getGrant produced challenge version2 rather than retained1; honest paid A proof got402/settled0 instead of200/A.
R7 repair3ccf: pdppIsConfigured is shared resolver for createApp and createServer; mounted authority wins, unknown remains failclosed. ReadDataContractResult carries cloned selectedEntry captured before await; HTTP uses result.entry for served file identity and passes selectedEntry to X402; helper snapshots primitive identity before grant await, retains fallback lookup only for callers without retained HTTP response. Updated two current-manifest MCP mocks with classifier2; historical fallback mocks remain historical. R7 GREEN3/3, boot3/3, final integrated checks below.

A INTEGRATION AND PRIOR FINDINGS: A formerly verified raw full block then sliced without representation policy; now shared pager verifies FULL block then representation:'grantee' redacts before slicing, private result.redaction evidence retained, returned manifest strips provenance/private evidence but preserves representationId. Identity pins ordered raw layout+policy+view separately from envelope, TOC uses blockRepresentationMetadata including cursorView; MCP rejects cursor missing representation. Canonical JSON bytes+UTF8 pager avoids split characters (tiny budgets may return one full codepoint). Cached nested block mutation during async payment after digest check previously leaked shared refs; A pager now clones manifest and loaded block before verify/representation. D conflict resolutions preserve all this, manifestBinding preserves classifier and redaction; A page.ts used unchanged from e536. Inherited block-generation-window26tests kept both suites; two legacy fixtures added required writtenAt metadata to stay well-formed legacy (all original assertions retained).
A final fallback finding on e536: readCheckedBlocks object-envelope fallback retained storage-shared object through async builder, mutation after policy/digest decision could change returned bytes. Parent actual RED6fail/12controls on real Lite+MCP pages/selection/manifest. Original e536 Astra saved useful RED then provider review request failed cybersecurity-content flag; NO acceptance, no retry/rephrase of that denied old request. This distinct review evaluates NEW repaired integrated head with full truthful context. Exact parent fix ffecd0ab adds structuredClone at object-envelope acquisition BEFORE checks/build (byte JSON.parse already owned),18GREEN. D cherry-picked exact commit, no independent patch. Its old-sidecar tests remove redaction explicitly even with current classifier, so fallback is still exercised. Parent final A dot pending; no combined acceptance.

EXACT FINAL INTEGRATED EVIDENCE eab7:15files393tests pass (Lite fallback ownership18, inherited block-generation26, core MCP read-client/session, block build, Lite storage, signed HTTP data/derivatives/lineage, server derivative origin, compute, contracts, publication-origin, pdpp-origin, configured). Additional actual createServer boot3pass/23skipped. Core/server tsc -b, all changed TS eslint/prettier, git diff --check pass. Node22.23.3 with existing local binaries, no install/fullsuite. New fallback paths real Lite+MCP; new payment races real signed HTTP plus local Gateway doubles. Live OAuth/inference/remote replica not checked. B's independent brand/budget/stream work not yet integrated. Maker test results attributed, review must state what reviewer reran. Current worktree clean, exact head pushed, no further mutation while reviewed.

Look for missing boundaries, bypasses, unsound historical classifier trust, own-write projection/caching, config composition divergence, retained identity/payment mismatch and async ownership. Verify latest A fallback and shared pager still honor D classifier/reader guards and B public budget/brand contracts. Distinguish existing A/B ownership from D regressions and concrete blockers from speculative redesign. Repeated findings need single owning invariant, not another line patch. Terse P0-P2 with exact scenario/file:line, reproduced vs inspected, check output/limits, review model provenance, empty patch.

# Review rubric: design and architecture before lines

Paste this into every review brief, whether it goes to the dot, Opus, Sonnet or Sol. Use the following inline rubric, with Hickey's Simple Made Easy at the center. Meadows' leverage points add one idea and no more: a change higher in the system outweighs any amount of tuning lower down, so review the design before the lines.

Why it matters: line-level review kept circling defects that were really design defects. Examples:
- data-connectors #509 and dc#519 each took three patch rounds. dc#519 was fixed only when `InventoryEvidence` became the single owner of completeness.
- The replication backoff braided "waiting" with "error".
- The 8a test check couldn't see the fields that mattered.

## Questions, answered in order

1. **Goal.** Does the design serve the real goal, or a proxy such as passing tests or green CI? Is the problem framed correctly?
2. **Decomplecting (Hickey).** What is braided that should be independent? Check each pair:
   - state and value;
   - time and identity;
   - policy and mechanism;
   - domain logic and I/O;
   - parsing and execution;
   - representation and meaning;
   - waiting and error;
   - unrelated reasons for change.

   Simple (un-braided) is objective; easy (familiar) is taste, so optimize for simple. Splitting code into more files is not decomplecting (canon R5: relocation is not abstraction).
3. **Invariant ownership and information hiding.** Which single component owns each invariant: completeness, ordering, identity, authorization, durability, visibility? Do two places decide the same thing? Does each module hide one decision that's likely to change (Parnas)? Is the module deep: a small interface hiding real work (Ousterhout)?
4. **Explicit state and effects; information flow.** Are time, mutation, I/O, retries and caching visible and controlled? Does each decision see the state it needs? Is anything hidden, dropped, or reported as success when it's only partial? This covers logs that hide causes, diagnostics that drop reasons, and oracles blind to the fields that matter.
5. **Feedback loops.** Can a retry, backoff, poll, cursor or reconciliation stall, starve or run away? Does it converge? Is it observable?
6. **Fit to real data.** Real sizes and shapes: whole-object copies, memory, the shapes real services actually return. Fit the code to the data, not to a pretty abstraction.
7. **Local reasoning and honest names.** Can each unit be understood from its name, signature and tests? Is each name a true invariant?
8. **Then** parameters, buffers, and line-level correctness and tests. Behavior preservation is a gate (canon R2). Prove the diff; don't narrate it (R4).

## Required output

```
Verdict: MERGE | MERGE-WITH-NITS | DON'T MERGE
1 goal: <finding, or "no issue: why">
2 complected concerns: <...>
3 invariant owners (list each -> owner): <...>
4 state/effects/information flow: <...>
5 feedback loops: <...>
6 fit to real data: <...>
Lower-level findings (P0-P2, file:line): <...>
Would a different, simpler design make several of these findings disappear? <yes/no + which>
```

When the same kind of finding repeats across rounds, name the owning component and recommend the structural fix, not another patch (memory: `feedback-system-design-before-patch-rounds`).

````

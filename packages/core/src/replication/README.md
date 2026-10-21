# PDPP replica operation profile v1

This internal Vana profile defines immutable replication evidence and derives a
current view from the complete retained operation set. It does not define
transport, storage, cryptography, or authorization-state replication.

## Observation order

Source observations are immutable facts. A connector may declare one comparable
source-version rule per stream: ordered integer, ordered RFC3339, or equality
only. A comparable higher version dominates a lower version only inside the
same domain and incarnation. Equality-only versions detect contradictory
payloads but do not order different values. An undeclared version is rejected.

After version dominance, known causal order wins: a later observation by the
same writer, or an observation whose batch frontier includes the earlier HLC.
Remaining candidates use `min(observedAt, finalizedAt(batch))`; before finality,
the observation time is uncapped. HLC logical value, writer id, and operation id
form the deterministic final tie-break. The operation counter never selects the
current value.

Differing candidates within the five-minute policy window are `unsettled` and
request a source re-observation. A non-reobservable stream promotes that
disagreement to owner review. Equal comparable source versions with different
content and conflicting concurrent owner resolutions also need owner review.
Append-only content conflicts remain quarantined. An unsettled disagreement
involving a source deletion is hidden from apps.

## Owner removals and deletion erasure

Source deletions are ordinary observations and may be superseded by later
source observations. Owner hide and delete are separate remove-wins decisions.
Only an explicit restore that names a removal operation clears that removal;
concurrent removals remain active. Source observations never clear owner
removals. An owner resolution names the alternatives it settles and carries the
value it selects; a later scrape cannot inherit that resolution unless its
frontier shows it received the resolution.

`OWNER_DELETE_GRACE_PERIOD_MS` is the single delete-retention contract constant
(30 days by default). The period starts at the delete batch's finality time. Once
it expires, the derived record retains only a suppression marker with its key,
operation ids, content hashes, observation times, and finality times. A later
observation cannot restore erased payload. A restore after erasure waits for a
new source observation.

## Account identity

Every operation carries `upstreamAccount` as issuer plus stable subject. It must
come from connector-declared identity evidence; login names and email addresses
are not stable keys. A connection registration binds one principal. Mismatched
operations are quarantined and never enter app views. The owner may keep the
held observations as a separate connection by an explicit choice.

## Operation and view contract

Every operation has a persisted HLC revision and writer id. Every observation
has `emittedAt` (source observation time), a content hash, and its batch id.
Every operation carries the writer frontier it had received. `MergeContext`
supplies finalized batch times and the local retention clock. `now` affects only
retention; it does not select current values.

The planner retains losing evidence and recomputes the view from operations. Its
records expose current value, candidates, state, owner control, refresh request,
flags, and payload retention. `appView` is the only app projection: it returns
only an upsert that is not quarantined, hidden, deleted, erased, or an unsettled
delete disagreement. Apps do not receive candidates or owner history.

Connection deletion still dominates all evidence for that connection. A
complete-scan deletion requires connector declaration and a confirming scan;
absence from a partial scan is no operation. The receiver must preserve the
complete operation set, including lifecycle facts, conflicts, pending records,
quarantine evidence, and suppression markers.

## Verification vectors

`merge-plan.test.ts` covers the N01–N29 policy cases. The three-device suite
ports fixtures 01–56, including the explicit fixture 18 reversal and causal
resolution timelines. Both suites cover source-version order, clock capping,
removal/restore, account quarantine, app projection, and complete-scan handling.
Each logical vector is replayed across delivery permutations so arrival order
does not change the result. `revision.test.ts` covers HLC creation and the
receive guard.
`envelope.test.ts` covers canonical encoding, exact declaration and owner binding,
the stable upstream principal, HLC shape, and lifecycle operation roundtrips.

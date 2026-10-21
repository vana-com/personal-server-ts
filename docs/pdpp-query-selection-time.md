# Query, selection and temporal conformance

This change fixes record disclosure and pagination defects against the current
contract. Candidate-only selection and time rules require an explicit opt-in.
The deployment defaults to the current profile. This change does not claim full
candidate conformance.

## Contract boundary

Set `pdpp.protocolProfile` to `candidate-0.1.0` to advertise and accept the
candidate authorization detail type. Its default, `current`, neither advertises
nor accepts that type. This is the single deployment switch for all B rules.
Within an enabled deployment, each request must still choose that type.

The default authorization detail type and the private v0.2 proposal keep their
selection defaults. The internal compatibility profile
`https://pdpp.dev/data-access/candidate-0.1.0` issues grants with version
`0.1.0-candidate`. This URI is an implementation profile, not a published PDPP
identifier or a statement that the candidate is locked.

The comparison uses Core main `541ebc38f0794d5c7c2d09198a978471dd61733e`
and the unlocked candidate `cba5d6db07bfafc52ae0a7e36c3d49bfb257657b`.
The server baseline is `0b5eac036a33cb714cdd6d3a71abddd98e609f2d`.

| Finding                                               | Class             | Result                                                                                                                                                                                                                                                   |
| ----------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fields outside a frozen grant                         | A, current defect | Required fields are resolved at issuance. Reads never add fields absent from the grant, including after a declaration changes. Sparse reads retain the required floor only inside the grant.                                                             |
| Malformed limits                                      | A                 | Whole-string positive safe integers; absent defaults to 25. Values above 100 retain the existing clamp and warning. Supplied empty, fractional, suffixed and unsafe values fail.                                                                         |
| Moving list rows and tied identities                  | A                 | Traverse historical versions at the first page's horizon, ordered by emitted time, record key, then instance. Later edits and inserts cannot move that traversal; encountering a subsequently erased visible record expires it with an explicit restart. |
| Offset/precision comparison and invalid stored values | A                 | Compare instants rather than strings. Invalid or missing values cannot authorize list, detail, sync data or blob disclosure.                                                                                                                             |
| Explicit selector and optional opt-in                 | B, candidate only | Every named, wildcard or preset stream requires fields or view. The field wildcard must stand alone. Omitted necessity means optional; optional streams require affirmative owner selection.                                                             |
| Typed time and strict AS bounds                       | B                 | Freeze date/date-time type from the retained schema. Reject invalid calendars, wrong types, empty or reversed ranges and invalid narrowing. Compare all fractional digits, offsets, lowercase t/z, unknown local offset and inserted leap seconds.       |
| Time-filtered removals                                | B                 | Compare visibility at both sync horizons. Emit a minimal removal for previously visible records that are deleted or leave the time window. Never use deletion payloads to authorize a removal. First sync has no removals.                               |

Current Core already freezes fields and forbids widening from a current
declaration (sections 6–8). Its schema-required floor belongs in the resolved
grant. Existing tests that expected read-time disclosure outside that grant
were corrected. This changes malformed or stale grants that previously depended
on the wider response; valid grants issued by the AS already include their floor.

Candidate clauses are separate: selection defaults, temporal declaration
eligibility, frozen time type, exact RFC3339 semantics, and h0/h1 removals.
Current untyped grants remain readable without a type migration. Offset-less
legacy authorization bounds use UTC consistently across host time zones; stored
record values remain strict. Current and
private-v0.2 tombstone wire behavior stays unchanged.

## Invariant owners

- `resolveReadScope` owns read-time field selection for list, detail, sync,
  metadata and client blob authorization. The HTTP routes do not add fields.
- `expandedRequestFields` owns request selector expansion;
  `streamIsOmitted` owns optional consent inclusion and is shared with inventory
  and fan-in checks.
- `pdpp/time.ts` owns the time type, strict parser and exact comparator. AS
  validation and narrowing, RS enforcement and ingest timestamp validation use it.
- `parseRecordQuery` owns query names, multiplicity, limit and order parsing.
- `listSnapshotPage` owns visible list pagination and cursor construction. Both
  stores supply ordered historical rows; HTTP never rebuilds a list cursor.
  `compareRecordIdentity` owns locale-independent identity ordering for list and sync.
- `selectSyncChange` owns comparison of authorized historical projections.
  Candidate time/resource eligibility runs before sync pagination in both stores.
  Eligibility uses the grant projection; sparse response fields do not suppress changes.

Legacy list cursors without a horizon or complete identity return the existing
`410 cursor_expired` restart signal. Their original traversal cannot be recovered
safely after mutation. New cursors carry both facts. Erasure of an unread visible record also expires
the listing; no profile returns its historical data after deletion.

SQLite list and sync use one `snapshotRows` primitive, with explicit indexes for
ordered traversal and latest-version lookup. Schema v12 adds those indexes.
SQLite iterates the ordered snapshot until one extra visible row establishes
continuation; it does not copy the entire list into JavaScript memory. The memory
backend reconstructs its snapshot from retained history and keeps one bounded
cache of raw row references to avoid sorting again on every page.

## Client compatibility checked read-only

| Client           | Source checked                                                                                                      | Candidate adoption                                                                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Account          | unity-surfaces `dd18fd5b`, `apps/account/src/lib/pdpp-consent/review-model.ts` and HTTP transport                   | Required: its current model defaults streams on and sends declined streams. Add affirmative selections, typed time presentation and profile forwarding before opting in. |
| Unity web        | Same revision, `apps/web/src/features/personal-server/web-personal-server-session.ts` and `local-ps-pdpp-ingest.ts` | Inspected paths use owner-data/legacy scope access; no direct candidate requester established.                                                                           |
| Unity mobile     | Same revision, `apps/mobile/src/features/personal-server/owner-data-access.ts` and `mobile-owner-data-client.ts`    | Inspected paths use signed owner-data access; candidate consent adoption is unverified.                                                                                  |
| OpenPet          | open-pet-next `a803c6b41144d5cd2b34f8c6fd04b4f436c5de13`, `src/lib/vana/read.ts`                                    | Inspected path signs legacy `/v1/data` reads. No direct candidate selection consumer established.                                                                        |
| Vana MCP         | Server baseline, `packages/core/src/mcp/read-client.ts`                                                             | Inspected path uses Web3Signed legacy reads. No direct candidate selection consumer established.                                                                         |
| Generic PDPP MCP | data-connect `a707c465`, `reference-implementation/vendor/mcp-server/src/tools.ts` and `src/credentials.ts`         | Reads scoped bearer credentials and forwards cursors. Candidate grants must be acquired upstream.                                                                        |
| Context Gateway  | `72ad1e67`, `apps/api/src/lib/pdpp-authorization-client.ts`                                                         | Required: explicit URI allowlist and selection model currently support only current/private-v0.2 details.                                                                |

These are source checks, not deployed-client or mobile acceptance evidence.

Current behavior changes also include rejecting duplicate query parameters with
400, excluding offset-less stored timestamps, expiring incomplete legacy list
cursors with 410, and using consistent code-point sync ordering across backends.
Clients must restart an expired traversal.

## Evidence and limits

Regression tests first reproduced malformed limits, list duplication/omission and
instance ties, fields added outside grants, optional streams included without a
choice, incorrect temporal comparison, typed-bound validation and time-window
removals. Tests exercise both memory and SQLite stores plus HTTP authorize,
review, approval, list, detail, sync and blob GET/HEAD paths.

The candidate's complete opaque cursor/context-binding and sync privacy redesign
is outside this slice. This profile must remain opt-in until those requirements
and client migrations are accepted. Existing cursors are not authorization
credentials. No live Account, OpenPet, mobile or MCP journey was executed here.

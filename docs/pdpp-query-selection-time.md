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
Frozen required fields, record `instance_id` and the sync deletion exception
follow the later candidate head `9638aa99a4ceb24c399d8bd4b8cf8670e26cf894`
(spec-core "Response records", StreamGrant `required_fields`, and the
paginated `changes_since` deletion rule).
The server baseline is `0b5eac036a33cb714cdd6d3a71abddd98e609f2d`.

| Finding                                               | Class             | Result                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fields outside a frozen grant                         | A, current defect | Required fields are resolved at issuance. Reads never add fields absent from the grant, including after a declaration changes. Sparse reads retain the required floor only inside the grant.                                                                            |
| Malformed limits                                      | A                 | Whole-string positive safe integers; absent defaults to 25. Values above 100 retain the existing clamp and warning. Supplied empty, fractional, suffixed and unsafe values fail.                                                                                        |
| Moving list rows and tied identities                  | A                 | Traverse historical versions at the first page's horizon, ordered by emitted instant, record key, then instance. Later edits and inserts cannot move that traversal. A record erased after the horizon is withheld from later pages; the rest of the listing continues. |
| Offset/precision comparison and invalid stored values | A                 | Compare instants rather than strings, in authorization and in list order and `last_updated`. Invalid or missing values cannot authorize list, detail, sync data or blob disclosure. One legacy-bound reading serves AS validation, narrowing and RS enforcement.        |
| Explicit selector and optional opt-in                 | B, candidate only | Every named, wildcard or preset stream requires fields or view. The field wildcard must stand alone. Omitted necessity means optional; optional streams require affirmative owner selection.                                                                            |
| Typed time and strict AS bounds                       | B                 | Freeze date/date-time type from the retained schema. Reject invalid calendars, wrong types, empty or reversed ranges and invalid narrowing. Compare all fractional digits, offsets, lowercase t/z, unknown local offset and inserted leap seconds.                      |
| Time-filtered removals                                | B                 | Compare visibility at both sync horizons. Emit a minimal removal for previously visible records that are deleted or leave the time window. Never use deletion payloads to authorize a removal. First sync has no removals.                                              |
| Record deleted after a sync session's first page      | B                 | A candidate page withholds it and continues; the next session returns it as of its own horizon (`docs/pdpp-sync-session.md`). The current contract serves every page at the session horizon.                                                                            |
| Initial review of an all-optional request             | B                 | The review shows every optional stream unselected. Approval refuses an empty grant until the owner selects a stream.                                                                                                                                                    |
| Frozen required fields and record identity            | B                 | Candidate grants carry `required_fields`, and the sparse-read floor comes from it, never from a later declaration. Candidate records and tombstones carry `instance_id`.                                                                                                |

Current Core already freezes fields and forbids widening from a current
declaration (sections 6–8). Its schema-required floor belongs in the resolved
grant. Existing tests that expected read-time disclosure outside that grant
were corrected. This changes malformed or stale grants that previously depended
on the wider response; valid grants issued by the AS already include their floor.

Candidate clauses are separate: selection defaults, temporal declaration
eligibility, frozen time type, exact RFC3339 semantics, h0/h1 removals, frozen
required fields and record `instance_id`. Current untyped grants remain
readable without a type migration. `legacyTimeBound` reads offset-less legacy
authorization bounds in UTC on every host, for AS validation, minimum checks,
narrowing and RS enforcement alike; stored record values remain strict. Current
and private-v0.2 tombstone and record wire shapes stay unchanged.

## Invariant owners

- `resolveReadScope` owns read-time field selection for list, detail, sync,
  metadata and client blob authorization. The HTTP routes do not add fields.
- `expandedRequestFields` owns request selector expansion;
  `streamIsOmitted` owns optional consent inclusion and is shared with inventory
  and fan-in checks.
- `pdpp/time.ts` owns the time type, strict parser, exact comparator, the
  legacy-bound reading (`legacyTimeBound`) and the instant sort key
  (`timeSortKey`). AS validation and narrowing, RS enforcement, ingest
  timestamp validation and both stores' list order use it.
- `parseRecordQuery` owns query names, multiplicity, limit and order parsing.
- `listSnapshotPage` owns visible list pagination and cursor construction. Both
  stores supply ordered historical rows; HTTP never rebuilds a list cursor.
  `compareRecordIdentity` owns locale-independent identity ordering for list and sync.
- The sync session owner (`docs/pdpp-sync-session.md`) compares authorized
  historical projections and paginates the authorized result. Eligibility uses
  the grant projection; sparse response fields do not suppress changes.

Legacy list cursors without a horizon or complete identity return the existing
`410 cursor_expired` restart signal. Their original traversal cannot be recovered
safely after mutation. New cursors carry both facts. They also carry the list
order they belong to (`orderKey: "instant"`). A cursor minted under the earlier
timestamp-text order names a different position under instant order, so it
also returns `410` rather than skip or repeat rows. The sync owner
(`docs/pdpp-sync-session.md`) issues every page cursor as a handle and expires a readable
one, whose offset counted the earlier locale-dependent key order. Completed
checkpoints carry no position and stay valid. A record erased after the
horizon, including one erased and reinserted, is withheld from later pages; no
profile returns its historical data after deletion. A list is not a sync
session, so withholding one record loses nothing a later read relied on.
Candidate spec-core withholds such a record from a sync page too; the sync
owner also carries it into the next session (see the deletion row above).

SQLite lists use the `snapshotRows` primitive, with explicit indexes for
ordered traversal and latest-version lookup; sync reads its own identity-ordered
window (`docs/pdpp-sync-session.md`). Schema v12 adds those indexes. Schema v13
adds `emitted_key` (`timeSortKey(emitted_at)`) to live and history rows,
backfills it, and orders list traversal and `last_updated` by it. Its live
summary index also carries `emitted_at`, so `last_updated` stays an
index-only read.
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
cursors with 410, ordering lists by emitted instant, and using consistent
code-point sync ordering across backends.
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

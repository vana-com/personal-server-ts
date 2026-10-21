# PDPP sync session owner

`createPdppSyncSessionService` (`packages/core/src/storage/pdpp-records/sync-session.ts`)
is the one owner of `changes_since` sessions. It decides which change a
session discloses, paginates the authorized result, and issues and checks
every page cursor and checkpoint. Stores supply only raw history through
`readSyncWindow`. The HTTP route states the grant and maps the page.

This builds on the query, selection and temporal slice
(`docs/pdpp-query-selection-time.md`). It uses that slice's
`snapshotRows`, `compareRecordIdentity`, `resolveReadScope` and time
comparator; it does not copy them.

## Invariant owners

| Invariant                                             | Owner                                                                                                |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Which change a session discloses                      | `disclose` in the session service. Profiles differ only in policy.                                   |
| Page boundaries and `has_more`                        | The session service. It counts only disclosed items and seeks by the last disclosed record identity. |
| Token format, role, binding and integrity             | The session service: readable tokens for the current profile, sealed tokens for the candidate.       |
| History at a horizon, reset fence, horizon validation | Each store's `readSyncWindow`, inside one read transaction.                                          |
| Sealing key and epoch                                 | Each store's `syncTokenScope`. SQLite keeps both in `pdpp_store_metadata` (schema v13).              |
| Stream discovery for a client token                   | The grant. `GET /v1/streams` lists every stream the grant names.                                     |

Stores no longer mint cursors, bump the write clock for a sync read, or
compare projections. The route no longer filters a page after pagination.

## Classification

The current profile serves every current and private-v0.2 grant and every
owner token. The candidate profile serves `0.1.0-candidate` grants, which the
AS issues only when `pdpp.protocolProfile` is `candidate-0.1.0`.

| Finding (design test)                                              | Class | Result                                                                                                                                                         |
| ------------------------------------------------------------------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hidden rows consume pages or add empty pages (04–08)               | A     | A page holds only disclosed items. A session with only hidden changes is one empty terminal page.                                                              |
| Empty or tombstone-only granted stream is not discoverable (23–24) | A     | A client token lists every granted stream, with `record_count: 0` when it holds no visible record.                                                             |
| Record deleted after page 1 is served on a later page              | A     | Not served. The next session reports the deletion.                                                                                                             |
| Checkpoint horizon ahead of the store clock (18, current part)     | A     | `410 cursor_expired`.                                                                                                                                          |
| A sync read advances the write clock                               | A     | It no longer does. A read-only SQLite store can now serve sync.                                                                                                |
| Hidden-field or time-window visibility transitions (01–03)         | B     | Visibility at both horizons; removals carry no payload. The query slice built this; it now lives in the owner.                                                 |
| Readable tokens and clock oracle (09, 10, 25)                      | B     | AES-256-GCM sealed tokens with fresh randomness, fixed-width horizons and padded length.                                                                       |
| Token reuse across grant, instances, resources, fields (11–16)     | B     | `400 invalid_cursor`. The binding digest covers the grant id, subject, client, source, stream grant, response fields, instances, eligibility fields and order. |
| Altered tokens, stream rebinding (17–19)                           | B     | `400 invalid_cursor`. A token sealed by another or a rebuilt store is `410 cursor_expired`.                                                                    |
| Baseline conflict and role confusion (20–22)                       | B     | A page cursor is bound to its session's `changes_since` input; page cursors and checkpoints are distinct roles.                                                |
| Order (26)                                                         | B     | Candidate sessions order by key in the `order` direction (default `desc`) and bind it. Current sessions keep ascending key order and ignore `order`.           |
| Empty `changes_since`                                              | B     | Candidate: `400 invalid_cursor`; start with `beginning`. Current: still begins a session.                                                                      |

The B rules change the wire for clients that store checkpoints. Applying them
to the current profile would invalidate every stored checkpoint, which is a
visible change for live clients, so they ship only with the candidate bundle.
The current profile therefore keeps its known token risks: a client can still
read, alter or reuse its own current-profile tokens.

## Compatibility

- Current-profile checkpoints keep their format, and checkpoints issued before
  this change stay valid.
- A current-profile page cursor issued before this change, in the middle of a
  session, returns `410 cursor_expired` if it is past page 1. It counted hidden
  rows, so it cannot be resumed against the authorized result. The client
  restarts that session.
- Two quiet current-profile sessions in a row can return the same checkpoint,
  because a sync read no longer advances the clock.
- Changing `order` between candidate sessions invalidates the checkpoint, as
  the candidate binds `order` into the query context.
- Schema v13 adds a column. As with earlier migrations, an older build refuses
  to open the upgraded database.
- Error precedence is unchanged: a deleted connection answers
  `404 instance_unavailable` before any `410`.

## Evidence and limits

`packages/server/src/routes/pdpp-sync-conformance.test.ts` drives the public
HTTP surface on both stores. All of its class A and B cases failed against
#441's head, except 01–08 under the candidate profile, which #441 had already
fixed. Controls cover fixed horizons, the deletion exception, a fresh access
token for the same grant, a changed `limit`, retries, and a SQLite restart
followed by a reset.

- No store prunes history yet, so `410` for pruned history is covered only by
  the reset fence, rebuilt stores and horizons ahead of the clock.
- SQLite still reads every key changed in the window on each page, as before.
  Lookups of the earlier version and of later deletions are now lazy and stop
  at the page boundary.
- The sealing key does not rotate. Rebuilding the records database expires
  every outstanding token.
- Transport timing is outside this contract.

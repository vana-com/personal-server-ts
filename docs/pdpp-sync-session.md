# PDPP sync session owner

`createPdppSyncSessionService` (`packages/core/src/storage/pdpp-records/sync-session.ts`)
is the one owner of `changes_since` sessions. It decides which change a
session discloses, paginates the authorized result, bounds the work one page
may do, and issues and checks every page cursor and checkpoint. Stores supply only raw history through
`readSyncWindow`. The HTTP route states the grant and maps the page.

This builds on the query, selection and temporal slice
(`docs/pdpp-query-selection-time.md`). It uses that slice's
`compareRecordIdentity`, `resolveReadScope` and time parser; it does not copy
them.

## Invariant owners

| Invariant                                             | Owner                                                                                                                                          |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Which change a session discloses                      | `disclose` in the session service. Profiles differ only in policy.                                                                             |
| Page boundaries, `has_more` and work per page         | The session service. It counts only disclosed items, and examines at most `maxExaminedPerPage` changes (default 10,000) per page.              |
| Token format, role, binding and integrity             | The session service: sealed page cursors in both profiles, readable checkpoints for the current profile, sealed checkpoints for the candidate. |
| History at a horizon, reset fence, horizon validation | Each store's `readSyncWindow`, inside one read transaction. Its window yields changes lazily in identity order from a seek boundary.           |
| One record per id on the wire                         | `assertOnlyHolder` in the session service and `listSnapshotPage` for lists; the detail route for single reads.                                 |
| Order of emitted time                                 | `timeSortKey` in `pdpp/time.ts`, from the same parser as `compareTime`. SQLite stores it as `emitted_key`.                                     |
| Sealing key and epoch                                 | Each store's `syncTokenScope`. SQLite keeps both in `pdpp_store_metadata` (schema v14).                                                        |
| Stream discovery for a client token                   | The grant. `GET /v1/streams` lists every stream the grant names.                                                                               |

Stores no longer mint cursors, bump the write clock for a sync read, or
compare projections. The route no longer filters a page after pagination.

## Classification

The current profile serves every current and private-v0.2 grant and every
owner token. The candidate profile serves `0.1.0-candidate` grants, which the
AS issues only when `pdpp.protocolProfile` is `candidate-0.1.0`.

| Finding (design test)                                              | Class | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Hidden rows consume pages or add empty pages (04–08)               | A     | A page holds only disclosed items. A session with only hidden changes is one empty terminal page.                                                                                                                                                                                                                                                                                                                                                                  |
| Empty or tombstone-only granted stream is not discoverable (23–24) | A     | A client token lists every granted stream, with `record_count: 0` when it holds no visible record.                                                                                                                                                                                                                                                                                                                                                                 |
| Checkpoint horizon ahead of the store clock (18, current part)     | A     | `410 cursor_expired`.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| A sync read advances the write clock                               | A     | It no longer does.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Same key from two read instances under one id (review F1)          | A     | Client reads refuse with `403 disclosure_unavailable` when another read instance holds a grant-visible record under the key. A same-key record the grant hides is no conflict and stays hidden. A detail read no longer returns 404 when the first instance's copy is hidden and another's is visible. Candidate list and sync pages serve both records, because each carries its `instance_id`; a detail read by key alone still refuses.                         |
| Large memory ingest commits current state without history (F2)     | A     | The memory store publishes rows, history and its clock only after every envelope is decided, without argument spreading.                                                                                                                                                                                                                                                                                                                                           |
| Stream metadata copies schema keywords (F3)                        | A     | The client schema is built from granted properties only; a granted property that uses `$ref` becomes `{}`.                                                                                                                                                                                                                                                                                                                                                         |
| Lists and recency order timestamp text (F4)                        | A     | Lists, seeks and `last_updated` order by instant. Invalid timestamps sort after valid ones, by text.                                                                                                                                                                                                                                                                                                                                                               |
| Successful sync pages skip the access feed (F5)                    | A     | Each successful sync page records one `completed` read.                                                                                                                                                                                                                                                                                                                                                                                                            |
| Unbounded work per sync page (F6)                                  | A     | Each page examines at most the budget, and an incremental window enumerates only keys written in it.                                                                                                                                                                                                                                                                                                                                                               |
| Hidden-field or time-window visibility transitions (01–03)         | B     | Visibility at both horizons; removals carry no payload. The query slice built this; it now lives in the owner.                                                                                                                                                                                                                                                                                                                                                     |
| Readable tokens and clock oracle (09, 10, 25)                      | B     | AES-256-GCM sealed tokens with fresh randomness, fixed-width horizons and padded length.                                                                                                                                                                                                                                                                                                                                                                           |
| Token reuse across grant, instances, resources, fields (11–16)     | B     | `400 invalid_cursor`. The binding digest covers the grant id, subject, client, source, stream grant, response fields, instances, eligibility fields and order.                                                                                                                                                                                                                                                                                                     |
| Altered tokens, stream rebinding (17–19)                           | B     | `400 invalid_cursor`. A token sealed by another or a rebuilt store is `410 cursor_expired`.                                                                                                                                                                                                                                                                                                                                                                        |
| Baseline conflict and role confusion (20–22)                       | B     | A page cursor is bound to its session's `changes_since` input; page cursors and checkpoints are distinct roles.                                                                                                                                                                                                                                                                                                                                                    |
| Record deleted after page 1                                        | B     | Candidate: the page withholds it and the session continues. Its identity rides in the sealed page cursors and checkpoint, and the next session returns it as of that session's horizon even if its projection is unchanged, as the candidate requires for a reference redacted on a later page. Comparing projections alone would lose a record deleted and recreated unchanged. Current: the page stays at the session horizon, as the current contract requires. |
| Order (26)                                                         | B     | Candidate sessions order by key in the `order` direction (default `desc`) and bind it. Current sessions keep ascending key order and ignore `order`.                                                                                                                                                                                                                                                                                                               |
| Empty `changes_since`                                              | B     | Candidate: `400 invalid_cursor`; start with `beginning`. Current: still begins a session.                                                                                                                                                                                                                                                                                                                                                                          |

The B rules change the wire for clients that store checkpoints. Applying them
to the current profile would invalidate every stored checkpoint, which is a
visible change for live clients, so they ship only with the candidate bundle.
The current profile therefore keeps its known token risks: a client can still
read, alter or reuse its own current-profile tokens.

## Compatibility

- Current-profile checkpoints keep their format, and checkpoints issued before
  this change stay valid.
- Current-profile page cursors are now sealed. A readable one issued before
  this change returns `410 cursor_expired`: it counted hidden rows, so it
  cannot be resumed against the authorized result. The client restarts that
  session. Page cursors live only within one session, so no stored state is
  affected.
- A current-profile client read whose grant spans several instances that
  hold visible records under one key now fails with
  `403 disclosure_unavailable`, as does any detail read of such a key. It previously
  received both records under one id, or one silently shadowing the other.
- List order changes only for streams whose timestamps mix precision or
  offsets.
- Two quiet current-profile sessions in a row can return the same checkpoint,
  because a sync read no longer advances the clock.
- Changing `order` between candidate sessions invalidates the checkpoint, as
  the candidate binds `order` into the query context.
- Schema v14 adds a column. As with earlier migrations, an older build refuses
  to open the upgraded database.
- Error precedence is unchanged: a deleted connection answers
  `404 instance_unavailable` before any `410`.

## Evidence and limits

`packages/server/src/routes/pdpp-sync-conformance.test.ts` drives the public
HTTP surface on both stores. All of its class A and B cases failed against
#441's head, except 01–08 under the candidate profile, which #441 had already
fixed. Controls cover fixed horizons, the deletion rule in each profile with and
without a recreate, one key held by two instances, a
pre-change current-profile page cursor, a fresh access token for the same grant,
a changed `limit`, retries, and a SQLite restart followed by a reset.

- No store prunes history yet, so `410` for pruned history is covered only by
  the reset fence, rebuilt stores and horizons ahead of the clock.
- A first sync seeks in the identity index and reads only the changes a page
  examines. An incremental page sorts the keys written in its window (a temp
  B-tree over those rows, not the stream) and then reads only what it examines.
- A page that examines its whole work budget without filling ends early with
  `has_more: true`. Such a page shows that the window holds at least that many
  changes the page did not disclose. The candidate forbids signalling hidden
  changes, so this is a deliberate bounded exception: it takes 10,000
  undisclosed changes on one page, and it reveals neither their keys nor their
  exact number.
- The identity guard covers client tokens only. Owner reads across several
  instances still return one id per record key.
- The sealing key does not rotate. Rebuilding the records database expires
  every outstanding token.
- Transport timing is outside this contract.
- A candidate token carries at most `MAX_SYNC_CARRY_BYTES` (2 KiB) of
  withheld and of carried identities. A session that withholds more, which
  takes that many visible records deleted between its pages, expires with
  `410 cursor_expired`.
- The candidate binds `order` into checkpoints, as spec-core requires for the
  query context. A client that changes `order` between sessions gets
  `400 invalid_cursor` and must start again from `beginning`.
- Owner tokens always use the current profile; the candidate's owner-scope
  token rules are not implemented here.
- Schema v14 is a one-way step, like the v12 and v13 migrations this stack already
  adds.

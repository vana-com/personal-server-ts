# PDPP Authorization Server durability statement

PDPP Core v0.1.0 §7 "Lifecycle durability" (spec-core L1810-L1829) and §9 AS
item 44 require the Authorization Server (AS) to describe the durability it
actually provides. This statement covers the AS in this repository
(`packages/core/src/pdpp/store.ts`, `history.ts`, `lifecycle-store.ts`,
`lifecycle.ts`, and `packages/server/src/routes/pdpp-auth.ts`).

## What the AS records, and when

Terminal events are revocations, dispositions and erasure instructions.
Every row below is written in one SQLite transaction together with an entry
in the hash-chained history log (`pdpp_history_log`). After the commit and
before the response, the AS rewrites the anchor file (see below). The
response is sent only when both succeeded.

| Event                                                                                                                                                        | Where                                                                                                                                                           | Recorded before the response that discloses it                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Owner revocation, disconnect, narrowing, decommission (`POST /pdpp/v1/revoke`, `POST /pdpp/v1/owner/grants/end`, `POST /pdpp/v1/owner/decommission/confirm`) | `pdpp_grants.revoked_at`, `pdpp_grant_endings`, `pdpp_owner_dispositions`, linked access tokens and refresh families; for `delete`, `pdpp_erasure_instructions` | Yes. One durable unit per grant; a multi-grant action answers 200 only when every grant is recorded, otherwise 503 with each grant `recorded` or `pending`. |
| Owner erasure request or advance election (`POST /pdpp/v1/owner/grants/erasure`)                                                                             | `pdpp_erasure_instructions`, `pdpp_owner_dispositions`                                                                                                          | Yes.                                                                                                                                                        |
| Client revocation (RFC 7009, `POST /pdpp/v1/token/revoke`) with any `pdpp_disposition`                                                                       | Same rows, `pdpp_revocation_dispositions`, and for `delete` the erasure instruction                                                                             | Yes. 503 with `Retry-After` when not durable; a matching retry completes it without moving any clock.                                                       |
| Client-conveyed `pdpp_disposition=delete` and `received` / `completed` / `retained` reports (`POST /pdpp/v1/grant-lifecycle`)                                | `pdpp_erasure_instructions`, `pdpp_retained_reports`                                                                                                            | Yes.                                                                                                                                                        |
| First return of an instruction in a lifecycle answer                                                                                                         | `pdpp_erasure_instructions.first_returned_at`                                                                                                                   | Yes, before the answer leaves.                                                                                                                              |
| Refresh-token reuse (family revocation)                                                                                                                      | `pdpp_refresh_families.revoked_at` and linked access tokens                                                                                                     | Yes.                                                                                                                                                        |
| Grant issuance with its authorization code; code redemption; `single_use` consumption; refresh supersession; recovery approval and code redemption           | `pdpp_grants`, `pdpp_auth_codes`, `pdpp_refresh_tokens`, `pdpp_recovery_*`                                                                                      | Yes. These are logged and anchored like terminal events (L1824).                                                                                            |
| Disabling a token for lifecycle use                                                                                                                          | `pdpp_lifecycle_disabled_tokens` (token digests)                                                                                                                | Yes.                                                                                                                                                        |

The store is one SQLite file, `<storageRoot>/pdpp-auth.db`, opened with
`journal_mode = WAL` and `synchronous = FULL`. A commit is acknowledged only
after SQLite reports it durable, which relies on the disk honouring flush
requests. Tokens are stored only as SHA-256 digests.

`grant_id` values carry 96 random bits, erasure `instruction_id` values 128
random bits, and authorization codes 122 random bits, so no restore,
failover or rollback can cause one to be reused (L1824).

## The restore-detection mechanism

The AS declares one mechanism (`packages/core/src/pdpp/history.ts`):

1. **Hash-chained log.** Every recorded event appends a row whose hash covers
   the previous row's hash, so the head `(seq, hash)` commits to the whole
   history before it.
2. **Anchor file outside the SQLite file.**
   `<storageRoot>/pdpp-auth.db.history-anchor.json` holds the history epoch,
   the head `(seq, hash)`, and the complete record of every effective erasure
   instruction (identifier, acceptance, effective time, stop-use time, and the
   grant's ending). It is replaced atomically (temporary file, fsync, rename,
   directory fsync) after each commit and before the AS acknowledges
   anything. If this write fails, the AS does not acknowledge: the route
   answers 503, and the evidence is written before the next acknowledgement.
3. **Check at open.** The history is current only when the anchor's epoch
   equals the database's epoch and the database holds the anchored head with
   the anchored hash. A database **behind** the anchor
   (`history_behind_anchor`), one whose row at the anchored position differs
   (`history_diverged`), one from another history (`epoch_mismatch`), a
   missing anchor for a store that was anchored before (`anchor_missing`), or
   an unreadable anchor (`anchor_unreadable`) is **not current**.

A database ahead of the anchor is current: evidence may lag events that were
never acknowledged (L1823). The check runs when the store opens (server
boot); a file swapped under a running process is not re-checked until the
next start.

### Paths the mechanism detects

- Restoring `pdpp-auth.db` alone from an older file copy or backup, while the
  anchor file stays current (for example a database-only restore, a copy of
  an older `pdpp-auth.db` over the live one, or a backup tool that restores
  the SQLite file but not its sidecar).
- Replacing `pdpp-auth.db` with a different database (a fresh file, or one
  from another server).
- Losing or corrupting the anchor file while the database survives.
- Losing only the suffix of the log that holds an acknowledged event E (the
  database ends before the anchored position). E's complete instruction
  survives in the anchor.

### What the AS does on a detected path (fails closed)

While the history is not current (`GET /pdpp/v1/owner/lifecycle/history`
shows the reason):

- no token is issued or re-delivered: the authorization-code and refresh
  exchanges answer 503 `temporarily_unavailable` with `Retry-After`, before
  any code or refresh token is consumed;
- no client token resolves active, at the Resource Server (co-located
  resolution) or in introspection (`active: false`);
- no new grant is approved (503);
- the lifecycle operation answers 503 `temporarily_unavailable` with
  `Retry-After`, except that a query for a grant whose complete erasure
  instruction is in the anchor returns that `erase` answer (L1820); lifecycle
  writes and client RFC 7009 revocations answer 503;
- owner revocations, dispositions and erasure requests are **accepted**:
  each is appended and fsync'd to
  `<storageRoot>/pdpp-auth.db.pending-owner-actions.jsonl` (outside the
  unavailable database) before the AS answers 202, and the owner sees each
  grant as `pending` with the statement that the AS issues no tokens and
  returns no positive answers meanwhile (L1827). A request without an
  explicit disposition is still rejected.

Re-establishing the history (`POST /pdpp/v1/owner/lifecycle/reestablish`)
needs the owner, and in one transaction:

1. restores every anchored erasure instruction the database lacks, with its
   original identifier and clocks, and the grant's ending;
2. applies every pending owner action, in order;
3. ends every grant that is still active, because its terminal events may be
   missing ("invalidation on restore of every grant whose terminal events may
   be missing", L1823). Each such grant needs the owner's explicit `keep` or
   `delete`; the request is rejected without them.

Only then does the history become current, under a new epoch. Consequence:
after a detected restore, every client must obtain a new grant. Revoked
grants, consumed `single_use` grants, redeemed codes and superseded refresh
tokens in the restored file are never revived.

## Losses this AS does not survive

- **Loss of the disk that holds `<storageRoot>`.** The database, the anchor
  and the pending-action journal live on one disk by default. This AS does
  not claim that any record survives loss of that disk.
- **Loss of the host**, unless the operator keeps a copy of `<storageRoot>`
  elsewhere. Restoring such a copy is one of the undetected paths below.
- **A disk or virtual disk that acknowledges a flush it has not made.** A
  power loss can then drop commits, anchor writes, or journal lines that were
  reported durable.

## Restore and rollback paths the mechanism does NOT detect

The anchor sits in the same directory as the database. A rollback that
restores both together leaves them consistent with each other, so it is
undetected:

- reverting a virtual-machine snapshot, container-volume or disk snapshot, on
  one host or after moving it;
- rolling back a filesystem or volume snapshot (APFS, ZFS, LVM, cloud disk)
  that contains `<storageRoot>`;
- restoring the whole `<storageRoot>` (database and anchor) from a file
  backup, for example a Time Machine or `rsync` copy;
- copying an older `<storageRoot>` onto a new host and starting the server;
- any restore of a store created before this mechanism existed, up to its
  first anchored event.

After any of these, every enforcement point treats the restored store as
current. A rollback that it does not detect, such as a revert of a
virtual-machine snapshot, can revive revoked grants and lose recorded
deletions. In detail, such a path can:

- revive **revoked grants**, with their access tokens and refresh-token
  families, so introspection and the Resource Server report them active
  again;
- revive **consumed `single_use` grants**, opening a second read window;
- revive **redeemed authorization codes**, redeemable again while their
  60-second expiry has not passed;
- revive **superseded refresh tokens**, usable again without reuse
  detection;
- lose recorded **dispositions, erasure instructions and erasure reports**.

Authorization codes and access tokens carry absolute expiry times, so a
restore does not extend them.

## Other limits

- The opt-in replica read path asks a remote issuer to introspect; this
  statement covers only the local store, not that issuer's history.
- Pending consent and lifecycle-recovery sessions live in memory and are lost
  on restart. They hold no issued authority.
- This AS has no device-code exchange, no token re-delivery, no package
  fan-out and no processing authority, so those enforcement points do not
  exist here.
- The AS keeps every grant's lifecycle and authentication bindings
  indefinitely; it does not compact resolved history.

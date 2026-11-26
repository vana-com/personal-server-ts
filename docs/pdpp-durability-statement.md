# PDPP Authorization Server durability statement

PDPP Core v0.1.0 §7 "Lifecycle durability" (spec-core L1810-L1829) and §9 AS
item 44 require the Authorization Server (AS) to describe the durability it
actually provides. This statement covers the AS in this repository
(`packages/core/src/pdpp/store.ts`, `packages/server/src/routes/pdpp-auth.ts`).

## What the AS records, and when

| Event | Where | Recorded before the response that discloses it |
|---|---|---|
| Owner revocation (`POST /pdpp/v1/revoke`) | `pdpp_grants.revoked_at`, linked access tokens and refresh families, one SQLite transaction | Yes. The 200 is sent after the commit. |
| Client revocation (RFC 7009, `POST /pdpp/v1/token/revoke`) | Same rows, plus any recorded `pdpp_disposition` in `pdpp_revocation_dispositions`, one transaction | Yes. The 200 is sent after the commit. |
| Refresh-token reuse (family revocation) | `pdpp_refresh_families.revoked_at` and linked access tokens, one transaction | Yes. `invalid_grant` is returned after the commit. |
| Grant issuance with its authorization code | `pdpp_grants` + `pdpp_auth_codes`, one transaction | Yes. The code is returned after the commit. |
| Authorization-code redemption, `single_use` consumption, refresh-token supersession | Conditional `UPDATE` inside a transaction | Yes. |

The store is one SQLite file, `<storageRoot>/pdpp-auth.db`, opened with
`journal_mode = WAL` and `synchronous = FULL`. A commit is acknowledged only
after SQLite reports it durable, which relies on the disk honouring flush
requests.

Every enforcement path reads this one store on every call: authorization-code
exchange, refresh exchange, co-located token resolution for the Resource
Server, RFC 7662 introspection, and RFC 7009 revocation. None caches a grant
decision. So, on a store that has not been restored, no path returns an active
introspection result or a token for a grant whose revocation was acknowledged.
A token response returns the complete grant and so is also a positive
assessment for it (spec-core L1415); it is computed by the same exchange paths
above. This build has no device-code exchange, no token re-delivery, no
package fan-out, no processing authority and no lifecycle operation.

`grant_id` values carry 96 random bits and authorization codes are random
UUIDv4 values (122 random bits), so a restored store cannot cause one to be
reused.

## Losses this AS does not survive

- **Loss of the disk that holds `<storageRoot>`.** The history lives on one
  disk. This AS does not claim that any record survives loss of that disk.
- **Loss of the host**, unless the operator keeps a copy of `<storageRoot>`
  elsewhere. Restoring such a copy is one of the undetected paths below.
- **A disk or virtual disk that acknowledges a flush it has not made.** A
  power loss can then drop commits that SQLite reported durable.

## Restore and rollback paths: none is detected

This AS declares **no** restore-detection mechanism. It keeps no evidence
outside the store's failure domain. It therefore detects none of these paths,
and none of them makes it fail closed:

- restoring `pdpp-auth.db` (or the whole `<storageRoot>`) from a file backup,
  for example a Time Machine or `rsync` copy;
- reverting a virtual-machine, container-volume or disk snapshot, on one host
  or after moving it;
- rolling back a filesystem or volume snapshot (APFS, ZFS, LVM, cloud disk);
- copying an older `<storageRoot>` onto a new host and starting the server.

After any of these, every enforcement point treats the restored store as
current. Such a path can revive:

- **revoked grants**, with their access tokens and refresh-token families, so
  introspection and the Resource Server report them active again;
- **consumed `single_use` grants**, opening a second read window;
- **redeemed authorization codes**, redeemable again while their 60-second
  expiry has not passed;
- **superseded refresh tokens**, usable again without reuse detection;
- **recorded `pdpp_disposition` values**, which are lost.

Authorization codes and access tokens carry absolute expiry times, so a
restore does not extend them.

## What this AS does not yet do

- It does not accept owner revocations while the history is unavailable
  (spec-core L1827 requires the AS to accept, record and later apply them).
  If `pdpp-auth.db` holds a state version this build does not support,
  `/pdpp/v1` is not mounted; any other open failure stops the server at boot.
  Either way the owner cannot revoke until the store is back.
- The opt-in replica read path asks a remote issuer to introspect; this
  statement covers only the local store, not that issuer's history.
- It records no erasure instructions and has no grant lifecycle operation.
  A recorded `delete` disposition is stored, but is not yet an erasure
  instruction (grant-lifecycle work package).
- Pending consent sessions live in memory and are lost on restart. They hold
  no issued authority.

# Write-once publication (BUI-911)

A stopped publisher can leave ciphertext at the next legal version without a registry row. Reusing it without an atomic deletion fence can undo a concurrent delete. This document separates client recovery from the gateway change that recovery requires.

## Invariant owners

- **Storage** owns atomic write-once creation at `(owner, scope, version)`. A different PUT must return `409 BLOB_EXISTS` without changing bytes. Client probes cannot supply this guarantee.
- **Gateway** owns contiguous version order and immutable version-to-commitment binding, including pending and failed rows. Repeating the same binding is idempotent; changing either commitment requires a later version.
- **Gateway** must own the publication/deletion generation. A delete increments a monotonic per-owner/scope generation in the same database transaction that installs its tombstone. Failed broadcasts, retries, rollbacks, and cleanup never restore an older generation.
- **Publisher** owns verification of the complete envelope, scope, content hash, stored ciphertext size, metadata hash, and stored lineage before registration/adoption. A synced result carries the registered version and canonical URL together.

## State machine

`reserve → upload → verify retained bytes → register/adopt → local acknowledgement`

Today reservation is the write-once storage key, not an expiring lock. A crash before PUT leaves no reservation. A crash after PUT leaves an unregistered reservation. A crash after registration leaves a committed version whose identity can be recovered independently of the local synced marker.

On an occupied unregistered next slot, a capable publisher downloads and validates its full envelope and lineage, computes its commitments from the retained bytes, and registers that binding under the captured generation/head fence. If its payload differs from the requested payload, the publisher then uploads/registers the requested payload at the next version in the **same generation** (adopt then supersede). It never deletes the occupant or silently overwrites a committed version. Invalid or undecryptable occupants require operator recovery; they are not publication authority.

Adopting an existing registration always resolves that version's canonical URL and verifies both commitments against available bytes. A missing blob can be recreated only if the new ciphertext satisfies **both** existing commitments, including stored size. Same-version adoption has no availability shortcut. Before the local synced marker is persisted, a crash after an effect repeats these checks; no local intent or version number alone proves completion. Already-synced rows retain the existing shortcut and do not revalidate remote availability. Work is bounded per invocation; repeated contention remains retryable.

A tombstone invalidates all earlier generation fences. A deliberate re-add acknowledges the tombstone version and publishes strictly later; a recovery attempt cannot turn itself into a deliberate re-add by rereading after a conflict. No recovery deletes ciphertext in order to free a slot.

## Proposed gateway contract (not deployed)

Owner/server authentication remains required. The fence is included in the authenticated request body; it is not an AddData signature extension that the old SDK can silently discard.

`GET /v1/data/:id/publication` returns `{ generation: "17", head: null | { id, expectedVersion, dataHash, metadataHash, deletedAt } }`. Reads must include pending/failed tombstones. Generation is gateway-owned, persistent even for an absent head, and monotonic across registry resets.

`POST /v1/data/:id/publication` accepts `{ mode: "register" | "adopt", fence: <the complete GET result>, ownerAddress, scope, expectedVersion, dataHash, metadataHash, signature, lineage?, lineageSignature? }`. In one transaction the gateway compares generation and head identity/commitments/deletion state, validates authorization and lineage, and either registers the next contiguous binding or verifies the exact live binding for adoption. It returns `{ dataPointId, fence: <new generation/head snapshot> }`. An intentional re-add uses a fence acknowledging the tombstone and a strictly later version. `409 PUBLICATION_FENCE_CHANGED` changes nothing and is retryable. Idempotent registration retries must never replace a tombstone. Delete atomically increments generation and installs the tombstone before reporting success, and fences physical cleanup against later re-adds.

The TypeScript capability port models this contract only. There is no HTTP adapter or capability claim for the current gateway. A real adapter must authenticate the entire request, validate responses, and be integration-tested with concurrent gateway transactions before enabling it.

## Compatibility and rollout

Fresh, uncontended uploads continue through the current gateway. Resume/adoption and publication across an observed delete require the optional fenced-publication capability; without it they surface retryable `NEEDS_FENCED_PUBLICATION` and remain unsynced. The additions writer retains `behind` coverage and reports that reason through `onPublicationBlocked`; the server logs it. This is an intentional recovery restriction, not a claim that the legacy gateway is race-free: an ordinary fresh registration racing an unseen delete still needs the gateway fix. Existing gateway binding replacement for pending/failed rows also remains an external requirement.

The full-host upload worker and additions writer share one publication policy. Bounded browser publication remains host-supplied and is outside this full-host implementation; its recovery must implement the same gateway contract before it can claim deletion safety.

Vana-storage #32 needs no additional API for verify/adopt/supersede. Its atomic write-once PUT must ship first. No read-then-delete reclaim, timeout lease, or storage generation API is proposed. If physical delete can race a later re-add at the same key, gateway cleanup fencing is also required; write-once while present alone does not prevent delete/recreate.

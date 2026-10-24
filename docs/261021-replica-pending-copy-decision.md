# Pending copies and finalized authority

Status: recommendation for Tim. This draft keeps #426's provisional ordering.

## Two devices editing one record

Distinct device writers are ordinary concurrent edits. Pending and confirmed operations use the same `(counter, writerId, operationId)` order. A pending winner carries the confirmation marker. Its counter does not advance the local Lamport clock. If its batch is quarantined, the next eligible operation becomes visible. If it is promoted, the same winner becomes confirmed. Delivery order must not affect the result.

The regression uses two receivers, reverses delivery of equal-counter edits from two device writers, and checks winner withdrawal. This does not establish which device observed the freshest upstream data. Stronger freshness remains a separate product decision.

## Conflicting copies of the same batch

Two different payloads claiming the same `(writer, batch)` identity are different from concurrent device edits. The current receiver keys pending storage by the host's batch ID. A changed payload quarantines that ID. `promote({credential,id})` does not identify which payload the host verified. Silently replacing the first payload, or choosing by arrival time, could import bytes different from those verified by the host. Keeping the ID quarantined can also block that writer's successors indefinitely.

Recommendation: retain copies by `(writer, batch, payload fingerprint)` and retain the exact fragment hash pairs for each copy. Treat a copy as provisional until the worker verifies every member and its predecessor against pinned finalized evidence. The host must select that exact fingerprint atomically with promotion and acknowledgment. Withdraw only copies disproved by finalized evidence. Do not infer authority from a retry deadline, a newer head hint, a larger Lamport counter, or the first copy received.

A finalized replacement of an unfinalized copy should be recoverable. Two incompatible finalized commitments for an immutable identity should remain a terminal integrity conflict, with safe diagnostics and an explicit repair process. A restored database that reused its writer identity needs writer rotation; payload selection must not conceal that failure.

## Decision required

Approve fingerprint-pinned recovery of unfinalized copies while retaining terminal quarantine for contradictory finalized commitments. This requires a host/receiver identity contract beyond the current `stage`, `promote`, and `quarantine` signatures. The scheduling lane has frozen those signatures for its present work, so this draft does not guess which quarantined copy a bare `promote(id)` authorizes.

Until that contract is agreed and tested across restart, replacement, acknowledgment, and successor import, runtime enablement remains blocked for same-batch copy recovery. Distinct-writer record conflicts keep the existing order and are covered separately.

# ADR 0001: Replication signer, transport and opt-in for internal testers

Status: proposed. Date: 2026-10-27.
Details and code evidence: [host contract](host-contract.md).

## Context

The replication engine on PR #483 is complete behind `replication.enabled`
(default off), but no host runs it. Both writer ids are random and bound to no
key, so a receiver cannot tell whether a batch came from a device the owner
approved. The transport port has no abort signal, Lite has no byte storage that
fits fragments, and there is no agreed opt-in or off switch.

## Decision

1. **Testers use the DPv2 carrier as built.** No production transport is
   chosen now.
2. **Each device signs its batches with its existing registered PS server
   key.** The owner's `ServerRegistration` roster at the gateway is membership;
   deregistration is removal.
3. **Writer ids are derived from the signer:** a hash of owner, server
   address, gateway registration id, role and a disclosed nonce. Receivers
   recompute them from the verified signature and the roster record, and
   require the roster owner, statement owner and receiver owner to match.
   Nothing is bound on first contact.
4. **Peers import only from servers registered now.** After removal they
   refuse unimported batches and keep imported data. A re-registered server is
   a new incarnation with new writers.
5. **The host owns timing and cancellation; the coordinator owns retries.**
   Adapters take an abort signal and byte cap and never retry.
6. **Limits bound work and memory per step,** with no blob-size cap, so no
   rule can stall a device's later changes. This needs engine work in A7:
   admission by next resumable unit, and resumable retention, hashing,
   preparation and import staging.
7. **Opt-in is per device and one-way.** The Account entitlement
   `replication_internal` (`opendatalabs.xyz` only) gates the UI. A SQLite
   mutation fence detects any write outside the capture path, by any build,
   and PS refuses re-enable.

## Consequences

- A copied `key.json` can sign as that device until the owner deregisters it.
- A removed device that kept the master key can read new batches, because
  storage reads are public and every device holds the master key. This must be
  fixed before production.
- Peers lose a removed device's changes that they had not yet imported.
- Lite replication must use the Lite server key, not the owner sync signer.
- Once-enabled databases carry triggers next to main's tables.

## Later, before production

A dedicated per-device replication key in Android Keystore, the iOS Secure
Enclave or the OS keychain, certified by the server key. It would stop a copied
`key.json` from signing and let batch keys be wrapped to each current device.
DPv2's cost (about two minutes of finality per hop, one registration per
fragment) may also justify a different carrier, which needs its own design.
Plan item A12 replaces per-fragment registration with one registration per
device sync, a manifest of content-addressed fragments.

## Alternatives considered

- **Wallet signs batches.** Needs a wallet prompt or a custodial signer per
  batch.
- **Bind a writer to the first server seen publishing it.** A registered
  server that reaches a fresh receiver first takes the writer, and nothing
  constrains the operation writer. Two review rounds found gaps in this table.
- **Accept batches published before revocation.** Needs a trusted publication
  time and lets a key used during the gap keep its writes.
- **Record-store write clock as the off-time detector.** Some reads advance it
  and `registerConnection` does not.

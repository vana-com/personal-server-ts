# ADR 0001: Replication transport and device identity

Status: proposed. Date: 2026-10-27.
Details and code evidence: [host contract](host-contract.md).

## Context

The replication engine on PR #483 moves canonical record changes between an
owner's devices. It is complete behind `replication.enabled` (default off) but
no host runs it. Before the Desktop and phone hosts can wire it, three things
must be fixed:

1. **What carries batches.** The only carrier today writes each fragment to
   vana-storage, registers it at the gateway and waits for a finalized
   DataRegistryV2 commitment. On dev, finality between two devices took about
   2 minutes (median 122 s, p90 134 s). One 101 MiB blob became 4,310
   fragments, each with its own registration.
2. **Who may write.** Both writer ids are random. The receiver's
   `authenticate(credential)` hook has no credential to check. Nothing binds a
   batch to a device the owner approved.
3. **What the hosts implement.** The carrier port has no abort signal, Lite
   has no byte storage that fits replica fragments, and there is no agreed
   status, lifecycle or opt-in contract.

## Decision

1. **Testers keep the DPv2 carrier.** It is built and has passed live dev runs.
2. **Production uses a vana-storage mailbox** behind the same carrier port:
   write-once objects keyed by owner, writer and sequence; a list-by-prefix
   call; retention until every non-revoked device acknowledges. No per-fragment
   gateway registration and no chain commitment. vana-storage must add the list
   endpoint and writer-owned deletion.
3. **Each device has its own P-256 replication key**, non-exportable on phones
   (Android Keystore, iOS Secure Enclave) and held in the OS keychain on
   Desktop. It is not the attestation subject and not the wallet.
4. **The registered server key certifies the device key.** A
   `PdppReplicaDevice` EIP-712 certificate binds owner, server, both writer ids
   and the device public key. The owner's existing `ServerRegistration` is the
   membership proof, and gateway deregistration is the revocation.
5. **The device key signs every batch statement.** Receivers verify the
   signature, the certificate, the roster and the writer binding before import.
   Failures are typed quarantines.
6. **Encryption stays on the owner master key** for now. Storage sees only
   ciphertext, sizes, timing and opaque writer tokens.
7. **The host owns timing; the coordinator owns retries.** Hosts call a
   single-flight `step` at `nextWake` and on triggers, and abort it on stop or
   background. Carriers never retry and must stop I/O on abort.
8. **The phone replicates only in the foreground.**
9. **Opt-in is per device and one-way.** An Account entitlement
   (`replication_internal`, from the verified email domain) gates the UI only.
   The host stores the device's opt-in record; PS stores a durable marker and
   refuses re-enable after off. No data is deleted.

## Consequences

- The engine does not change when the carrier changes. The mailbox is a new
  carrier, tested with the same acceptance suite.
- Production replication loses public DataRegistry evidence for replica data.
  This needs a product decision (host contract, open question a).
- A revoked device can still decrypt new batches it can read, because every
  device holds the master key. Wrapping a per-batch key to each device closes
  this (open question b).
- One record blob over the tester limit (32 MiB) stops that device's later
  changes from reaching its peers until the limit rises (open question d).
- A lost device key is permanent for that device: it can only join again as a
  new device.
- vana-storage, both hosts and Account each get new work; none of it is in this
  repository's change set for D0.

## Alternatives considered

- **PS-to-PS relay.** Needs both devices online at once. A foreground-only
  phone and a sleeping Desktop rarely overlap. Adds an always-on service.
- **Gateway mailbox.** Puts bulk bytes in a registry service this repository
  does not own.
- **Wallet signs batches.** Needs a wallet prompt or a custodial signer per
  batch, and ties replication to the Account signer.
- **Reuse the server key as the batch key.** On Node it is a file key in
  `key.json`; on the phone it is a JS-held key. A hardware-backed device key is
  stronger, and the certificate keeps the server key's role to one signature
  per device.
- **Reuse the Android attestation subject.** It serves Account attestation. A
  shared key would couple two revocation and rotation paths.

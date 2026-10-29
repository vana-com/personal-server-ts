# PDPP replica operation profile v1

This is an internal Vana implementation profile, not a normative PDPP addition.
It defines pure operation decisions. It has no storage, receiver, publisher,
transport encryption, byte transfer, or authorization-state replication.

## Provisional decisions

`REPLICA_POLICY` in `merge-plan.ts` is the decision index. The executable vectors
pin these choices so a later policy revision must change its expected results.

1. Mutable records use the greatest persisted `(counter, writerId, operationId)`.
   Strings compare by JavaScript UTF-16 code units, without locale collation.
   Retain every losing operation, including tombstones. A later upsert can
   resurrect a record. Convergence means equal retained evidence yields equal
   results; it does not establish the freshest upstream truth from offline
   scrapes. Emitted timestamps and local query versions do not select winners.
2. Append-only different-content writes quarantine the entire key. Equal JSON
   data and blob descriptors are equal content regardless of object-key order;
   emitted timestamps are metadata. Quarantine has no winner and retains all
   contenders. Ordinary upserts cannot repair it, even at a higher revision.
   Repair requires a separately authorized explicit resolution protocol. Profile
   v1 has no repair operation; quarantine remains until that protocol exists.
   Other keys remain readable. Append-only record deletion is rejected.
3. One existing issuer keeps grants, tokens and revocation. Only data and
   connection evidence replicate. `resolveLocalInstance` uses an explicit,
   verified logical-connection mapping for each device's local instance handle.
   It does not map grants or confer token authority. Independent device-source
   instances retain independent connection IDs. Grant/revocation replication
   and acceptance of another issuer's handles are outside this profile.

## Identity and lifecycle

Each operation carries owner, producer source ID, logical connection ID,
immutable acquisition method, generation, and persisted revision. Record
identity adds stream and canonical record key. The trusted retained declaration
binds its digest, version, schema digest, semantics and ordered primary key.
The host supplies data validation against that exact retained schema. Versions
of one stream with the same shape (stream, semantics, primary key;
`declarationShape`) are one record set: they merge by revision, and each
operation validates against its own schema. A key whose candidates name two
shapes is quarantined. `resolveDeclaration` decides an operation whose binding
is not retained: a version of a retained shape applies and validates by key
only, a binding of a stream with no retained binding stays pending
(`missing_declaration`), and another shape of a retained stream stays pending
as `incompatible_declaration` and never applies. `rebinding.ts` decides
what a changed set of retained declarations does to a database. The decoder
requires an exact known binding. It does not fetch declarations or verify their
digest itself.

Connection registration starts generation 1. A reset advances exactly one
generation and retains the method; incompatible methods or sources fail closed.
Every intervening reset must be present before a newer generation becomes live.
Old-generation records remain suppressed even if their counters are greater.
Connection deletion dominates all writes and resets, including later revisions.
Recreation requires a new logical connection ID. No missing batch implies delete.

Operation identity is `(writerId, operationId)`. Identical replay has no extra
multiplicity. Different bytes for that identity quarantine all affected
connections. Clone/restore must rotate writer identity before making new writes.
Writer ids are derived from the server's gateway registration and a writer
nonce (`writer-identity.ts`); receivers accept a batch only when its signed
`PdppReplicaBatch` statement and the roster (`roster.ts`) authorize the
transport writer and every operation writer.
`nextLamportCounter` advances past every observed counter; the host must persist
it with its mutation. Slice 1 journal sequence and local record version are
neither a Lamport counter nor evidence of cross-device ordering.

## Wire and execution boundary

`encodeReplicaEnvelope` emits canonical JSON: recursively sorted object keys,
array order retained, finite JSON numbers and no whitespace. The decoder accepts
only those exact canonical bytes, rejecting duplicate-member ambiguity, unknown
versions, unknown fields, and changed authenticated-owner/declaration binding.
Authentication, decryption and verification precede decode; the expected owner
must come from that authenticated context. This codec is not a signature check.
Transport sequences, predecessors and fragmentation belong to later framing
work; this operation envelope cannot yet be published. `blob-claim` pins a verified
content descriptor to a connection generation. `stream-complete` lists exact
operation identities and SHA-256 digests. `hasCompletionDependencies` checks that
coverage; receivers must additionally validate merged snapshot and byte integrity
before claiming availability. The SQLite implementation and fence contract are
documented in `packages/server/src/storage/pdpp-replication.md`.

`planReplicaMerge` takes the complete retained operation set. Preserve that set
across calls, including lifecycle evidence, losers, pending evidence, conflicts
and tombstones. Recompute after dependencies arrive. The result is a plan with
normalized records, conflicts, pending, rejected and suppressed evidence. It does
not mutate the input, allocate local versions, apply writes, or verify blob bytes.
Blob descriptors alone never authorize a local byte claim or prove completion.
Public PDPP record envelopes and local cursor tokens are untouched.

## Executable vectors

`__fixtures__/envelope-v1.json` pins independently serialized wire bytes and the
corresponding decoded object. `envelope.test.ts` tests the golden, lifecycle and
blob roundtrips, version rejection and each declaration-binding substitution.
`fixtures.ts` defines the mutable conflict/delete/resurrection sequence.
`merge-plan.test.ts` exhausts permutations with duplicate/reversed replay and
checks concrete winners, retained losers, deletes and quarantine outcomes.
`identity.test.ts` covers shared logical connections and refused account collapse.
`revision.test.ts` covers total ordering, counter advance and exhaustion.

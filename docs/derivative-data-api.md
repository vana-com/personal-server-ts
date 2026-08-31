# Derivative data: lineage API

Status: protocol slice for the external interpretation pipeline. A derivative
is an ordinary Personal Server write that carries a lineage pointer to the
records it was computed from. Nothing else changes: the write path, the
encrypt / upload / register path and the grant grammar stay as they are.

What this slice gives you:

1. a write that carries `lineage` (the source data point ids),
2. a way to walk lineage in both directions (sources and derivatives),
3. the guarantee that a grant on a derived scope confers nothing on its
   sources (and the other way round),
4. delete with an optional lineage cascade.

Not in this slice: context queries, TEE hosting, snapshot / view semantics.
An interpretation can run outside Vana and write its results back through
the Write API, or it can be registered as a question and computed inside the
Personal Server (see "Compute (question to derivative)" at the end).

## Identifiers

- `dataPointId` = `keccak256(abi.encode(address owner, string scope))`, the
  DataRegistryV2 primary key. Every version of a scope shares the id. Ids are
  0x-prefixed 32-byte hex; the protocol compares them case-insensitively and
  stores them lowercase.
- A lineage entry is a data point id. Lineage never points at a specific
  version of a source: it says "this record was computed from the owner's
  `<scope>` data point".
- Lineage is recorded per version of the derived record and is immutable
  once that version is registered. A new version of the same scope carries
  its own lineage.
- All sources must belong to the same owner as the derived record. Empty or
  absent lineage means a root record.

## Write a derivative (Personal Server)

`POST /v1/data/:scope` is the existing Write API endpoint. Session writes
(write-session bearer token + `X-Vana-Write-Signature` proof) and owner
writes both accept lineage.

`lineage` is an optional top-level field of the JSON body:

```http
POST /v1/data/spine.health.summary
Authorization: Bearer vana_write_...
Content-Type: application/json
X-Vana-Write-Signature: Web3Signed <base64url(payload)>.<sig>

{"summary":"Sleep improved after March.","lineage":["0x5b1a...9c","0x9e77...02"]}
```

For a binary write (`Content-Type` other than JSON) put `lineage` inside the
JSON object carried by the `X-Vana-Metadata` header:

```http
POST /v1/data/spine.health.report
Content-Type: application/pdf
X-Filename: report.pdf
X-Vana-Metadata: {"description":"Quarterly report","lineage":["0x5b1a...9c"]}
```

The caller's `lineage` field stays in the record exactly as sent (it is part
of the bytes the builder signed, see below). The Personal Server validates it
and mirrors it into the stored envelope `data` under the reserved key
`$lineage`, next to `$writtenBy` and `$binary`:

```json
{
  "summary": "Sleep improved after March.",
  "lineage": ["0x5b1a...9c", "0x9e77...02"],
  "$lineage": {
    "sources": ["0x5b1a...9c", "0x9e77...02"],
    "writtenAt": "2026-08-31T09:12:44.000Z"
  },
  "$writtenBy": {
    "builder": "0x...",
    "grantId": "0x...",
    "signature": "...",
    "bodyHash": "sha256:...",
    "writtenAt": "..."
  }
}
```

`$lineage.sources` is the validated, lowercased, order-preserved list. A body
(or metadata object) that brings its own `$lineage` is rejected with 400, the
same rule as `$writtenBy`.

Because `$lineage` lives inside `data`, `dataHash` (unchanged definition:
keccak256 of the plaintext envelope JSON) now commits to the lineage as well;
`metadataHash` keeps its definition (`{scope, collectedAt, sizeBytes}`). The
on-chain AddData struct is untouched. The plaintext copy of the lineage that
the gateway stores is covered by a separate server-signed attestation (see
"Gateway write").

Builder attribution and the reserved keys: the builder signs the compact JSON
body (JSON writes) or the stored `$binary` record (binary writes). Both
server-stamped keys, `$writtenBy` and `$lineage`, are stripped before the
stored bytes are re-hashed by `verifyStoredWriterAttribution`, so a record
with lineage verifies exactly like one without. The builder's own `lineage`
field is inside the signed bytes, so the lineage claim itself is builder
signed and the server-stamped `$lineage` is the validated mirror of it.

Validation, in order:

1. `lineage` must be an array of distinct 0x-prefixed 32-byte hex strings, at
   most 256 entries, none of them the record's own id. Otherwise 400
   `LINEAGE_INVALID`. A `null` or absent `lineage` makes no lineage
   statement (a root record, nothing stamped). An empty array is an explicit
   root statement: `$lineage` is stamped with `sources: []` and the record is
   registered at the gateway as an attested root, which matters for a
   same-version refresh (see "Gateway write").
2. Every source id must resolve to a data point of this owner: the Personal
   Server first checks its local index (`keccak256(owner, scope)` over its own
   scopes, so a source that has not synced yet is still valid), then asks the
   gateway with `includeDeleted=true`. A tombstoned source is a valid lineage
   target (it is reported as deleted when the lineage is walked). An id that
   resolves to nothing, or to another owner's data point, fails with 422
   `LINEAGE_SOURCE_UNKNOWN` and `details.unknown` lists the offending ids.
3. The derived scope must not be named under a source's wildcard prefix (see
   "Naming rule"). Otherwise 400 `LINEAGE_SCOPE_UNDER_SOURCE_PREFIX`.

Scopes follow the existing grammar (two or three dot-separated segments, e.g.
`spine.health.summary`).

A rejected session write hands the builder's proof back (the replay guard is
not consumed), so the same signed request can be retried after fixing the
lineage.

Success response (201) is the existing ingest response plus the accepted
lineage:

```json
{
  "scope": "spine.health.summary",
  "collectedAt": "2026-08-31T09:12:44Z",
  "status": "syncing",
  "lineage": { "sources": ["0x5b1a...9c", "0x9e77...02"] }
}
```

Error bodies for lineage codes use the protocol error envelope:

```json
{
  "error": {
    "code": 422,
    "errorCode": "LINEAGE_SOURCE_UNKNOWN",
    "message": "...",
    "details": { "unknown": ["0x9e77...02"] }
  }
}
```

| Status | errorCode                           | When                                                                                               |
| ------ | ----------------------------------- | -------------------------------------------------------------------------------------------------- |
| 400    | `INVALID_BODY`                      | body carries `$lineage` (or `$writtenBy`)                                                          |
| 400    | `LINEAGE_INVALID`                   | not an array of distinct bytes32 hex, or more than 256 entries, or a source is the record's own id |
| 400    | `LINEAGE_SCOPE_UNDER_SOURCE_PREFIX` | naming rule violated                                                                               |
| 422    | `LINEAGE_SOURCE_UNKNOWN`            | a source is not a data point of this owner                                                         |
| 500    | `SERVER_NOT_CONFIGURED`             | the server has no owner address                                                                    |
| 502    | `LINEAGE_SOURCE_LOOKUP_FAILED`      | a source is not local and the gateway could not be reached                                         |

## Naming rule

Grant scopes use the existing pattern grammar: an exact scope, `prefix.*`
(every scope starting with `prefix.`), or `*`. A grant on `chatgpt.*` reads
every scope under `chatgpt.`. If a derivative of `chatgpt.conversations` were
named `chatgpt.summary`, a grant on the source namespace would read the
derivative and a grant on `chatgpt.*` taken for the derivative would read the
sources. That is the only way the current grammar can leak across a lineage
edge, so it is ruled out at write time:

> A derived scope must not share its first dot-segment with any of its
> source scopes.

`spine.health.summary` derived from `chatgpt.conversations` and
`oura.sleep` is fine. `chatgpt.health.summary` derived from
`chatgpt.conversations` is rejected with 400
`LINEAGE_SCOPE_UNDER_SOURCE_PREFIX`. Put derivatives in the interpreting app's
own namespace.

A `*` grant reads everything by definition and is not a lineage leak.

## Derivative grants

A grant on `spine.health.summary` is a grant on that scope only. The read
policy matches the requested scope against the grant entries verbatim, and the
write policy only honors `write:`-prefixed entries, so:

- a grant on a derived scope never satisfies a read of any of its sources;
- a grant on a source never satisfies a read of the derivative;
- a write grant on the derived scope (`write:spine.health.summary`) lets the
  builder write the derivative and nothing else; reading the sources needs its
  own read grant on the source scopes.

The pipeline therefore needs two grants from the user: read on the raw source
scopes, write on the derived scope(s). Other apps then take read grants on the
derived scopes only.

## Walk lineage

### Gateway

```http
GET /v1/data/:dataPointId/lineage[/:version]
Authorization: Web3Signed <base64url(payload)>.<sig>
```

Authentication is the request-signing scheme the Personal Server already
uses (EIP-191 over a base64url JSON payload with `aud`, `method`, `uri`,
`bodyHash`, `iat`, `exp`, optional `grantId`): `aud` is the gateway origin,
`method` is `GET`, `bodyHash` is the hash of an empty body
(`sha256:e3b0c442...`), `iat <= exp` with at most one hour between them, and
`uri` is the request path without a query string, exactly as in Personal
Server reads. The endpoint takes no query parameters: the view selectors are
signed. The version is a path segment (`/v1/data/<id>/lineage/3`; omit it for
the current version) and the grant view is the scheme's own `grantId` claim
in the signed payload, so a captured signature cannot be replayed for another
version or grant view. The signer decides the view:

- the data point's owner, or one of the owner's confirmed, unrevoked
  registered servers: full view. With a `grantId` claim the response is instead the view that grant
  sees (the grant must be issued by this owner), attested as such; this is
  how a Personal Server serves a builder.
- a confirmed, paid builder holding a live grant from the owner (not revoked
  or expired, registration paid and confirmed on chain) that covers the data
  point's scope: the view for that grant. Nodes whose scope the grant does
  not cover are returned as `{ "redacted": true }` and nothing else: no id,
  scope or version. A data point id is `keccak256(owner, scope)` and the
  grantee knows the owner, so an id would let it dictionary-test scope
  names. Order and count are kept, which is all a consent UI needs to
  show the shape of the graph.
- anyone else, and any signer asking about an id the gateway does not hold:
  404, indistinguishable, so a wallet cannot enumerate which data point ids
  exist. A grantee whose grant does not cover the root gets the same 404.

Response:

```json
{
  "data": {
    "dataPointId": "0xd3f1...aa",
    "scope": "spine.health.summary",
    "version": "3",
    "deletedAt": null,
    "sources": [
      {
        "dataPointId": "0x5b1a...9c",
        "scope": "chatgpt.conversations",
        "version": "12",
        "deletedAt": null
      },
      { "redacted": true }
    ],
    "derivatives": [
      {
        "dataPointId": "0x41c0...7e",
        "scope": "coach.weekly",
        "version": "1",
        "deletedAt": "2026-08-30T18:00:00.000Z"
      }
    ]
  },
  "proof": {
    "userSignature": "0x...",
    "gatewaySignature": "0x...",
    "timestamp": 1756630000,
    "status": "confirmed",
    "estimatedConfirmation": null,
    "chainBlockHeight": 123456
  }
}
```

- `ownerAddress` is the data point owner; every node in the view belongs to
  the same owner.
- `version` is the derived record's version whose lineage is shown. Without
  a path version it is the current version; when the current version is a
  tombstone it is the last data (non-tombstone) version below it (so a
  deleted derivative still exposes what it came from, and never anything
  older: a version registered without lineage is a root and stays one).
  `/lineage/N` selects a specific version and 404s when that version does
  not exist or failed on chain.
- `sources[].version` is the source's current version, `deletedAt` its
  tombstone time or null. A source whose registration no longer exists (its
  only version failed on chain and was rolled back after the derivative cited
  it) keeps its scope and is served with `version: "0"`.
- `derivatives` lists the same owner's data points whose effective lineage
  cites this id: their current version, or for a deleted derivative the
  version its tombstone replaced (`deletedAt` set). A newer version
  registered without lineage, or with a lineage that dropped this source,
  ends the relationship; `version` is the citing version. `derivatives` is
  always the current reverse lineage, whichever version of the root is
  shown: `/lineage/N` answers what version N came from and what is built on
  the data point now, not who cited it at that time.
  At most 1000 derivatives are listed (lowest ids first); when more exist
  the view carries `derivativesTruncated: true`, bound into the response hash
  (appended as a `bool` only when set). Pagination is not part of this
  slice.
- `proof` is the standard gateway attestation (`GatewayAttestation` EIP-712,
  `userSignature` = the data point's AddData signature) over:
  - `requestHash = keccak256(abi.encode(string "GET /v1/data/:dataPointId/lineage", bytes32 dataPointId, uint256 version, bytes32 grantId))`
    with `version` 0 when no path version was given and `grantId` the grant
    CLAIMED by the request (bytes32 zero when no claim was sent), so the
    client can always recompute it; a grant view also carries `data.grantId`,
    the grant that decided the redactions (claimed, or selected for a builder
    that made no claim), appended to the response hash as `bytes32` only when
    set, before the `derivativesTruncated` bool; `userSignature`, `status` and `chainBlockHeight`
    in the proof are those of the requested version for `/lineage/N`,
    otherwise the head's (for a tombstoned head, the tombstone registration,
    whose lineage is shown from the data version it replaced);
  - `responseHash = keccak256(abi.encode(bytes32 dataPointId, address ownerAddress, string scope, uint256 version, uint256 deletedAt, bytes32 sourcesHash, bytes32 derivativesHash))`
    where `deletedAt` is unix seconds (0 when null), each list hash is
    `keccak256(abi.encode(bytes32[] nodeHashes))` in response order, a
    visible node hashes as
    `keccak256(abi.encode(bytes32 dataPointId, string scope, uint256 version, uint256 deletedAt))`
    and a redacted node as
    `keccak256(abi.encode(string "redacted", uint256 position))` where
    position is its index in the list, so the proof binds count and order
    without carrying an identifier.
    The gateway signs the view it served, so a redacted view verifies on its
    own and un-redacting or dropping a node breaks the proof.

| Status | When                                                                                                                        |
| ------ | --------------------------------------------------------------------------------------------------------------------------- |
| 400    | malformed id or version, or a query string (the endpoint takes none)                                                        |
| 401    | missing or invalid request signature                                                                                        |
| 403    | owner or registered server asked for a `grantId` that is not a live grant of the owner, or one that does not cover the root |
| 404    | unknown data point, unknown or failed version, or a signer with no live covering grant (indistinguishable from unknown)     |

### Personal Server

```http
GET /v1/data/:scope/lineage[/:version]
```

Same authentication as `GET /v1/data/:scope`: the owner, or a builder with
`Authorization: Web3Signed ...` whose grant (from the payload's `grantId`
claim, `?grantId=` or `X-PS-Grant-Id`) covers `:scope`. The signed `uri` is
the request path without a query string, as for every Personal Server read;
the version is a path segment so it is inside the signed uri (a signature for
`/lineage/2` is refused on `/lineage/3`), and any query string is rejected with 400 (`?version=` as `INVALID_VERSION`, anything else as `INVALID_QUERY`). The server resolves `dataPointId = keccak256(owner, scope)`, calls the
gateway endpoint signed with its server key (same path version), passes the
builder's `grantId` as the signed claim so the gateway attests the redacted
view, and returns the gateway response body unchanged (`data` + `proof`).
Owners get the full view.

| Status    | errorCode               | When                                                                            |
| --------- | ----------------------- | ------------------------------------------------------------------------------- |
| 400       | `INVALID_QUERY`         | any query string; version is a path segment, the grant view is the signed claim |
| 401 / 403 | (existing read errors)  | not the owner and no covering grant                                             |
| 404       | `NOT_FOUND`             | the scope is not registered at the gateway yet                                  |
| 502       | `LINEAGE_GATEWAY_ERROR` | the gateway returned an error                                                   |
| 503       | `LINEAGE_UNAVAILABLE`   | this server has no gateway URL or signing key                                   |

Lineage is served from the gateway, so a derivative becomes walkable once its
registration has synced (the ingest response reports `status: "syncing"`).
The Personal Server's upload worker registers a derivative at the gateway
with the `lineage` from its `$lineage` (see "Gateway write" below); the
gateway requires the sources to be registered first, so a derivative whose
source has not synced yet is retried on the next sync cycle.

## Delete

`DELETE /v1/data/:scope` keeps its single-node behaviour: a durable delete
(gateway tombstone, then the ciphertext of every covered version, then the
local copy) answering 200 with a per-step result. Deleting a derivative never
touches its sources.

`?cascade=lineage` is specified here and NOT implemented in this slice: the
Personal Server answers 501 `LINEAGE_CASCADE_UNAVAILABLE` for it today. The
single-scope durable delete exists; what is missing is the lineage walk that
finds every derivative. The cascade must tombstone every derivative at the
gateway, and DPv2 deletion
(gateway tombstone, then ciphertext, then the local copy) is separate work
that no current runtime has; a cascade that only removed local copies would
report derivatives deleted while their gateway records and ciphertext remain
and sync could bring them back. Once durable deletion lands the cascade is:

```http
DELETE /v1/data/chatgpt.conversations?cascade=lineage
```

```json
{
  "scope": "chatgpt.conversations",
  "cascade": "lineage",
  "deleted": [
    { "dataPointId": "0x41c0...7e", "scope": "coach.weekly" },
    { "dataPointId": "0xd3f1...aa", "scope": "spine.health.summary" },
    { "dataPointId": "0x5b1a...9c", "scope": "chatgpt.conversations" }
  ]
}
```

Owner only. The server walks the gateway lineage graph from the scope's data
point (owner view, signed as the server), deepest derivatives first, and
deletes each node durably, then the scope itself. The whole walk completes
before anything is deleted; a gateway failure, an oversize graph or a
foreign-owner node aborts with nothing removed. Nodes already deleted at the
gateway are skipped.

| Status | errorCode                     | When                                                              |
| ------ | ----------------------------- | ----------------------------------------------------------------- |
| 200    |                               | cascade completed; `deleted` lists the nodes in deletion order    |
| 400    | `INVALID_CASCADE`             | `cascade` is set to anything but `lineage`                        |
| 409    | `LINEAGE_CROSS_OWNER`         | a node in the walk has a different owner; nothing deleted         |
| 501    | `LINEAGE_CASCADE_UNAVAILABLE` | this server has no durable delete (every current runtime)         |
| 502    | `LINEAGE_GATEWAY_ERROR`       | the walk failed at the gateway; nothing was deleted               |
| 502    | `LINEAGE_CASCADE_INCOMPLETE`  | a node's tombstone did not land; `details.deleted` lists what did |

## Gateway write (for clients that register directly)

`POST /v1/data` accepts an optional `lineage: string[]` next to the existing
AddData fields, together with `lineageSignature`:

```json
{
  "ownerAddress": "0x...",
  "scope": "spine.health.summary",
  "dataHash": "0x...",
  "metadataHash": "0x...",
  "expectedVersion": "3",
  "lineage": ["0x5b1a...9c", "0x9e77...02"],
  "lineageSignature": "0x..."
}
```

The signed EIP-712 AddData struct is unchanged. The on-chain commitment to
the lineage is `dataHash` (the Personal Server hashes the plaintext envelope,
`$lineage` included), which the gateway cannot open. The plaintext list the
gateway stores for `(dataPointId, expectedVersion)` therefore carries its own
proof of authorship, `lineageSignature`: an EIP-712 signature under the same
DataRegistry domain as AddData over

```
LineageAttestation {
  address   ownerAddress;
  string    scope;
  uint256   expectedVersion;
  bytes32   dataHash;
  bytes32[] sources;   // lowercase ids, registered order
}
```

signed by the owner or one of the owner's active servers: registered,
confirmed or finalized, paid and unrevoked, the same bar a server has to
clear to read lineage. Why a second signature: the AddData signature is public (every
gateway attestation carries it as `userSignature`), and a still-pending
version accepts a same-version refresh, so without the attestation anyone
could replay a registration with a different lineage. The Personal Server's
upload worker produces this signature with the server key.

The gateway validates the same things the Personal Server does (shape,
naming rule, every source is an existing data point of `ownerAddress`,
deleted allowed) and answers 400 `LINEAGE_INVALID` /
`LINEAGE_SCOPE_UNDER_SOURCE_PREFIX`, 401 `LINEAGE_SIGNATURE_REQUIRED` /
`LINEAGE_SIGNATURE_INVALID`, or 422 `LINEAGE_SOURCE_UNKNOWN`
(`unknown: [...]`); error bodies are the gateway's usual
`{ success: false, error, code }`. A tombstone version cannot carry lineage.
The 201 response echoes `lineage` (`[]` when the request made no lineage
statement).

`lineage` absent (or `null`) is "no lineage statement": a fresh version is a
root, and a same-version refresh of a still-pending version keeps whatever
lineage the slot holds while its `dataHash` is unchanged (a re-sign, a
replay, or a metadata-only refresh: the attestation binds `dataHash`, not
`metadataHash`); a refresh that commits to a different `dataHash` clears
it. An array, the empty array included, is a statement
and needs `lineageSignature`: a refresh that carries one replaces the slot's
lineage together with the payload (`[]` clears it: an attested root). The
201 echoes `lineage` as sent (lowercased) or `null` when no statement was
made. A tombstone version never carries lineage; a tombstone that refreshes
a pending data slot clears it. Once the version is in flight or settled the
refresh is refused as today, so registered lineage is immutable.

## Compute (question to derivative)

The compute layer lets a builder register a QUESTION over the owner's source
scopes and have the Personal Server answer it locally. The answer is written
as an ordinary derivative record (everything above applies unchanged) into a
derived scope the builder may write; the builder then reads it through its
normal read grant, which needs a BARE read entry for the derived scope on
top of the `write:` entry (see "The grant a builder needs" below). The raw
source data never leaves the Personal Server except through the inference
call.

Consent for a builder question is read on every source scope plus write on
the derived scope, from the same grant. The answer is whatever the model
returns from the sources, and a question can ask for the sources verbatim,
so a builder that may read the derived scope can read anything the prompt
saw. The system prompt is not a security boundary; the grant is. A source
scope that the builder's grant does not cover with a bare read entry
(`write:` entries do not count) refuses the registration with 403
`DERIVATIVE_SOURCE_NOT_GRANTED` listing the uncovered scope names, and the
same check runs against the live grant before every compute, so a grant
that is later narrowed fails the question closed without an inference call.
Owner registrations are not subject to it. What the builder does not need
is a SEPARATE grant for the sources: one grant carries the whole flow.

### The grant a builder needs

The read policy matches a requested scope against the grant's entries
verbatim, and a requested scope never carries the `write:` prefix, so a
`write:` entry can never satisfy a read. Three kinds of entry are therefore
needed, in one grant:

| Entry                      | What it is for                                   |
| -------------------------- | ------------------------------------------------ |
| bare read on each source   | registering the question and every recompute     |
| bare read on derived scope | reading the answer back with `GET /v1/data/...`  |
| `write:<derivedScope>`     | registering, and the question API's builder auth |

```json
{
  "scopes": [
    "oura.sleep",
    "chatgpt.conversations",
    "coach.weekly",
    "write:coach.weekly"
  ]
}
```

Leaving out the bare `coach.weekly` entry is the common mistake: the
question registers and computes, and then the read of the answer fails with
`SCOPE_MISMATCH` because `write:coach.weekly` grants no read. Patterns work
in both positions (`coach.*` and `write:coach.*`).

What runs where:

1. the builder registers
   `{ derivedScope, sourceScopes, question, model?, recompute? }`;
2. the Personal Server reads the sources from LOCAL storage, trims them,
   assembles a prompt, calls the inference provider and writes the answer
   into `derivedScope` with lineage = the source data point ids;
3. every time a source scope gets a new local version (ingest or sync) the
   question is marked `stale` and recomputed after a quiet period, unless
   it was registered with `recompute: "snapshot"`;
4. the builder polls the question for `ready`, then reads `derivedScope`.

### Endpoints

All under `/v1/derivatives`. Authentication for a builder is the Write API's
(no new credential): the write-session bearer token from
`POST /v1/write/session` plus the `X-Vana-Write-Signature` proof over the
request, authorized for `write:<derivedScope>` exactly like a write to that
scope. A JSON body must be the compact serialization of its own value
(`JSON.stringify` output; pretty-printed bodies are refused with 400
`WRITE_BODY_NOT_CANONICAL`, as on the write path). Registration bodies are
capped at 16 KB (413). The owner uses any owner credential. PS-Lite serves the
same routes with the same credential: it mounts `POST /v1/write/session` and
runs the identical authorization code, so a builder registers questions
against a browser-hosted Personal Server exactly as it does against the Node
build. Its sessions and proof-replay memory are in-process (as the Node
build's are), so a reload of the hosting tab ends live sessions and the
builder re-handshakes.

Two rules about the proof matter on these routes.

**The signed `uri` covers the query string.** The list route authorizes the
caller against `?derivedScope=`, so the proof must commit to it: sign
`pathname + search`, not the bare path. A proof that signed only the path is
refused on a request that carries a query (401
`WRITE_ATTRIBUTION_INVALID`), and a proof signed for one derived scope does
not authorize a list of another. Parameter ORDER does not matter (the server
compares a canonical form, parameters sorted by name and then value), but
the parameters themselves must match. Requests with no query string sign the
bare path exactly as before.

**Polling needs a `nonce` claim.** A proof payload is otherwise fully
determined by `{aud, method, uri, bodyHash, grantId, iat, exp}`, so two
identical `GET /questions/:id` polls signed in the same second are
byte-identical and the second is refused as a replay (401
`WRITE_ATTRIBUTION_REPLAY`). Add an optional `nonce` claim to the signed
payload (any unique string of 1 to 128 characters; a uuid is the intended
shape) and each call is distinct. The nonce itself is then single use:
re-using one is a replay even if the rest of the payload changed. Without a
nonce the whole proof is the replay key, so the fallback for a client that
cannot add claims is to vary one it already sends: give each call its own
`exp` (unbounded going forward), or an `iat` a second apart (a future `iat`
is rejected beyond 60s of skew, so count backwards). Signed payload with a nonce:

```json
{
  "aud": "https://ps.example.com",
  "bodyHash": "sha256:e3b0...b855",
  "exp": 1787654621,
  "grantId": "0x...",
  "iat": 1787654321,
  "method": "GET",
  "nonce": "8a1f0c2e-...",
  "uri": "/v1/derivatives/questions/5f0c..."
}
```

(Claims are serialized with sorted keys, base64url-encoded and signed
EIP-191, exactly as without the nonce.)

| Method | Path                       | Who                                                       | Result                               |
| ------ | -------------------------- | --------------------------------------------------------- | ------------------------------------ |
| POST   | `/questions`               | builder (`write:<derivedScope>`) or owner                 | 201 registration view                |
| GET    | `/questions`               | owner; builder with `?derivedScope=` (own questions only) | `{ questions: [...] }`               |
| GET    | `/questions/:id`           | owner or the registering builder                          | registration view                    |
| POST   | `/questions/:id/recompute` | owner or the registering builder                          | 202 registration view, recompute now |
| DELETE | `/questions/:id`           | owner or the registering builder                          | `{ questionId, deleted: true }`      |

Every route but DELETE answers with the same registration view, so a client
needs one schema. The 202 from `recompute` carries the status the scheduled
run starts from: `pending` for a question that never computed, `stale`
otherwise.

Registration body:

```json
{
  "derivedScope": "coach.weekly",
  "sourceScopes": ["chatgpt.conversations", "oura.sleep"],
  "question": "How did my sleep relate to my mood this week?",
  "model": "z-ai/glm-5.2",
  "recompute": "snapshot"
}
```

`model` is optional (the server default applies). `recompute` is optional
too: `"on-change"` (the default) recomputes on every source change, while
`"snapshot"` computes once at registration and afterwards only on an
explicit `POST /questions/:id/recompute`; any other value is 400
`DERIVATIVE_QUESTION_INVALID`. Validation, in order:
scopes follow the scope grammar; 1 to 16 distinct source scopes, none equal
to the derived scope; `question` is 1 to 8000 characters; the naming rule
(the derived scope must not share its first segment with any source,
400 `LINEAGE_SCOPE_UNDER_SOURCE_PREFIX`); and the registration must not make
the derived scope a transitive source of itself through other registrations
(409 `DERIVATIVE_CYCLE`), which is what keeps recompute-on-refresh bounded.
Sources do not have to exist yet: a missing source fails the compute
("source scope X has no local data") and the question recomputes once the
scope arrives.

Registration view (POST, GET, list and recompute):

```json
{
  "questionId": "5f0c...",
  "derivedScope": "coach.weekly",
  "sourceScopes": ["chatgpt.conversations", "oura.sleep"],
  "question": "...",
  "model": null,
  "recompute": "on-change",
  "registeredBy": { "kind": "builder", "builder": "0x...", "grantId": "0x..." },
  "status": "ready",
  "error": null,
  "createdAt": "...",
  "updatedAt": "...",
  "lastComputedAt": "2026-08-31T09:12:44.000Z",
  "derivedVersion": 3,
  "derivedCollectedAt": "2026-08-31T09:12:44Z"
}
```

A builder that did not register a question (even one holding a write grant
on the same scope) gets 404 for it, and so does an unknown id: any caller
that presents a live write session (or owner credentials) gets 404 rather
than 401, which would send a client with a re-handshake-on-401 policy
through a pointless handshake and then report the wrong problem. A caller
with no credentials still gets 401. A builder that calls `GET /questions`
with no `?derivedScope=` gets 400 `DERIVATIVE_DERIVED_SCOPE_REQUIRED` for
the same reason: the unfiltered list is the owner's. Registrations are local
to the Personal Server that holds them (they never sync); that replica
computes.

| Status | errorCode                           | When                                                                 |
| ------ | ----------------------------------- | -------------------------------------------------------------------- |
| 400    | `DERIVATIVE_QUESTION_INVALID`       | body shape, scope grammar, limits                                    |
| 400    | `LINEAGE_SCOPE_UNDER_SOURCE_PREFIX` | naming rule                                                          |
| 400    | `DERIVATIVE_DERIVED_SCOPE_REQUIRED` | builder list call with no `?derivedScope=`                           |
| 401    | `WRITE_ATTRIBUTION_INVALID`         | the proof does not cover this exact request (uri, query included)    |
| 401    | `WRITE_ATTRIBUTION_REPLAY`          | the proof, or its nonce, was already used                            |
| 403    | `DERIVATIVE_SOURCE_NOT_GRANTED`     | a source scope is not read-granted to the builder (`details.scopes`) |
| 404    | `DERIVATIVE_QUESTION_NOT_FOUND`     | unknown id, or not this builder's question                           |
| 409    | `DERIVATIVE_CYCLE`                  | the registration would make the derived scope its own source         |
| 413    | `CONTENT_TOO_LARGE`                 | registration body over 16 KB                                         |
| 503    | `DERIVATIVE_COMPUTE_UNAVAILABLE`    | the server has no compute layer wired                                |

### Observing a question as the reader

`GET /v1/derivatives/status?derivedScope=<scope>` is the lifecycle view for
the party that will READ the answer — the consent-flow app that holds only
a bare read entry on the derived scope and therefore can never open a write
session. Authorization is the data read's (a live grant covering the scope,
or the owner); nothing is served and nothing is charged, the same bar as
the lineage read. Without it a reader polling `GET /v1/data/<scope>` cannot
tell "computing right now" (404) from "failed and will never retry" (also
404).

```http
GET /v1/derivatives/status?derivedScope=coach.weekly
Authorization: Web3Signed <base64url(payload)>.<sig>
```

```json
{
  "derivedScope": "coach.weekly",
  "status": "failed",
  "lastComputedAt": "2026-08-31T09:12:44.000Z",
  "derivedVersion": 3,
  "derivedCollectedAt": "2026-08-31T09:12:44Z",
  "errorCode": "inference_unavailable",
  "retryAfterSeconds": 300
}
```

The view is deliberately narrow: the question text, the source scopes, the
question id, the registrar and the raw `error` string stay owner-only.
`errorCode` is the closed vocabulary above. `retryAfterSeconds` is the next
automatic retry the scheduler has pending (null when none) — poll on that
cadence instead of guessing. When several registrations share the derived
scope, the most recently updated one answers. A covered scope with no
question behind it is 404; an uncovered scope is refused before any lookup,
so the route discloses nothing about which scopes have questions.

### Status machine

```
pending --compute ok--> ready
pending --compute err-> failed
ready | failed --source scope changed / owner recompute--> stale
stale --compute ok--> ready
stale --compute err-> failed
```

`pending` is "never computed"; it stays `pending` while scheduled. A source
change during a running compute makes the scheduler run once more when it
finishes (one compute in flight per question, changes coalesce). Recompute
after a change waits `inference.recomputeDebounceMs` (default 5000);
`POST /recompute` (owner, or the registering builder retrying after a
failure) runs immediately. A question registered with
`recompute: "snapshot"` never takes the source-change edge: it computes at
registration and on `POST /recompute` only. On boot the server reschedules
every question a previous run left `pending` or `stale`. `failed` carries a short `error` (a status code,
a scope name, an error class); the prompt and the data are never stored in
it.

Retry policy inside one compute: a transient inference failure (no
response, 429, 5xx) and a transient gateway failure during the grant check
are retried up to three attempts with backoff (1s, 4s); protocol failures
(a revoked grant, an uncovered source, a 4xx from the provider) fail closed
at once.

Failures are classified into `errorCode`, a CLOSED vocabulary stored next
to the free-text `error` and safe to serve to readers (it never carries a
scope name, the question or provider detail):

| `errorCode`             | Meaning                                          |
| ----------------------- | ------------------------------------------------ |
| `inference_unavailable` | transient provider/relay failure (retried)       |
| `source_missing`        | a source scope is deleted or has no local data   |
| `grant_invalid`         | the registering builder's grant no longer covers |
| `internal`              | anything else, including permanent provider 4xx  |

`inference_unavailable` is the one transient class: after the in-compute
attempts are spent, the scheduler retries the question on a backoff
schedule (default 1m, 5m, 30m; in-memory, so a restart drops the chain).
Every other class — and an exhausted backoff — leaves the question
`failed` until the next source change or `POST /recompute`.

Before a compute of a builder-registered question the server re-runs the
write policy against the live grant and the read coverage of every source:
a revoked, expired or narrowed grant fails the question
(`GRANT_REVOKED: ...`, `DERIVATIVE_SOURCE_NOT_GRANTED: ...`) without an
inference call. A builder question on a server with no grant verifier
wired fails closed the same way.

Two more guards run before the provider is called. A source scope the
gateway reports deleted is refused exactly like a read would refuse it
(410 on the read path): "source scope X is deleted", stale local copy or
not. And the stored `$lineage` of every source is walked through the local
index; if it reaches the question's own derived data point id the compute
fails with `DERIVATIVE_CYCLE`. That covers cycles the per-store check at
registration cannot see (two replicas each holding one half, syncing each
other's output); the scheduler also ignores a synced version whose lineage
descends from the question's own derived scope.

Chains: the compute path writes through the owner ingest contract, not
HTTP, so it notifies the scheduler itself; a question that reads a derived
scope recomputes when that scope is recomputed (A -> B -> C).

### Trim rule and prompt

For each source scope the latest local version is read. A record whose
`data` is an array is trimmed to the newest `inference.maxSourceItems`
(default 50) items; a record object has each top-level array trimmed the
same way and keeps its other keys; the server-stamped `$lineage`,
`$writtenBy` and `$binary` keys are dropped, and a binary record contributes
only a marker (its bytes are not sent). "Newest" uses the item's own
timestamp field when it has one (`createdAt`, `create_time`, `timestamp`,
`date`, ...); items without one are taken from the end of the array. When a
source still exceeds 200000 characters serialized, the item budget is halved
until it fits, and as a last resort the serialization is cut.

The prompt is two messages: a fixed system prompt (answer strictly from the
provided user data, reply as a JSON object with `answer` and `evidence`)
and a user message with the question followed by one section per source
(`### Scope: <scope> (newest k of n items)`, the collectedAt, the trimmed
JSON). The reply is parsed as JSON (a fenced block or surrounding prose is
tolerated); when no object parses the whole text is the answer.

### The derived record

Written through the owner ingest path (no `$writtenBy`), with
`$lineage.sources` = `keccak256(owner, sourceScope)` for every source scope
in registration order and `writtenAt` = the compute time. The record body:

```json
{
  "questionId": "5f0c...",
  "question": "How did my sleep relate to my mood this week?",
  "answer": "...",
  "evidence": "...",
  "model": "z-ai/glm-5.2",
  "computedAt": "2026-08-31T09:12:44.000Z",
  "sources": [
    { "scope": "chatgpt.conversations", "version": 12, "collectedAt": "..." },
    { "scope": "oura.sleep", "version": 4, "collectedAt": "..." }
  ],
  "lineage": ["0x5b1a...9c", "0x9e77...02"],
  "inference": { "receiptId": "...", "aciIdentity": "..." },
  "$lineage": { "sources": ["0x5b1a...9c", "0x9e77...02"], "writtenAt": "..." }
}
```

`sources[].version` is the local index version of each source at compute
time (lineage itself is version-less, see "Identifiers"). `inference` is
present when the provider returned `x-receipt-id` / `x-aci-identity`. The
record carries the lineage twice on purpose, the same way an HTTP
derivative does: `lineage` is the caller-side field (here the compute
job's claim, for a builder write the signed claim) and `$lineage` is the
server-validated stamp that the upload worker registers; readers should
trust `$lineage`. The
record then syncs, uploads and registers with its lineage like any other
derivative; the builder reads it with a read grant on `derivedScope`, which
confers nothing on the sources.

### Inference provider and config

The provider is an OpenAI-compatible chat completions client over `fetch`
(Node and browser). Config (`config.json`, also the PS-Lite config):

| Key                             | Default                          | Meaning                                                              |
| ------------------------------- | -------------------------------- | -------------------------------------------------------------------- |
| `inference.baseUrl`             | `https://inference.phala.com/v1` | chat completions base; set to the Vana inference relay in production |
| `inference.model`               | `z-ai/glm-5.2`                   | default model                                                        |
| `inference.e2ee`                | `true`                           | end to end encryption of prompt and answer to the Phala gateway      |
| `inference.maxSourceItems`      | `50`                             | newest items kept per source scope                                   |
| `inference.recomputeDebounceMs` | `5000`                           | quiet period after a source change                                   |

Environment overrides (Node server only): `INFERENCE_BASE_URL`,
`INFERENCE_MODEL`, `INFERENCE_E2EE` (`false` turns encryption off), and
`INFERENCE_API_KEY` for local development against a provider directly (sent
as `Authorization: Bearer`; in production the relay holds the key and the
Personal Server sends no key).

The Personal Server authenticates to the Vana inference relay
(`POST /v1/inference/chat/completions` on the data gateway) as itself: every
relay call carries `Authorization: Web3Signed ...`, the same scheme and the
same request signer the lineage read uses, over `aud` (the relay origin),
the method, the path, and `bodyHash`, the SHA-256 of the exact body bytes
sent. The Node server signs with the server key, PS-Lite with the browser
identity key that registered it; the relay checks that the signer is the
owner or one of the owner's active registered servers and forwards nothing
otherwise (401 without a valid signature, 403 without a live registration).
The attested-key fetch through the relay is signed the same way (GET, no
body, the nonce inside the signed path); the direct Phala fallback is
unsigned. `INFERENCE_API_KEY` is the local-development alternative and wins:
a bearer key means the base URL is a provider, not the relay, so no
signature is produced. Nothing else about the request changes, and a signer
that cannot sign fails the compute without sending anything.

PS-Lite never calls a provider directly: with `inference.baseUrl` left at
the direct-provider default the compute layer stays off and
`/v1/derivatives` answers 503 `DERIVATIVE_COMPUTE_UNAVAILABLE`; set it to
the relay. Deactivating the runtime stops the scheduler; activating it
reschedules `pending` and `stale` questions.

Every request carries `provider: { aci_verified: true, zdr: true }` and
`max_tokens` (2048); the response headers `x-receipt-id` and
`x-aci-identity` are passed through into the record. A non-2xx reply fails
the question with the status only; an empty assistant reply is a failure
too, never a `ready` record.

### End to end encryption to Phala

With `inference.e2ee: true` (the default) the prompt and the answer are
encrypted between the Personal Server and the Phala confidential-inference
gateway with the E2EE v2 protocol
(https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/e2ee-v2.md),
suite `x25519-aes-256-gcm-hkdf-sha256`. The Vana inference relay in between
forwards ciphertext; it cannot read the owner's data, the question, or the
answer. Set `inference.e2ee: false` (or `INFERENCE_E2EE=false` on the Node
server) only for local development against a provider without ACI
attestation: the compute layer then sends plaintext over TLS and logs a
warning at startup.

Per request:

1. The gateway's attested E2EE key is fetched with
   `GET {inference.baseUrl}/aci/attestation?nonce=<64 hex>` (through the
   relay, which must pass the route through unchanged; when the relay
   answers 404 the report is fetched from `https://inference.phala.com/v1`
   directly). The report is verified structurally before the key is used:
   `sha256(JCS(workload_keyset))` must equal `workload_keyset_digest`, the
   ACI statement built from that digest and our nonce must hash to
   `report_data` (freshness and keyset binding), the TDX quote's report-data
   slot must carry it, the keyset must not be expired, and the service must
   advertise E2EE version 2. The X25519 entry (`dstack-kms-e2ee-x25519-v1`
   on the Phala gateway) is selected by `algo`. No verified key, no request.
   The key is cached for five minutes and re-fetched after
   `e2ee_model_key_mismatch` or a changed `X-ACI-Keyset-Digest`.
2. A fresh client X25519 key pair, a 32-byte nonce and the Unix-seconds
   timestamp are generated; the request carries `X-E2EE-Version: 2`,
   `X-Client-Pub-Key`, `X-Model-Pub-Key`, `X-E2EE-Nonce`, and
   `X-E2EE-Timestamp`.
3. Every `messages[i].content` is replaced by the hex encoding of
   `ephemeral_pub || aes_gcm_nonce || ciphertext || tag`, each field under a
   fresh ephemeral key, keyed by HKDF-SHA256 over the X25519 shared secret,
   with the RFC 8785 canonical JSON of `{purpose, algo, model, field, nonce,
ts}` as associated data, so a ciphertext cannot be moved to another
   field, request or model.
4. The gateway decrypts inside the enclave, runs the model, and encrypts
   `choices[0].message.content` to the client key under the response AAD
   (which also binds the clear response `id`). The Personal Server decrypts
   and stores the answer; a reply that is not valid ciphertext for this
   request (a plaintext reply, a swapped id, a tampered field) fails the
   compute and is never stored.

What the relay still sees: the model name, the number of messages and the
size of each ciphertext (roughly the prompt size), the request timing, the
`provider` routing hint, `max_tokens`, the E2EE headers (public keys, nonce,
timestamp), and the response headers (`x-receipt-id`, `x-aci-identity`,
`X-ACI-Keyset-Digest`, token usage). Failure messages stored on a question
carry the E2EE error code only, never a prompt or an answer.

Caveat: the E2EE key belongs to the Phala gateway enclave (an aggregator),
not to the model backend behind it; encryption between the gateway and the
upstream is the gateway's own channel binding, attested in its report. The
structural checks above establish that the key is the one the hardware quote
bound; verification of the TDX quote itself against the Intel root is a
`verifyEvidence` hook on `createPhalaE2eeEncryption` that the Node server
does not wire yet (a DCAP verifier such as `@phala/aci-verifier` can be
plugged in there).

Manual smoke test against a real gateway: `npm run e2ee:smoke` sends one
encrypted request to `INFERENCE_BASE_URL` (default
`https://inference.phala.com/v1`, model `INFERENCE_MODEL`, optional
`INFERENCE_API_KEY`) and prints only the receipt id and the answer length.

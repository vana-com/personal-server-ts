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

Not in this slice: compute inside the Personal Server, context queries, TEE
hosting, snapshot / view semantics. The interpretation runs outside Vana and
writes its results back through the Write API.

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
  not cover are returned as `{ "dataPointId": "0x...", "redacted": true }`,
  so a consent UI can show the shape of the graph without learning the
  scopes.
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
      { "dataPointId": "0x9e77...02", "redacted": true }
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
    with `version` 0 when no path version was given and `grantId` bytes32
    zero for the full view; `userSignature`, `status` and `chainBlockHeight`
    in the proof are those of the requested version for `/lineage/N`,
    otherwise the head's (for a tombstoned head, the tombstone registration,
    whose lineage is shown from the data version it replaced);
  - `responseHash = keccak256(abi.encode(bytes32 dataPointId, address ownerAddress, string scope, uint256 version, uint256 deletedAt, bytes32 sourcesHash, bytes32 derivativesHash))`
    where `deletedAt` is unix seconds (0 when null), each list hash is
    `keccak256(abi.encode(bytes32[] nodeHashes))` in response order, a
    visible node hashes as
    `keccak256(abi.encode(bytes32 dataPointId, string scope, uint256 version, uint256 deletedAt))`
    and a redacted node as
    `keccak256(abi.encode(bytes32 dataPointId, string "redacted"))`.
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

`DELETE /v1/data/:scope` keeps its single-node behaviour (204, the scope's
local copy, blobs and gateway record). Deleting a derivative never touches
its sources.

`?cascade=lineage` is specified here and NOT implemented in this slice: the
Personal Server answers 501 `LINEAGE_CASCADE_UNAVAILABLE` for it today. The
cascade must tombstone every derivative at the gateway, and DPv2 deletion
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

signed by the owner or one of the owner's registered servers (the same rule
as AddData). Why a second signature: the AddData signature is public (every
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
lineage the slot holds while its payload hashes are unchanged (a re-sign or
a replay); a refresh that commits to different hashes clears it. An array, the empty array included, is a statement
and needs `lineageSignature`: a refresh that carries one replaces the slot's
lineage together with the payload (`[]` clears it: an attested root). The
201 echoes `lineage` as sent (lowercased) or `null` when no statement was
made. A tombstone version never carries lineage; a tombstone that refreshes
a pending data slot clears it. Once the version is in flight or settled the
refresh is refused as today, so registered lineage is immutable.

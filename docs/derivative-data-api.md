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

Because `$lineage` lives inside `data`, `metadataHash` (unchanged definition:
the commitment the Personal Server computes over the envelope) now commits to
the lineage as well. The on-chain AddData struct is untouched.

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
   `LINEAGE_INVALID`. A `null` or absent `lineage` is a root record.
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
GET /v1/data/:dataPointId/lineage[?version=N][&grantId=0x...]
Authorization: Web3Signed <base64url(payload)>.<sig>
```

Authentication is the request-signing scheme the Personal Server already
uses (EIP-191 over a base64url JSON payload with `aud`, `method`, `uri`,
`bodyHash`, `iat`, `exp`): `aud` is the gateway origin, `method` is `GET`,
`uri` is the request path without the query string, `bodyHash` is the hash of
an empty body. The signer decides the view:

- the data point's owner, or one of the owner's registered servers: full
  view. With `?grantId=` the response is instead the view that grant sees
  (the grant must be issued by this owner), attested as such; this is how a
  Personal Server serves a builder.
- a registered builder holding a live grant from the owner that covers the
  data point's scope: the view for that grant. Nodes whose scope the grant
  does not cover are returned as `{ "dataPointId": "0x...", "redacted": true }`,
  so a consent UI can show the shape of the graph without learning the
  scopes.
- anyone else: 403.

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

- `version` is the derived record's version whose lineage is shown. Without
  `?version=` it is the current version; when the current version is a
  tombstone it is the last version that carried lineage (so a deleted
  derivative still exposes what it came from). `?version=N` selects a specific
  version and 404s when that version does not exist.
- `sources[].version` is the source's current version, `deletedAt` its
  tombstone time or null.
- `derivatives` lists every data point of the same owner that cites this id in
  any of its versions; `version` is the latest citing version, `deletedAt` the
  derivative's current tombstone time or null.
- `proof` is the standard gateway attestation over
  `requestHash = keccak256(abi.encode("GET /v1/data/:dataPointId/lineage", dataPointId, version, grantId))`
  (`version` 0 and `grantId` bytes32 zero when not given) and a `responseHash`
  over the node list exactly as returned, redactions included. The gateway
  signs the view it served, so a redacted view verifies on its own.

| Status | When                                                                                                        |
| ------ | ----------------------------------------------------------------------------------------------------------- |
| 400    | malformed id, `version` or `grantId`                                                                        |
| 401    | missing or invalid request signature                                                                        |
| 403    | signer is neither owner, registered server nor a covering grantee; or `grantId` was not issued by the owner |
| 404    | unknown data point or version                                                                               |

### Personal Server

```http
GET /v1/data/:scope/lineage[?version=N]
```

Same authentication as `GET /v1/data/:scope`: the owner, or a builder with
`Authorization: Web3Signed ...` whose grant (from the payload's `grantId`
claim, `?grantId=` or `X-PS-Grant-Id`) covers `:scope`. The server resolves
`dataPointId = keccak256(owner, scope)`, calls the gateway endpoint signed
with its server key, passes the builder's `grantId` so the gateway attests the
redacted view, and returns the gateway response body unchanged (`data` +
`proof`). Owners get the full view.

| Status    | errorCode               | When                                           |
| --------- | ----------------------- | ---------------------------------------------- |
| 401 / 403 | (existing read errors)  | not the owner and no covering grant            |
| 404       | `NOT_FOUND`             | the scope is not registered at the gateway yet |
| 502       | `LINEAGE_GATEWAY_ERROR` | the gateway returned an error                  |
| 503       | `LINEAGE_UNAVAILABLE`   | this server has no gateway URL or signing key  |

Lineage is served from the gateway, so a derivative becomes walkable once its
registration has synced (the ingest response reports `status: "syncing"`).
The Personal Server's upload worker registers a derivative at the gateway
with the `lineage` from its `$lineage` (see "Gateway write" below); the
gateway requires the sources to be registered first, so a derivative whose
source has not synced yet is retried on the next sync cycle.

## Delete

`DELETE /v1/data/:scope` keeps its single-node behaviour (204, the scope's
local copy, blobs and gateway record). Add `?cascade=lineage` to also delete
every derivative that lists the scope as a source, transitively:

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
point, deepest derivatives first, and refuses the whole operation with 409
`LINEAGE_CROSS_OWNER` if any node in the walk belongs to another owner
(cannot happen for lineage written through this API, checked anyway). Nodes
already deleted are skipped. Deleting a derivative never touches its
sources, with or without cascade.

| Status | errorCode                     | When                                                           |
| ------ | ----------------------------- | -------------------------------------------------------------- |
| 200    |                               | cascade completed; `deleted` lists the nodes in deletion order |
| 400    | `INVALID_CASCADE`             | `cascade` is set to anything but `lineage`                     |
| 409    | `LINEAGE_CROSS_OWNER`         | a node in the walk has a different owner                       |
| 501    | `LINEAGE_CASCADE_UNAVAILABLE` | this server cannot reach the gateway lineage graph             |
| 502    | `LINEAGE_GATEWAY_ERROR`       | the walk failed at the gateway; nothing was deleted            |

## Gateway write (for clients that register directly)

`POST /v1/data` accepts an optional `lineage: string[]` next to the existing
AddData fields:

```json
{
  "ownerAddress": "0x...",
  "scope": "spine.health.summary",
  "dataHash": "0x...",
  "metadataHash": "0x...",
  "expectedVersion": "3",
  "lineage": ["0x5b1a...9c", "0x9e77...02"]
}
```

The signed EIP-712 AddData struct is unchanged: the gateway stores lineage as
gateway-attested metadata for `(dataPointId, expectedVersion)`, and the
on-chain commitment to it is `metadataHash`, which the Personal Server
computed over data that includes `$lineage`. The gateway validates the same
things the Personal Server does (shape, naming rule, every source is an
existing data point of `ownerAddress`, deleted allowed) and answers 400
`LINEAGE_INVALID` / `LINEAGE_SCOPE_UNDER_SOURCE_PREFIX` or 422
`LINEAGE_SOURCE_UNKNOWN` (`unknown: [...]`). A tombstone version cannot carry
lineage. The 201 response echoes `lineage`.

A same-version refresh of a still-pending version replaces its lineage
together with its payload (absent lineage on the refresh makes it a root);
once the version is in flight or settled the refresh is refused as today, so
registered lineage is immutable.

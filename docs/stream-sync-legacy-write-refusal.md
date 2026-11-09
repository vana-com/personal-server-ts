# Refusing legacy writes after the stream-sync switch

Once an account has moved to stream sync, a legacy-format write from an app
version built before stream sync is refused with an update-your-app error. The
old app keeps its local records. This note lists every legacy write path in this
repository and says which ones the server can refuse.

## The check

- **One switch input.** The refusal applies while `streamSync.write` is on.
  Nothing else takes part in the decision. `streamSync.refuseLegacyWrites`
  stays in the config schema so stored configs still parse, but no code reads
  it. Hosts build one `AccountStorageMode` from `streamSync.write`
  (`packages/server/src/bootstrap.ts`, `packages/server/src/app.ts`,
  `packages/lite/src/browser-runtime.ts`) and pass that same instance to the
  write gate, the read selector and the MCP engines. It is the only latch.
- **Switch state.** The account owns the switch. A host reads it from the
  Account setting (`GET /api/v1/me/stream-sync`) before it launches the server
  and passes it as `streamSync.write`. The server reads only that local value
  and never calls the Account. The mode samples it when it is built, and Lite
  samples it again before any config update, so a `true` seen at startup is
  not lost before the first write. Once `true`, it stays `true`.
- **Unknown.** If the mode cannot be established (the source cannot be read
  and nothing is latched, or the owner does not match), a legacy write is
  refused with a retryable `503 ACCOUNT_MODE_UNKNOWN`, like a read. A
  known-unswitched account is never refused.
- **The seal is the invariant.** One object, the legacy-write seal
  (`packages/core/src/storage/legacy-write-seal.ts`), decides whether a legacy
  version may become durable. Every storage that installs a legacy file or
  index row holds a seal and wraps its last durable step in `seal.commit(step)`.
  `commit` asks the account mode and runs `step` in the same tick, with no
  `await` between. Switched or unknown mode throws `LegacyWriteRefusedError`
  and runs nothing. A storage built without a seal does not compile
  (`createIndexManager` and `publishDataFile` require one). A seal that nobody
  bound to a mode answers unknown and refuses. It is modeled on the read-side
  seal in `mcp/legacy-seal.ts`.
  Callers that reach storage without a route (derivative compute and its
  replay on start, the download worker, `recover()` of prepared imports, boot
  recovery of staged files) are covered by the same seal, because the check is
  in the storage and not in the caller.
- **Route checks are early refusals only.** `admitLegacyWrite` and the route
  commit fences (`fenceLegacyCommit`) give a clean 426 or 503 before a body is
  read or a request is staged. Nothing depends on them. Tests remove them and
  show the seal still refuses.
- **No mode wired is unknown.** `legacyWriteVerdict(undefined)` is `unknown`,
  never `allow`. A server with no `serverOwner` or no config cannot say which
  account it holds, so a legacy write is refused with the retryable 503
  (DECISION-UNKNOWN-MODE-1109). `createApp` without a config source builds a
  mode whose source throws, which reads as unknown. The PDPP importer takes
  `serverOwner` so an owner mismatch reads as unknown, like every other route.
- **A refusal leaves nothing.** A refused write removes what it staged: the
  blob, the staged file, the prepared import row. When a chunked finalize is
  refused because the account switched (426), the session's chunks and
  metadata go too, because the session can never finish. While the mode is only
  unknown (503) the chunks stay so the retry can use them; they expire with the
  session. `recover()` of a prepared import and boot recovery of a staged
  file drop the work on switched and leave it in place on unknown.
- **Drain.** After a host observes the switch it must know no legacy write is
  still landing. `seal.drain()` resolves once every commit that started before
  the call has settled. A commit that starts later is refused. The Lite config
  update calls it after a `true` is seen. Node needs no drain: its mode is read
  from the config file, which changes only by restart, so the mode is fixed for
  the life of the process.
- **Oura import is not atomic.** `POST /v1/import/oura-browser` writes one
  legacy file per stream. Each is its own sealed commit. A switch part-way
  through the batch keeps the streams already committed (they were legal when
  written; the stream-sync import takes over from there), refuses the next one,
  and the call fails with no receipts. No stream written after the switch is
  kept.
- **Sidecars are not sealed.** Block manifests and first-seen ledgers are
  derived caches. They are removed with the scope delete, and a legacy version
  is invisible without its index row, which is sealed.
- **`createMemoryPsLiteStorage` has no seal.** It is test-only. Production Lite
  uses `createPersistentPsLiteStorage`, which carries the seal and is bound by
  the runtime.
- **Who is refused.** Every legacy write of a switched account, from every
  caller. `Vana-Stream-Sync-Client: 1` earns nothing: a client built for stream
  sync must stop making legacy writes. The header chooses nothing about what a
  caller may read.
- **Where the early refusals run.** `POST /:scope` (`core/src/api/index.ts`,
  `if (!writeAuth)`), the durable `PUT …/imports/:operation` and the upload
  routes (same file, after `authorizeOwner`; an upload abort stays allowed), and
  chunked import begin/chunk/finalize (`server/src/routes/chunked-scope-import.ts`,
  `refuseIfLegacy`). They check the normalized path, so `/imports/<op>/` and
  doubled slashes reach the same gate. A session opened before the switch is
  refused at its next chunk or finalize. The only exemption is a delegated
  builder write whose `X-Vana-Write-Signature` proof was verified; every other
  route is owner-only and has none, so a signature header earns nothing there.
  `dataRoutes` also refuses before any body is read. The chunk and finalize
  routes have no middleware refusal: `refuseIfLegacy` runs inside them because
  it must know the session to remove it.
- **Error.** HTTP `426 Upgrade Required`, code `update_required`, header
  `Upgrade: vana-stream-sync`:

  ```json
  {
    "error": { "code": 426, "errorCode": "update_required", "message": "…" },
    "errorCode": "update_required",
    "message": "This account has moved to stream sync. Update the Vana app to keep syncing. The data already on this device is untouched."
  }
  ```

  Why 426: it says "this client is too old" and nothing else. 409 is already
  used here for import conflicts and stream-sync control scopes, and an old
  client may retry or merge on it. 5xx invites a retry. 401 and 403 invite a
  sign-in loop. The body has the message under both error shapes this API
  uses, so an old client shows it from the field it already reads.

## Durable legacy commits and the seal call that covers each

Every place a legacy version becomes durable, and the one call that makes it
refuse. A refusal leaves no file, no index row and no prepared row.

| Commit                                                                             | Where                                                                                     | Seal call                                                                                             |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Node index row (`insert`, `insertIfCurrent`)                                       | `server/src/storage/index-manager.ts`                                                     | `legacyWriteSeal.commit` around the insert transaction                                                |
| Node index row for a recovered file                                                | `index-manager.ts` `insertRecovered`                                                      | `legacyWriteSeal.commit`                                                                              |
| Node data file (`writeEnvelopeAndIndex`, `commitEnvelope`, download `insertEntry`) | `server/src/storage/hierarchy.ts` `publishDataFile`, `node-data-storage.ts`               | `seal.commit` in `publishDataFile`; the index row above                                               |
| Node staged file (chunked finalize, boot recovery)                                 | `hierarchy.ts` `publishStagedDataFile`; `chunked-scope-import.ts`; `node-data-storage.ts` | `seal.commit` in `publishStagedDataFile`                                                              |
| Import operation: prepared row                                                     | `server/src/storage/import-operations.ts`                                                 | `seal.assertOpen()` before the INSERT                                                                 |
| Import operation: publish by `recover()` (also reached by DELETE)                  | `import-operations.ts` `recoverRow`                                                       | `publishDataFile(..., seal, ...)`; switched drops the row, unknown keeps it                           |
| Lite index row (`installEntry`)                                                    | `lite/src/storage.ts`                                                                     | `updateIndex(..., { legacyCommit: true })`, then `legacyWriteSeal.commit(() => publish(next))`        |
| Lite blob (`writeEnvelope`)                                                        | `lite/src/storage.ts`                                                                     | `legacyWriteSeal.assertOpen()`; the blob is invisible until the sealed row install                    |
| Derivative compute and its replay on start                                         | `core/src/derivatives/compute.ts`                                                         | `legacyWriteSeal.assertOpen()` before the grant check; the write below it is sealed too               |
| Download worker                                                                    | `core/src/sync/workers/download.ts`                                                       | `legacyWriteSeal.assertOpen()` in `downloadAll` and in the per-scope loop; the commit below is sealed |
| Oura import (one commit per stream)                                                | `core/src/oura/index.ts`, `server/src/routes/oura.ts`                                     | each stream is a sealed data write; the early fence is only an early refusal                          |

Not sealed on purpose: delete and erase paths (a person must be able to remove
data after the switch), Lite metadata updates, sidecars (see above).

## Census (this repository)

| Path                                                                     | Where                                                                                                                                                                                                                                            | Old clients that use it                                                                | Can the check see the switch?  | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/data/:scope`                                                   | gate `server/src/routes/data.ts:199`; handler `core/src/api/index.ts:2930`                                                                                                                                                                       | Desktop (renderer ingest, projection import), Web via a hosted server, a hosted server | Yes: `config.streamSync.write` | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `PUT /v1/data/:scope/imports/:operation`                                 | gate `data.ts:203`; handler `core/src/api/index.ts:2395`                                                                                                                                                                                         | Desktop saved-export delivery and retained-import                                      | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/data/:scope/imports` (chunked begin)                           | gate `data.ts:200`; handler `data.ts:272`                                                                                                                                                                                                        | Chunked importers                                                                      | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `PUT /v1/data/:scope/imports/:id/chunks/:index`                          | gate `data.ts:201`; handler `data.ts:299`                                                                                                                                                                                                        | Chunked importers                                                                      | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/data/:scope/imports/:id/finalize`                              | gate `data.ts:202`; handler `data.ts:329`                                                                                                                                                                                                        | Chunked importers                                                                      | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/data/:scope/uploads`                                           | gate `data.ts:204`; handler `core/src/api/index.ts:2392` (`handleScopeUploadRequest`)                                                                                                                                                            | Scope-version streaming uploads                                                        | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `PUT /v1/data/:scope/uploads/:id/batches/:index`                         | gate `data.ts:205`; same handler                                                                                                                                                                                                                 | Same                                                                                   | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/data/:scope/uploads/:id/commit`                                | gate `data.ts:206`; same handler                                                                                                                                                                                                                 | Same                                                                                   | Yes                            | Refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `DELETE /v1/data/:scope`, `DELETE …/imports/:id`, `DELETE …/uploads/:id` | `core/src/api/index.ts:3223`, `data.ts:342`                                                                                                                                                                                                      | Any                                                                                    | Yes                            | **Allowed on purpose.** A delete writes a tombstone, but refusing it would stop a person from deleting data from the old app. The switch deletes the account's legacy files anyway.                                                                                                                                                                                                                                                                                                                         |
| `POST /v1/data/:scope` with a builder write session                      | `core/src/api/index.ts` `authorizeWrite` then `if (!writeAuth)` refusal; signature verified in `core/src/write/authorize.ts:136` (`verifyWriterAttribution`), reached from `server/src/api-auth.ts:288`; refusal at `core/src/api/index.ts:2954` | Third-party builders, not Vana apps                                                    | Yes                            | **Exempt only when the signature verifies.** `writeAuth` exists only after the session bearer and `X-Vana-Write-Signature` proof verified. A forged or missing signature gets no `writeAuth`, so an owner-path write is refused like any other (a test sends a forged header on a switched server and checks nothing is stored). The route layer cannot verify the signature (it signs the body), so for plain `POST /:scope` it defers header-bearing requests to the data handler. No other route defers. |
| `POST /v1/sync/trigger`, `/v1/sync/file/:id`                             | `core/src/api/index.ts:3341`                                                                                                                                                                                                                     | Any                                                                                    | n/a                            | Not a client write. The server's own sync engine decides what to upload.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `/v1/stream-sync/*`                                                      | `server/src/app.ts:535`                                                                                                                                                                                                                          | Stream-sync clients                                                                    | n/a                            | New routes. Never gated.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `/v1/records/*`, `/v1/blobs/ingest` (PDPP record store)                  | `server/src/routes/pdpp-records.ts:1274,1431,1614,1826`                                                                                                                                                                                          | Record-store clients                                                                   | n/a                            | Not legacy files. Not gated.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `POST /v1/import/oura-browser`                                           | `server/src/routes/oura.ts`, in-process write `core/src/oura/index.ts:384`                                                                                                                                                                       | Desktop connector host                                                                 | n/a                            | The server writes in-process with no HTTP request to gate. Same version as its host. Not gated.                                                                                                                                                                                                                                                                                                                                                                                                             |
| Phone in-process runtime `/v1/data`                                      | `lite/src/runtime.ts:1267`                                                                                                                                                                                                                       | The phone app that bundles it                                                          | n/a                            | Bundled with its own app shell, so the caller is never older than the server. Not gated.                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Server → storage upload of local legacy files                            | `core/src/sync/workers/upload.ts:266`                                                                                                                                                                                                            | Every server version                                                                   | n/a                            | An **old server version** uploads straight to storage. See below.                                                                                                                                                                                                                                                                                                                                                                                                                                           |

## What this repository cannot refuse

An old app version carries an old server inside it (Desktop sidecar, phone
runtime). That server uploads legacy files straight to the storage service
with the owner's own signature. No server of ours is in the loop, so no code
here can refuse it. The narrowest enforcement point is the storage service's
write authorization: it refuses a legacy-format upload for an account that has
switched, with the same `426 update_required` body. The Account already holds
the switch state, so the storage service reads it from there. This change
does not touch the storage service or the gateway.

Web is covered at the Account's signing step, not here (companion change).

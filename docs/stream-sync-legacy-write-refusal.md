# Refusing legacy writes after the stream-sync switch

Once an account has moved to stream sync, stream data is its only store. No new
legacy file, index row, registry fact or remote object may appear for it. This
note says who decides, where the decision is enforced, which writes are refused
and which are never refused.

## Who decides

The account-mode module decides (`packages/core/src/sync/account-mode`). A host
feeds it the Account's answers. Nothing else keeps a copy of the answer.

- **One lock.** The module has one read-write lock. A legacy write takes the
  shared side (`ModeAuthority.commitLegacy`) and runs inside it. The On latch
  takes the exclusive side. So an On waits for every legacy write already in
  flight, and no legacy write starts after the On.
- **One seal.** `LegacyWriteSeal` (`core/src/storage/legacy-write-seal.ts`)
  binds that module to one owner. `commit(write)` runs a legacy write.
  `remove(work)` runs a pure removal. `verdict()` and `admit()` are early
  refusals that save work. They never permit anything.
- **The seal sits where bytes become durable.** A storage method that installs
  a legacy file or row takes a `LegacyWriteHold`. A hold exists only inside
  `commit`. Code that writes without one does not compile. Routes, workers and
  boot recovery all reach storage, so all of them meet the same seal.
- **The gate only words the refusal.** `core/src/api/legacy-write-gate.ts`
  turns a refusal into the response an old client reads. It decides nothing.
- **Order of locks.** The seal comes first, then a path lock, then a scope lock,
  then a queue. Code that holds a scope lock must not ask for the seal. The
  lock is not re-entrant: a write inside `commit` must not call `commit` or
  `remove` again. A caller that is already inside `commit` passes its `hold`,
  and the removal then runs inside that lock.
- **The authority is built first.** `createServer` loads the account-mode
  records before it opens any index. The seal is made before boot recovery runs.

## Answers

| Account                  | Legacy write                                              | Client `DELETE` route      | Pure removal |
| ------------------------ | --------------------------------------------------------- | -------------------------- | ------------ |
| Not switched (Off heard) | Runs                                                      | Runs                       | Runs         |
| Switched (On)            | `426 update_required`, header `Upgrade: vana-stream-sync` | `409 USE_CONNECTOR_DELETE` | Runs         |
| Mode unknown             | `503 ACCOUNT_MODE_UNKNOWN`, `Retry-After: 5`              | `503 ACCOUNT_MODE_UNKNOWN` | Runs         |

Why 426: it says "this client is too old" and nothing else. 409 is used for
import conflicts, and 5xx invites a retry.

The `Vana-Stream-Sync-Client` header changes nothing. A switched account refuses
the write whether or not the header is present.

### Removal and delete

- A **pure removal** adds nothing new. It runs under the shared lock in every
  mode, because a person must always be able to remove data, and the host erases
  legacy files after the switch through the same storage. It runs
  (`seal.remove`) inside a caller's `commit` when the caller passes its `hold`.
- A **client `DELETE /v1/data/:scope`** is different. On a switched account it
  would report "deleted" while the stream rows stay readable. So it is refused
  with `409 USE_CONNECTOR_DELETE`: the connector delete erases. On an unknown
  mode it is a retryable `503`. On an unswitched account it deletes. The mode
  check and the delete are one `commit`.
- The **gateway tombstone** in a scope delete is a new fact in the registry. It
  is a legacy write: it runs inside `commit`, and a switched account sends none.

### Sync workers

A worker step is classified by whether it writes anything new.

| Step                                 | Writes something new?              | Result on a switched or unknown account                                                                                           |
| ------------------------------------ | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Download: store a fetched version    | Yes (file and row)                 | Refused at the storage seal. The pass stops at the first refusal and advances no cursor.                                          |
| Upload: blob upload and registration | Yes (remote object, registry fact) | Each remote write is its own `commit` (`publication/publish.ts`). A blob already in flight finishes, the registration is refused. |
| Delete: gateway tombstone            | Yes (registry fact)                | Refused. A re-submission after a failed tombstone is paused and spends no attempt.                                                |
| Delete: local copy and blob cleanup  | No                                 | Runs in every mode.                                                                                                               |
| Derivative compute: store the answer | Yes                                | Refused at the storage seal. The model is not asked when the account is already refused.                                          |
| PDPP importer: canonical publish     | Yes                                | Refused inside `commit`.                                                                                                          |

## Sinks

Each row names the seal site and the test that proves it.

### Server storage

| Sink                                  | Seal site                                   | Test                                           |
| ------------------------------------- | ------------------------------------------- | ---------------------------------------------- |
| `writeEnvelope`                       | `server/src/storage/node-data-storage.ts`   | `server/src/storage/legacy-write-seal.test.ts` |
| `writeEnvelopeAndIndex`               | same                                        | same                                           |
| `commitEnvelope`                      | same                                        | same                                           |
| `insertEntry`                         | same                                        | same                                           |
| `recoverStagedDataFiles`              | same                                        | same                                           |
| `reindexLegacyDataFiles`              | same                                        | same                                           |
| `commitVersion` with an import intent | `server/src/storage/import-operations.ts`   | same                                           |
| `commitVersion` without an intent     | same                                        | same                                           |
| `recoverImportOperations`             | same                                        | same                                           |
| delete finishing an owed import       | same                                        | same                                           |
| chunked finalize, new publication     | `server/src/routes/chunked-scope-import.ts` | same                                           |
| chunked finalize, resumed stage       | same                                        | same                                           |
| removals                              | `seal.remove` in the two storage files      | same                                           |

### Lite storage

| Sink                                                                               | Seal site                     | Test                                 |
| ---------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------ |
| `writeEnvelope`, `writeEnvelopeAndIndex`, `insertEntry`                            | `lite/src/storage.ts`         | `lite/src/legacy-write-seal.test.ts` |
| `openVersionWriter.commit`                                                         | same                          | same                                 |
| a refused streamed commit                                                          | same                          | same                                 |
| `deleteScope`, `deleteVersion`, `deleteVersionIfEnvelopeMissing`, `deleteByFileId` | same                          | same                                 |
| one authority for runtime and storage                                              | `lite/src/browser-runtime.ts` | same                                 |

### Core callers

| Sink                            | Seal site                                             | Test                                       |
| ------------------------------- | ----------------------------------------------------- | ------------------------------------------ |
| Client `DELETE /v1/data/:scope` | `core/src/api/index.ts`                               | `core/src/api/legacy-delete-route.test.ts` |
| Gateway tombstone               | `core/src/sync/workers/delete.ts`                     | `delete-seal.test.ts`                      |
| Tombstone re-submission         | same                                                  | `delete-finality.test.ts`                  |
| Upload: blob and registration   | `core/src/publication/publish.ts`                     | `upload-seal.test.ts`                      |
| Download                        | storage seal; early check in `workers/download.ts`    | `download-seal.test.ts`                    |
| PDPP importer                   | `core/src/sync/pdpp-import.ts`                        | `pdpp-import.test.ts`                      |
| Derivative answer               | storage seal; early check in `derivatives/compute.ts` | `compute-seal.test.ts`                     |
| Ingest, index step              | `core/src/contracts/data.ts`                          | `data-seal.test.ts`                        |
| The seal itself                 | `core/src/storage/legacy-write-seal.ts`               | `legacy-write-seal.test.ts`                |
| `commitRemoval`                 | `core/src/sync/account-mode/authority.ts`             | `authority.test.ts`                        |

### Boot

| Step                          | Seal site                 | Test                             |
| ----------------------------- | ------------------------- | -------------------------------- |
| Boot recovery, reindex marker | `server/src/bootstrap.ts` | `bootstrap-account-mode.test.ts` |

At boot the mode is usually unknown. Recovery then leaves staged files and the
reindex marker in place. When the first answer that makes the mode known
arrives, the recovery pass runs once more. An Off publishes what the last run
acknowledged. An On drops it.

## Writes that are not legacy sinks

| Path                                                                                   | Why it is not refused                                                                             |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `/v1/stream-sync/*`                                                                    | New routes. They are stream writes, not legacy sinks.                                             |
| `/v1/records/*`, `/v1/blobs/ingest`                                                    | PDPP record store, not legacy files.                                                              |
| Durable additions (`core/src/additions/durable.ts`, `lite/src/additions-transport.ts`) | System documents. They are not scope data. **Not sealed.** See "Open points".                     |
| `POST /v1/sync/trigger`, `/v1/sync/file/:id`                                           | Not a client write. The sync engine decides what to upload, and its steps are in the table above. |

## What this repository cannot refuse

An old app version carries an old server inside it (Desktop sidecar, phone
runtime). That server uploads legacy files straight to the storage service with
the owner's own signature. No server of ours is in the loop, so no code here can
refuse it. The narrowest enforcement point is the storage service's write
authorization. This change does not touch the storage service or the gateway.

## Open points

- **Durable additions publish system documents** with `publishVersion` without
  the seal. They are not scope data, but they are remote legacy-format writes.
  A decision is owed on whether the switch must stop them.
- **A host that injects its own Lite storage** is not sealed by the factory. The
  storage must be built with a seal, or it refuses nothing.

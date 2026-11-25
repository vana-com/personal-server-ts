# Retirement await audit

A: live authority is checked by `gatedPort` inside the destructive port, after its reads, signing, serialization or locks. B: the sole `writeDone` writer requires branded scope confirmations; their constructor checks a pinned absent/deleted head and fresh absence of index entries and files. C: the remote adapter rejects a missing or different fenced version before queue, blob or local cleanup.

The table lists every await in the standalone retire pass and the delete worker’s fenced call tree. Request creation, scheduling and the unrelated background blob-retry loop are outside this call tree. Internal port awaits are included for signing and marker persistence; the storage boundaries are listed below.

| Await (file:line)                                     | Effect after it and invariant                                                           |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------- |
| packages/core/src/localdb/legacy-retire-intent.ts:186 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-retire-intent.ts:219 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-retire-intent.ts:237 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-retire-intent.ts:266 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-retire-intent.ts:285 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-retire-intent.ts:330 | A gates the next host effect; B gates the done write.                                   |
| packages/core/src/localdb/legacy-delete.ts:107        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:114        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:214        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:240        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:264        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:470        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:476        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:495        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:510        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:531        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:533        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:543        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:546        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:547        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:579        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:608        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:615        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/localdb/legacy-delete.ts:635        | A gates cleanup; B requires remote and local completion proof.                          |
| packages/core/src/sync/workers/delete.ts:248          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:257          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:258          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:483          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:490          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:492          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:493          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:586          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:610          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:611          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:645          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:699          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:700          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:798          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:920          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:936          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:949          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:956          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:957          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:990          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:992          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:997          | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1003         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1019         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1028         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1030         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1034         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1038         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1502         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/workers/delete.ts:1524         | A gates queue, blob and local effects; C gates entry to cleanup.                        |
| packages/core/src/sync/delete-data-port.ts:199        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:244        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:279        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:284        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:308        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:311        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:315        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:334        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:369        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:372        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:417        | Unfenced retry only: a fence throws before this branch (C).                             |
| packages/core/src/sync/delete-data-port.ts:420        | Unfenced retry only: a fence throws before this branch (C).                             |
| packages/core/src/sync/delete-data-port.ts:465        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/delete-data-port.ts:472        | A gates each HTTP DELETE after signing; C gates all cleanup.                            |
| packages/core/src/sync/pending-blob-deletions.ts:160  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:195  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:200  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:203  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:209  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:213  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:218  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:224  | A gates the KV write after serialization and reads.                                     |
| packages/core/src/sync/pending-blob-deletions.ts:232  | A gates the KV write after serialization and reads.                                     |
| packages/server/src/storage/import-operations.ts:546  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:267  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:545  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:551  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:557  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:570  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/node-data-storage.ts:580  | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/hierarchy.ts:434          | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/hierarchy.ts:649          | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/hierarchy.ts:653          | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/server/src/storage/hierarchy.ts:777          | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:323                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:331                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:332                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:333                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:417                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:418                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:439                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:483                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:484                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:876                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:877                      | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1450                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1460                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1465                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1469                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1526                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1535                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1548                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1574                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1576                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1585                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |
| packages/lite/src/storage.ts:1587                     | A gates each local effect after reads or locks; B consumes only fresh absence evidence. |

Local storage effect owners use the same helper inside their locks: Node’s `deleteFencedVersion` gates its synchronous row/file transaction after `finishOwedPublications`; the fallback gates unlink, sidecar removal and row removal separately. Lite’s `eraseUnderPathLock` gates both file stores, block trees and index publication; its OPFS ports gate `removeEntry` after directory lookup. Physical absence checks only read. An absent pin persists exact id/path/collection-time identities; an unindexed file or replacement outside that set blocks without scope-wide deletion.

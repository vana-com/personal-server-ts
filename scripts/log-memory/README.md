# Stream-sync log memory

Measures the peak memory of the stream-sync log's large operations in Node,
offline. One case is a source of `records` records of `pad` bytes each, run
through these steps, each in a **fresh process** over the state the steps
before it left on disk (file SQLite databases, one file per blob, the
registry's rows in `state.json`):

| Step          | What it measures                                          |
| ------------- | --------------------------------------------------------- |
| `publish`     | the first publish of the source (a writer)                |
| `restore`     | a second device's default first load of the log           |
| `compaction`  | the log folded into a snapshot (called directly, ungated) |
| `replace`     | a covered replace of every key, published                 |
| `progressive` | a third device's first load with progressive mode on      |

`intake1` and `intake2` prepare the source and its replacement and are not
measured. A fresh process matters: a publish leaves ~700 MiB of freed pages
resident, and a later step in the same process reads as if it cost nothing.

```sh
# Node 22 (better-sqlite3's ABI). Holds ~/.tmp/heavy-run.lock, waits for 12 GiB.
scripts/log-memory/run.sh B  100000 1024      # 100k x 1 KiB
scripts/log-memory/run.sh A  2000   150000    # 2k x 150 KB
scripts/log-memory/table.py ~/.tmp/log-memory-out/B.jsonl
```

Each line is `idleMiB` (resident size after a full collection, when the step
began), `peakMiB` (the kernel's `VmHWM`, total process peak) and `aboveIdleMiB`
(their difference). `sampledHeapMiB` and `sampledExternalMiB` say where the
peak lives; they are a sampled lower bound.

## Before and after

To measure `main` with the same harness, check out the commit that added the
harness (`git log -- scripts/log-memory`, its first commit: it holds the
harness and no change to the code under test) in a worktree on top of main's
sources, and run the same cases there. Main's `planCompaction` has the
cost-model gate in front of it, which a log of a few segments never passes: in
that worktree make the gate false (`false && !required && ...`) so the
`compaction` step compacts.

## The legacy path

`bench/legacy-memory.workload.ts` sends the same records through the legacy
sync workers (`sync/workers/upload.ts`, `download.ts`) as one data point, with
real encryption and in-memory storage fakes:

```sh
node --expose-gc --import tsx packages/server/src/localdb/bench/legacy-memory.workload.ts --records 70000 --pad 1024
```

The legacy path refuses a data file whose upload body passes
`MAX_UPLOAD_BODY_BYTES` (95 MB, `sync/upload-state.ts`). The workload prints
`refused: true` for a source that large. Under the cap, its fakes keep the
stored bytes in the process, so read `endMiB - idleMiB` (what stayed) beside
`aboveIdleMiB`.

What a Node run cannot show: the phone's bridge (every query and blob crosses
it as a message), real encryption (the harness seals with the identity
function, so ciphertext equals plaintext), the WebView's own garbage, and a
real network. `compaction` calls the compaction directly because the cost
model fires only for a log with a long tail.

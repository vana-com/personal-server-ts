# Record envelope and streamed body (head format 2)

Status: design note. It replaces the 8 MiB record exclusion and the earlier
draft of this note ("fragment parts with a `span` field").

## Goal

No record is dropped for size. The design aim is a peak memory bounded by the
**part size** (4 MiB target, 16 MiB limit) instead of the record size. That
holds today for the **forward read of an imported base** (`viewBodies` with
no overlay body). It does **not** hold for the write path (the record
object, and in the spool path one body at a time) or for any read that
needs an object, or for an overlay row. The measured numbers are in
"Measured memory" below; this note claims nothing past them.

## What is wrong today

A record is one canonical line `{"o","r","v":<record>}`. Every step holds the
whole line: the parsed object, the canonical string, its UTF-8 bytes, the
spool line, the plaintext part and the ciphertext. The 8 MiB cap hid this by
dropping the record. These facts are in `records.ts`, `parts.ts`, `merge.ts`,
`spool.ts`, `writer.ts` (`append`, `reduceGroup`, `buildParts`) and
`stream-sync-read/lines.ts`.

## Design

### 1. Envelope and body

A record is a **frame**: `E LF B LF`.

- `B` is the body: the canonical JSON of the record (the bytes the line held
  after `"v":`). It has no raw LF, because canonical JSON escapes control
  characters.
- `E` is the envelope, canonical JSON of five fields:
  `{"h":<sha256 of B, 64 hex>,"k":<pkHash, 64 hex>,"n":<byte length of B>,"o":<run start ms>,"r":<runId>}`.

Merge, overlay and delete use `(k, o, r)` only. A reducer entry is
`{o, r, where the body is}`; it never parses a body. `pkHash` is still the
hash of the primary-key values, computed from the key fields before the body
is serialized.

### 2. One write of the body, streamed

`canonicalJsonChunks(value)` is a generator that yields the same bytes as
`canonicalJson` in pieces of at most 64 KiB (a long string is escaped slice by
slice, never split inside a surrogate pair). Because `E` leads with `h` and
`n`, a record is serialized twice and never held: pass 1 feeds an incremental
SHA-256 and counts bytes; pass 2 writes the bytes. Hosts inject the
incremental hash as a new port, `Sha256Stream` (`update`, `digest`), next to
the existing one-shot `Sha256`.

A body that arrives as bytes (a client that already holds canonical JSON)
enters through `appendBody(key values, chunks)`; the writer hashes and counts
while it spools it. The caller vouches that the body contains the key fields.

### 3. Parts hold frames; a long frame spans parts

A part is a byte string of whole frames. A frame of at most the inline limit
(1 MiB, `INLINE_BODY_BYTES`) sits inside one part, as today's lines do,
sorted by `k`. A longer frame is cut into 4 MiB pieces, each its own part, placed alone between the
inline parts of its bucket. Nothing marks a piece in the head: the parts of
one prefix, read in order, are one byte stream of frames, and the first
envelope says how long its frame is. The head lists parts as before:
`{bytes, count, hash, prefix}`. `count` is the number of frames that **start**
in the part, so a continuation piece has `count: 0`. Several parts may share a
prefix (the head today forbids it). The head stays the only authority on which
parts form a version, and each part hash commits to its bytes.

The reducer (`FrameReducer`, envelopes only) keeps, for each winner, a _held_
frame in memory (a frame of at most 1 MiB; bounded by the bucket, at most one
part) and a long frame by locator: a spool body file or a run of base parts.
Only held bytes count toward the bucket split. A winning base piece run is carried into the
next head unchanged: no piece is read, decrypted or uploaded again. Reading
only the first piece of a run gives the stamp.

### 4. Streaming authenticated encryption

Part blobs of format 2 use the **STREAM** construction as specified for the age
file format (age-encryption.org/v1, payload): ChaCha20-Poly1305, 64 KiB
chunks, a 12-byte nonce made of an 11-byte big-endian chunk counter and a
final-chunk flag byte, a fresh 16-byte random header nonce, and a payload key
from HKDF-SHA-256(key = the per-scope key, salt = header nonce, info =
`"payload"`). Truncation, reordering and extension fail authentication. We do
not invent a mode. The primitives come from `@noble/ciphers` and
`@noble/hashes`, which already run in Node, browsers and WebViews. The blob is
`magic || header nonce || chunks`; the magic distinguishes it from an OpenPGP
SEIPD blob, which readers keep decrypting. **Heads stay OpenPGP** (at most
1 MiB, one object). A format-1 reader then decrypts a format-2 head, reads
`format: 2` and refuses with `unsupported_format`. It never reaches a STREAM
blob, so it cannot report a misleading `key_mismatch`.

### 5. Streaming reads

The reader parses frames from the decrypted parts of a prefix, one part in
memory at a time, and hands the consumer `{envelope, body: AsyncIterable}`.
For a base body the server can forward body chunks to the HTTP response, or
to the Lite bridge, unparsed (`viewBodies`). A consumer that needs an object
(field projection, filters, the legacy projection) parses the whole body:
it holds the chunks, their join, the decoded string and the parsed value at
once, about 3 times the record.

**Overlay rows are not streamed.** The local overlay reads its spool bodies
whole (`writer-overlay.ts` `parseBody`), `overlayWinners` keeps every winning
parsed record in memory, and `viewBodies` re-serializes an overlay value with
`chunksOfValue`. A record of 100 MiB that is a local overlay winner costs the
parse-read figure below, not the forward-read figure. Locators for overlay
bodies (envelope plus spool body file, read lazily) would remove this; they
are not built.

### 6. One code path for small records

A small record is a frame whose body is one chunk. There is no second
format. Packing many frames into one part keeps tiny records cheap.

## Format version

`format` becomes **2** for every head a new writer writes.

| Piece           | Change                                                                                                                                                                     |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Head            | `format: 2`; part `count >= 0`; equal prefixes may repeat; `recordCount` is the sum of counts.                                                                             |
| Part bytes      | frames (`E LF B LF`) instead of NDJSON lines `{"o","r","v"}`.                                                                                                              |
| Spool log       | `<k> TAB <envelope> TAB <body>` instead of `<pkHash> <line>`. The reader also reads the old line: a run that was ready before the upgrade is still published and overlaid. |
| Blob encryption | STREAM AEAD instead of OpenPGP SEIPD for format 2.                                                                                                                         |
| Ports           | `Sha256Stream` added. `Sha256`, `Keccak256`, `NamespaceHmac` unchanged.                                                                                                    |
| Names           | unchanged (`h-<keccak>`, `g<gen>-p-<sha256>`).                                                                                                                             |

Readers accept 1 and 2 (the current and the previous version). A reader that
knows only format 1 gets `unsupported_format` and refuses; it cannot misread
a format-2 head. A format-2 writer reading a format-1 base converts each line
on the fly: the body is the text after `"v":`, which is already canonical.
**Release order:** readers (Personal Server, Lite, Web) ship first. Writers
write format 2 only after that; an account that stays on an old reader sees
`unsupported_format` for a stream a new writer touched, which is the refusal
rule Tim set.

## Why these are the standard choices

- Envelope plus opaque payload with a length and a content hash is the layout
  of git objects, tar and HTTP chunked bodies: a reader can route and order
  records without reading payloads.
- STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated
  Encryption", 2015) with a final-chunk flag is the construction in age, Tink
  streaming AEAD and libsodium `secretstream`. We follow age's byte layout.
- Content addressing of parts (`g<gen>-p-<sha256>`) is unchanged, so the head
  still commits to every byte through the part hashes.

## Measured memory (100 MiB record)

Each step in its own child process, net of the process baseline (see
`big-record-memory.test.ts`).

| Step                      | Node (RSS delta) | Lite (fake-indexeddb heap, upper bound) |
| ------------------------- | ---------------- | --------------------------------------- |
| Write (spool and publish) | 115-123 MiB      | 222-224 MiB (GC on), 290-304 MiB (off)  |
| Forward read (flat path)  | 22-30 MiB        | 165-166 MiB (GC on), 213-223 MiB (off)  |
| Parse read (object)       | 314-317 MiB      | 437-438 MiB (GC on), 465-471 MiB (off)  |

The write is not part-bounded: the record object itself is in memory (the
caller gave it to us), and the body is serialized twice from it. The forward
read is the one flat path.

## Not in this change

The Desktop client still caps one batch body at 8 MiB. The Personal Server
batch route takes up to the legacy ingest ceiling (`DATA_INGEST_MAX_SIZE`) and
parses the body whole, so its peak is about 3 times the batch. The existing
list and query reads still parse a record to project or filter it; only the
streaming read primitive is flat, and only for base bodies.

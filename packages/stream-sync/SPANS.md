# Record envelope and streamed body (head format 2)

Status: design note. It replaces the 8 MiB record exclusion and the earlier
draft of this note ("fragment parts with a `span` field").

## Goal

Peak memory of a write or a read is bounded by the **part size** (4 MiB
target, 16 MiB limit), not by the record size, on Node, in a browser and in a
phone WebView. No record is dropped for size.

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
(8 MiB) sits inside one part, as today's lines do, sorted by `k`. A longer
frame is cut into 4 MiB pieces, each its own part, placed alone between the
inline parts of its bucket. Nothing marks a piece in the head: the parts of
one prefix, read in order, are one byte stream of frames, and the first
envelope says how long its frame is. The head lists parts as before:
`{bytes, count, hash, prefix}`. `count` is the number of frames that **start**
in the part, so a continuation piece has `count: 0`. Several parts may share a
prefix (the head today forbids it). The head stays the only authority on which
parts form a version, and each part hash commits to its bytes.

The reducer keeps, for each winner, a small body in memory (bounded by the
bucket, at most one part) and a large body (over 1 MiB) by locator: a spool
body file or a base piece run. A winning base piece run is carried into the
next head unchanged: no piece is read, decrypted or uploaded again. Reading
only the first piece of a run gives the stamp.

### 4. Streaming authenticated encryption

Blobs of format 2 use the **STREAM** construction as specified for the age
file format (age-encryption.org/v1, payload): ChaCha20-Poly1305, 64 KiB
chunks, a 12-byte nonce made of an 11-byte big-endian chunk counter and a
final-chunk flag byte, a fresh 16-byte random header nonce, and a payload key
from HKDF-SHA-256(key = the per-scope key, salt = header nonce, info =
`"payload"`). Truncation, reordering and extension fail authentication. We do
not invent a mode. The primitives come from `@noble/ciphers` and
`@noble/hashes`, which already run in Node, browsers and WebViews. The blob is
`magic || header nonce || chunks`; the magic distinguishes it from an OpenPGP
SEIPD blob, which readers keep decrypting.

### 5. Streaming reads

The reader parses frames from the decrypted parts of a prefix, one part in
memory at a time, and hands the consumer `{envelope, body: AsyncIterable}`.
The server forwards body chunks to the HTTP response, or to the Lite bridge,
unparsed. Only a consumer that needs an object (field projection, filters,
the legacy projection) parses, and only then does it hold the body once.

### 6. One code path for small records

A small record is a frame whose body is one chunk. There is no second
format. Packing many frames into one part keeps tiny records cheap.

## Format version

`format` becomes **2** for every head a new writer writes.

| Piece           | Change                                                                                         |
| --------------- | ---------------------------------------------------------------------------------------------- |
| Head            | `format: 2`; part `count >= 0`; equal prefixes may repeat; `recordCount` is the sum of counts. |
| Part bytes      | frames (`E LF B LF`) instead of NDJSON lines `{"o","r","v"}`.                                  |
| Spool log       | frames instead of `<pkHash> <line>`.                                                           |
| Blob encryption | STREAM AEAD instead of OpenPGP SEIPD for format 2.                                             |
| Ports           | `Sha256Stream` added. `Sha256`, `Keccak256`, `NamespaceHmac` unchanged.                        |
| Names           | unchanged (`h-<keccak>`, `g<gen>-p-<sha256>`).                                                 |

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

## Not in this change

The Desktop client and the run-intake route still cap one batch body at
8 MiB. An oversized record needs a chunked body upload from Desktop before it
can reach a Personal Server. The seed upload route accepts long lines.
The existing list and query reads still parse a record to project or filter
it; only the streaming read primitive is flat.

# Source declaration fixtures — provenance

These three files are **not authored here**. They are byte-for-byte copies of
the `SourceDeclaration` documents the Unity DataPipe producer emits and
digests, vendored so tests exercise the producer's real bytes rather than a
document written to agree with us.

That distinction is the whole reason they exist. A declaration authored in
this repo would prove only that PS agrees with itself; these prove PS agrees
with the producer, which is what the `$pdpp` digest check actually asserts.

## Source

| Field           | Value                                                   |
| --------------- | ------------------------------------------------------- |
| Producer repo   | `unity-surfaces`, PR **#1098**                          |
| Producer commit | **`bccc682e`**                                          |
| Producer path   | `packages/app-runtime/src/sources/` (emitted artifacts) |
| Delivered via   | `pdpp-delivery-0917/declarations/`                      |
| Copied          | 2026-09-17                                              |

## Digests — the contract these files carry

SHA-256 over each file's **exact bytes**, which is the value the producer
stamps into `$pdpp.declaration.digest` (as `sha256:<hex>`). Reproduced
independently by two lanes before being recorded here.

| File                                | sha256 (exact bytes)                                               |
| ----------------------------------- | ------------------------------------------------------------------ |
| `instagram.source-declaration.json` | `e4a9d0cb262f6b43956d7ff9cf17dd8851f3be1e3c3fe059bc18f022a29fbce5` |
| `github.source-declaration.json`    | `00c64092177a2830f670bd2cab83eab788e0c23575ad26b5b5762064b97ab3bb` |
| `youtube.source-declaration.json`   | `8292a2d3e3ab6ff2bbe87e3cbe7cb3efb719ee1ca7001be77c1724b12d68a046` |

### GitHub declaration update, 2026-09-18

`github.source-declaration.json` was re-copied from the producer when the
GitHub Collection Profile's remaining streams gained retained declarations.
It went from one stream to six: `user` (unchanged, byte-for-byte — diff the
two revisions to confirm) plus `repositories`, `starred`, `issues`,
`pull_requests` and `gists`. Every other top-level key is unchanged, so the
whole diff is additive and the digest moved from `c08e321dcac2…` to
`00c64092177a…` for that reason alone.

The profile's seventh stream, `user_stats`, is **not** here. Its upstream
`semantics` is `"append"`, which `parseDeclaration` rejects at the
whole-document level (only `mutable_state` and `append_only` are admitted), so
retaining it verbatim would unmount every GitHub stream including `user`.
Resolving that needs the two specs to agree on the value, not a local edit —
rewriting it to `append_only` here would put a claim in the producer's mouth.

Verify with:

```sh
sha256sum packages/core/src/pdpp/__fixtures__/*.source-declaration.json
```

## Rules for changing these files

**Do not reformat, re-indent, or re-serialize them.** The digest is over the
bytes, not the JSON value. Prettier and any JSON-canonicalizing tool must
leave them alone — a whitespace-only change silently invalidates every
producer digest that references them, and the failure surfaces as an
unexplained `digest_mismatch` at import rather than as a diff anyone reads.

A genuine producer update means: re-copy from the new producer commit, update
the commit and digests in the table above, and update `PUBLISHED_DIGEST` in
`packages/server/src/pdpp/datapipe-sync-import.e2e.test.ts`, which pins the
instagram value so drift fails loudly instead of quietly.

## Runtime note

These are **test fixtures only**. A real deployment provisions its
declarations explicitly through `config.pdpp.declarationPaths`; nothing at
runtime reads this directory.

# legacy-projection (internal to `personal-server-ts-core`)

Pure functions that project PDPP records back to the legacy Vana scope bodies
that existing apps read (for example `chatgpt.conversations` →
`{conversations, total}`).

- `projectPdppRecordsToLegacyPayload(scope, records, options)` — project one
  legacy scope from `{stream, data}` records of one PDPP source.
- `legacyScopeToPdppSelection(scope)` — the PDPP source and streams a legacy
  scope is built from.

This module uses browser-safe hashing and no Node built-ins, so it runs in
browsers and WebViews (eslint rejects `node:` imports here). It is not a published
package: it ships inside core, and apps read legacy scopes through the
Personal Server, which projects. The source was lifted from `unity-surfaces`
`packages/app-runtime/src/legacy-scope-adapter` at `origin/dev` b227e8ce1;
this module is now the single source of truth.

## Declaration-driven text and blob projection

The pure projector accepts trusted per-stream JSON schemas in
`options.streamSchemas`. Only fields annotated with
`x_pdpp_text_encoding: "pdpp-safe-escape-v1"` are decoded. An absent or older
schema is left unchanged. The decoder follows the ChatGPT 0.2.53 producer
contract: one replacement pass for escaped control/surrogate code units and
U+005C; literal unmatched backslash-u text remains literal. Declared arrays and
objects decode every nested string and object key; other primitives stay
unchanged. Raw forbidden code units and decoded-key collisions return
`invalid_encoded_text`, without partial output from that row. Prototype-named
keys remain ordinary own properties. Projection drops and counts malformed
rows using `records_dropped`; valid peers remain readable. Existing branch
completeness checks still apply to conversations affected by a dropped message.

`readCanonicalLegacyScope` and `createLegacyScopeView` accept an optional
`declarations` registry (`forInstance(instance, stream)`). The canonical reader
copies these schemas in its snapshot, validates and budgets referenced blobs,
then resolves a `blob_ref` annotated with `x_pdpp_blob_projects_field` and
`x_pdpp_blob_codec: "json-string-v1"`. The blob is a UTF-8 JSON string of exact
source text; it is never run through the inline decoder. Both null and absent
inline values are supported. Missing/unreadable bytes return `missing_raw_blob`;
an absent optional target and absent reference stay absent. An explicitly
required absent target returns `message_content_omitted`. Decode omissions
make canonical reads incomplete, and an entirely rejected item stream never
returns a successful empty history. These decode gaps block takeover. The
ChatGPT branch-integrity exception below applies only to its exact
conversation receipts. Schema and projection-contract changes invalidate both
view revisions and takeover caches.

Integration requirement: server composition must supply the registry governing
the selected instance to these optional inputs. No production caller outside
core storage was changed in this scoped patch. Do not annotate old vendored
declarations as a substitute: doing so would reinterpret old literal escapes.
The caller must keep declaration upgrades consistent with the records they
govern; this patch does not infer a historical per-record declaration version.

## ChatGPT branch evidence

ChatGPT conversation reads follow the selected node's stored first-version
parent links within that conversation. A clean path longer than the declared
count is served with `declared_count_below_walked`; a count never truncates a
stored path. A short or unavailable path uses flags only when they identify
one coherent chain of the declared size. Cycles cannot become valid through
flag cardinality. An unrecoverable conversation yields a hashed coverage gap;
healthy conversations remain available. Exact receipts can preserve scope
coverage, but grant neither deletion permission nor replacement authority.

Canonical storage keeps explicit empty message text. Legacy reads omit it,
matching the old ChatGPT connector's nonempty-text filter. Same-read empty
text remains retention evidence for coverage; null, absent and non-string
content do not. Retained tombstones and the existing deletion, identity and
snapshot safeguards still protect the whole scope.

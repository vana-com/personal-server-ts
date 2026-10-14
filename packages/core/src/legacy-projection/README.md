# legacy-projection (internal to `personal-server-ts-core`)

Pure functions that project PDPP records back to the legacy Vana scope bodies
that existing apps read (for example `chatgpt.conversations` →
`{conversations, total}`).

- `projectPdppRecordsToLegacyPayload(scope, records, options)` — project one
  legacy scope from `{stream, data}` records of one PDPP source.
- `legacyScopeToPdppSelection(scope)` — the PDPP source and streams a legacy
  scope is built from.

This module has no dependencies and no Node built-ins, so it runs in browsers
and WebViews (eslint rejects `node:` imports here). It is not a published
package: it ships inside core, and apps read legacy scopes through the
Personal Server, which projects. The source was lifted from `unity-surfaces`
`packages/app-runtime/src/legacy-scope-adapter` at `origin/dev` b227e8ce1;
this module is now the single source of truth.

# Parity oracle

This directory produced the goldens in `../src/legacy-projection/__fixtures__/parity/`. It is
not built, tested or published. CI only runs `../src/legacy-projection/parity-goldens.test.ts`
against the committed goldens.

The oracle runs the frozen legacy connector and the PDPP bundle for one
source over the same synthetic upstream responses (`inputs/`), in Node, with
the clock frozen at 2026-10-01T00:00:00Z:

| Source | Legacy connector (frozen) | PDPP bundle |
| --- | --- | --- |
| ChatGPT | `apps/mobile/public/connectors/chatgpt-4.0.0-vana.1.js` | `apps/mobile/public/connectors/chatgpt-0.2.20.js` |
| Claude | `apps/desktop/connectors/anthropic/claude-export-playwright.js` (2.0.1) | `apps/mobile/public/connectors/claude-0.2.23.js` |

Paths are in unity-surfaces; the goldens were made from `origin/dev`
b227e8ce1. Each golden records the sha256 of both scripts. A golden holds the
stored PDPP streams (rows deduped by `key ?? data.id`, as the phone stores
them), the legacy body the legacy script delivered, and
`reviewedDifferences`: every place the projection differs from that body,
with the reason.

Shims (see `lib/host.mjs`): linkedom instead of a browser, a stubbed `fetch`
that fails on any request the fakes do not model, no IndexedDB (every run is
a first run), no sleeps, a simulated download. Inputs are synthetic; no real
capture was available.

## Regenerate

```sh
cd packages/core/parity-oracle
npm ci
REF_DIR=/path/to/unity-surfaces node generate.mjs   # writes out/
npx tsx review.ts out/goldens                       # adds reviewedDifferences
```

`review.ts` overwrites `../src/legacy-projection/__fixtures__/parity/*.json` and fails on any
difference that matches no reviewed rule. Add a rule only after reading the
difference in `out/diffs/DIFFS.md`.

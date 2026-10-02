/**
 * Test-debris scopes identified in protected-scopes-prod.tsv (production
 * Data Gateway inventory, provided 2026-09-22): strings that are exact
 * production grant/registration rows but are self-evidently test/dev
 * artifacts, not real legacy app scopes.
 *
 * - `poc.spoof.<timestamp>` / `r2.pending-revoke.<timestamp>`: the source
 *   prefix itself (poc.spoof, r2.pending-revoke) is not a real connector id
 *   in either the desktop connector catalog or data-connectors' scope
 *   catalog, and the numeric suffix is a Unix-ms timestamp, not a stable
 *   scope name.
 * - `seedbot.alpha` / `seedbot.beta`: "seedbot" has no connector anywhere in
 *   this repo or data-connectors; the name and the alpha/beta pairing read
 *   as a seed/fixture generator's own two test rows.
 * - `demo.answer` / `write:demo.answer`: "demo" is not a connector id, and
 *   the `write:` prefix does not match this repo's `<source>.<scope>` scope
 *   grammar at all (verified: no other row in the 226-row TSV carries a
 *   colon).
 */
const POC_SPOOF_RE = /^poc\.spoof\.\d+$/;
const R2_PENDING_REVOKE_RE = /^r2\.pending-revoke\.\d+$/;
const SEEDBOT_RE = /^seedbot\.(alpha|beta)$/;

const TEST_DEBRIS_PATTERNS: {
  test: (scope: string) => boolean;
  reason: string;
}[] = [
  {
    test: (s) => POC_SPOOF_RE.test(s),
    reason:
      "poc.spoof.<unix-ms> — proof-of-concept debris, timestamped suffix, no matching connector",
  },
  {
    test: (s) => R2_PENDING_REVOKE_RE.test(s),
    reason:
      "r2.pending-revoke.<unix-ms> — revocation-flow test debris, no matching connector",
  },
  {
    test: (s) => SEEDBOT_RE.test(s),
    reason:
      "seedbot.* — no seedbot connector exists; reads as seed-data generator's own test rows",
  },
  {
    test: (s) => s === "demo.answer" || s === "write:demo.answer",
    reason:
      "demo.answer / write:demo.answer — 'demo' is not a connector id; write: prefix violates the source.scope grammar every other production row follows",
  },
];

export function classifyAsTestDebris(scope: string): string | undefined {
  for (const { test, reason } of TEST_DEBRIS_PATTERNS) {
    if (test(scope)) {
      return reason;
    }
  }
  return;
}

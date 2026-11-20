/** The registry's stream-scope grammar, which is narrower than legacy reads. */
const STREAM_ROW_SCOPE = /^pdpp\.([^.~]+)~([0-9a-f]{16})?\.(.+)$/;

/** The connection log fenced by this scope, or null for control/log/legacy rows. */
export function fencingLogScope(scope: string): string | null {
  const match = STREAM_ROW_SCOPE.exec(scope);
  if (!match || match[3] === "~log") return null;
  return `pdpp.${match[1]}~${match[2] ?? ""}.~log`;
}

/** Distinct log rows the batch fences without writing, excluding true tombstones. */
export function countFencedLogScopes<Row extends { readonly scope: string }>(
  rows: readonly Row[],
  isTombstone: (row: Row) => boolean,
): number {
  const written = new Set(rows.map((row) => row.scope));
  const fences = new Set<string>();
  for (const row of rows) {
    const log = fencingLogScope(row.scope);
    if (log !== null && !written.has(log) && !isTombstone(row)) fences.add(log);
  }
  return fences.size;
}

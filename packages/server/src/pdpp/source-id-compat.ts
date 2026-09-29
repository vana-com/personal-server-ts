/** Resolve Desktop's legacy source keys only when their retained source exists. */
export function resolveRetainedSourceId(
  requested: string,
  retainedSourceIds: ReadonlySet<string>,
): string | undefined {
  if (retainedSourceIds.has(requested)) return requested;

  const candidate = canonicalSourceIdCandidate(requested);
  return candidate && retainedSourceIds.has(candidate) ? candidate : undefined;
}

/** Convert only the two Desktop legacy keys into a canonical-source candidate. */
export function canonicalSourceIdCandidate(
  requested: string,
): string | undefined {
  const publicId =
    requested.match(/^([a-z0-9_-]+)$/i)?.[1] ??
    requested.match(
      /^https:\/\/registry\.pdpp\.dev\/connectors\/([a-z0-9_-]+)$/i,
    )?.[1];
  if (!publicId) return undefined;

  return `https://registry.pdpp.dev/sources/${publicId}`;
}

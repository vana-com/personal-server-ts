/** A completed Oura checkpoint window never proves deletion of omitted history. */
export const OURA_BROWSER_HISTORY_POLICY = {
  allowProvenDeletion: false,
  preserveRetainedEntities: true,
} as const;

/** Common `time_range.since` day of an eligible selection; null is full history. */
export function ouraTakeoverSelectionSince(
  value: unknown,
): { since: string | null } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const selection = value as Record<string, unknown>;
  if (
    Object.keys(selection).length !== 1 ||
    !Array.isArray(selection.streams) ||
    selection.streams.length !== 3
  )
    return null;
  const names = new Set<string>();
  let commonSince: string | null | undefined;
  for (const entry of selection.streams) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      return null;
    const stream = entry as Record<string, unknown>;
    if (
      typeof stream.name !== "string" ||
      Object.keys(stream).some((key) => key !== "name" && key !== "time_range")
    )
      return null;
    const name = stream.name.replace(/^oura\./, "");
    if (!["sleep", "readiness", "activity"].includes(name) || names.has(name))
      return null;
    names.add(name);
    let since: string | null = null;
    if (stream.time_range !== undefined) {
      const range = stream.time_range;
      if (
        !range ||
        typeof range !== "object" ||
        Array.isArray(range) ||
        Object.keys(range).length !== 1
      )
        return null;
      const day = (range as Record<string, unknown>).since;
      if (
        typeof day !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
        !Number.isFinite(Date.parse(day)) ||
        new Date(day).toISOString().slice(0, 10) !== day
      )
        return null;
      since = day;
    }
    if (commonSince !== undefined && commonSince !== since) return null;
    commonSince = since;
  }
  return { since: commonSince ?? null };
}

/** Completion is eligible only for one three-stream selection with one common since. */
export function isOuraTakeoverSelection(value: unknown): boolean {
  return ouraTakeoverSelectionSince(value) !== null;
}

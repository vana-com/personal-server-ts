/** A completed Oura checkpoint window never proves deletion of omitted history. */
export const OURA_BROWSER_HISTORY_POLICY = {
  allowProvenDeletion: false,
  preserveRetainedEntities: true,
} as const;

/** Completion is eligible only for one unrestricted three-stream selection. */
export function isOuraTakeoverSelection(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const selection = value as Record<string, unknown>;
  if (
    Object.keys(selection).length !== 1 ||
    !Array.isArray(selection.streams) ||
    selection.streams.length !== 3
  )
    return false;
  const names = new Set<string>();
  let commonSince: string | null | undefined;
  for (const entry of selection.streams) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      return false;
    const stream = entry as Record<string, unknown>;
    if (
      typeof stream.name !== "string" ||
      Object.keys(stream).some((key) => key !== "name" && key !== "time_range")
    )
      return false;
    const name = stream.name.replace(/^oura\./, "");
    if (!["sleep", "readiness", "activity"].includes(name) || names.has(name))
      return false;
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
        return false;
      const day = (range as Record<string, unknown>).since;
      if (
        typeof day !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
        !Number.isFinite(Date.parse(day)) ||
        new Date(day).toISOString().slice(0, 10) !== day
      )
        return false;
      since = day;
    }
    if (commonSince !== undefined && commonSince !== since) return false;
    commonSince = since;
  }
  return true;
}

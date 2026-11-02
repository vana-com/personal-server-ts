/** Public promise of the Oura admission, coverage and owner-import contract. */
export const OURA_LEGACY_TAKEOVER_CONTRACT = "oura-legacy-takeover-v1";
export const OURA_LEGACY_SCOPES = [
  "oura.sleep",
  "oura.readiness",
  "oura.activity",
] as const;

export type OuraCollectionRequirements =
  | { ok: true; since: string | null }
  | { ok: false; reason: "invalid_day" | "invalid_history"; scope: string };

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Exact entity days, never collection timestamps or inferred default windows. */
export function deriveOuraCollectionRequirements(
  histories: readonly { scope: string; data: unknown }[],
): OuraCollectionRequirements {
  let since: string | null = null;
  for (const { scope, data } of histories) {
    if (
      !OURA_LEGACY_SCOPES.some((candidate) => candidate === scope) ||
      !object(data)
    ) {
      return { ok: false, reason: "invalid_history", scope };
    }
    const keys =
      "records" in data
        ? ["records"]
        : scope === "oura.sleep"
          ? ["dailyScores", "sleepPeriods"]
          : ["days"];
    if (!keys.some((key) => key in data))
      return { ok: false, reason: "invalid_history", scope };
    for (const key of keys) {
      if (!(key in data)) continue;
      const rows = data[key];
      if (!Array.isArray(rows))
        return { ok: false, reason: "invalid_history", scope };
      for (const row of rows) {
        if (!object(row))
          return { ok: false, reason: "invalid_history", scope };
        const day = row.day;
        if (
          typeof day !== "string" ||
          !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
          !Number.isFinite(Date.parse(`${day}T00:00:00.000Z`)) ||
          new Date(`${day}T00:00:00.000Z`).toISOString().slice(0, 10) !== day
        ) {
          return { ok: false, reason: "invalid_day", scope };
        }
        if (since === null || day < since) since = day;
      }
    }
  }
  return { ok: true, since };
}

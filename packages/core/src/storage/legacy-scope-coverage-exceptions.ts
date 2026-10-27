/** Reviewed legacy collector defects for coverage comparison. */
export const LEGACY_COVERAGE_EXCEPTIONS = [
  {
    scope: "chatgpt.memories",
    path: "$.memories[].created_at",
    reason:
      "legacy collector wrote collection time; canonical carries source creation time",
    authority: "canonical",
  },
] as const;

/** Legacy oura-playwright copied average_hrv despite its frozen integer schema. */
export const LEGACY_INTEGER_ROUNDING_EXCEPTIONS = [
  { scope: "oura.sleep", path: "$.sleepPeriods[].averageHrv" },
] as const;

/** Legacy ChatGPT conversation updates used Unix seconds rather than ISO strings. */
export const LEGACY_EPOCH_TIMESTAMP_EXCEPTIONS = [
  {
    scope: "chatgpt.conversations",
    path: "$.conversations[].update_time",
    reason:
      "legacy collector wrote Unix seconds; canonical carries an ISO timestamp",
    authority: "canonical",
  },
] as const;

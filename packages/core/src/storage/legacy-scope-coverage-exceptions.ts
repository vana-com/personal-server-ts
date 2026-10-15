/** Reviewed legacy collector defects for coverage comparison. */
export const LEGACY_COVERAGE_EXCEPTIONS = [
  {
    scope: "chatgpt.memories",
    path: "$.memories[].created_at",
    reason:
      "legacy collector wrote collection time; canonical carries source creation time",
    authority: "canonical",
  },
  {
    scope: "oura.sleep",
    path: "$.dailyScores[].timestamp",
    reason:
      "Oura projection omits a null canonical timestamp from this optional legacy field",
    authority: "canonical",
  },
  {
    scope: "oura.sleep",
    path: "$.sleepPeriods[].type",
    reason:
      "Oura projection omits null or out-of-enum canonical types from this optional legacy field",
    authority: "canonical",
  },
  {
    scope: "oura.activity",
    path: "$.days[]",
    reason:
      "OpenPet decodes Oura score as Go int, so rows with a null score are omitted",
    authority: "canonical",
  },
  {
    scope: "oura.readiness",
    path: "$.days[]",
    reason:
      "OpenPet decodes Oura score as Go int, so rows with a null score are omitted",
    authority: "canonical",
  },
  {
    scope: "oura.sleep",
    path: "$.dailyScores[]",
    reason:
      "OpenPet decodes Oura score as Go int, so rows with a null score are omitted",
    authority: "canonical",
  },
] as const;

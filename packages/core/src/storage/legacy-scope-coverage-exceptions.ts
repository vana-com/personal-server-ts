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

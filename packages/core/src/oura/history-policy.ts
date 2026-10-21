/** A completed Oura checkpoint window never proves deletion of omitted history. */
export const OURA_BROWSER_HISTORY_POLICY = {
  allowProvenDeletion: false,
  preserveRetainedEntities: true,
} as const;

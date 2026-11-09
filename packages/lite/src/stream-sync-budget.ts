/**
 * Writer budgets for the Lite (browser / phone) stream-sync writer.
 *
 * Chosen from the P3 heap sweep (2 MiB target, 2 MiB reduce budget, 1 MiB
 * spool flush). A single record may still exceed the target (an 8 MiB record
 * is accepted and sits alone in its part), so the target bounds the part size
 * the planner can choose, not the largest record.
 */
const MiB = 1024 * 1024;

export const LITE_PART_TARGET_BYTES = 2 * MiB;
export const LITE_REDUCE_BUDGET_BYTES = LITE_PART_TARGET_BYTES;
export const LITE_SPOOL_FLUSH_BYTES = 1 * MiB;

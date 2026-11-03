/**
 * Opt-in policy-v3 research/staging API. Existing v1 exports are unchanged.
 * Runtime flag activation still uses v1 until capture/projection/finality ports.
 */
export * from "./policy-v3/envelope.js";
export * from "./policy-v3/merge-plan.js";
export * from "./policy-v3/record-reducer.js";
export * from "./policy-v3/revision.js";

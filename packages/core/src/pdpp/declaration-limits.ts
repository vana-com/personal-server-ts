/**
 * Declaration size bound, apart from `declaration.ts` so that replication
 * limits do not load its Node-only retrieval code (`node:crypto`,
 * `node:net`) into PS-Lite bundles.
 */
export const MAX_DECLARATION_BYTES = 256 * 1024;

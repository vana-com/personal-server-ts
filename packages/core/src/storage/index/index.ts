export type {
  IndexEntry,
  IndexListOptions,
  NewIndexEntry,
  ScopeSummary,
} from "./types.js";
export { initializeDatabase, INDEX_SCHEMA_VERSION } from "./schema.js";
export { createIndexManager, type IndexManager } from "./manager.js";

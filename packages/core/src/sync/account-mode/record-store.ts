import type { DurableModeRecord } from "./mode-machine.js";

/**
 * Where the records live: one per owner, outside the data database that a wipe
 * or rebuild can empty. The Node host keeps a file per owner; Lite keeps its
 * own IndexedDB database.
 *
 * `save` resolves only when the record is durable, and rejects otherwise. The
 * authority never serves an answer that depends on a record until `save` has
 * resolved. `load` returns every stored record; one that cannot be read is
 * left out, so its owner is unknown until the Account answers again.
 */
export interface ModeRecordStore {
  load(): Promise<Map<string, DurableModeRecord>>;
  save(owner: string, record: DurableModeRecord): Promise<void>;
}

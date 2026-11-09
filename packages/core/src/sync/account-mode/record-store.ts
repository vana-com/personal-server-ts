import {
  reduceAccountMode,
  validModeOwner,
  type AccountModeRecord,
  type ModeClock,
  type ModeEvent,
  type ModeReduction,
} from "./mode-machine.js";

/**
 * Host-implemented durable metadata port, outside wipeable data/projection stores.
 * transact must load the latest owner record, serialize concurrent transitions for
 * that owner, commit atomically, and return only after durable completion. A failure
 * rejects; it must never return a successful decision. No clock is read by this port.
 *
 * On evidence is pending. Only a successful durable save of that On may cause a
 * subsequent saveComplete. Serialize writes/acks so an old Off save cannot ack On.
 * The actual sink integration must keep its commit fence through the write; this
 * decision core alone cannot make a later, separately executed write atomic.
 */
export interface AccountModeRecordStore {
  read(owner: string): Promise<AccountModeRecord | null>;
  transact(
    owner: string,
    transition: (record: AccountModeRecord | null) => ModeReduction,
  ): Promise<ModeReduction>;
}

/** Always reloads through transact, including commit; never caches admission. */
export function reduceStoredAccountMode(
  store: AccountModeRecordStore,
  event: ModeEvent,
  clock: ModeClock,
): Promise<ModeReduction> {
  if (!event || !validModeOwner(event.owner)) {
    return Promise.resolve(reduceAccountMode(null, event, clock));
  }
  return store.transact(event.owner, (record) =>
    reduceAccountMode(record, event, clock),
  );
}

const copyRecord = (
  record: AccountModeRecord | null,
): AccountModeRecord | null => (record === null ? null : { ...record });
const copyResult = (result: ModeReduction): ModeReduction => ({
  record: copyRecord(result.record),
  decision: { ...result.decision },
});

/** Test double only. This is NOT a disk store and provides no restart durability. */
export class MemoryAccountModeRecordStore implements AccountModeRecordStore {
  private readonly records = new Map<string, AccountModeRecord>();
  private readonly tails = new Map<string, Promise<void>>();

  constructor(initial: readonly AccountModeRecord[] = []) {
    for (const record of initial) {
      if (!validModeOwner(record.owner) || this.records.has(record.owner)) {
        throw new Error("Invalid or duplicate account mode owner.");
      }
      this.records.set(record.owner, { ...record });
    }
  }

  async read(owner: string): Promise<AccountModeRecord | null> {
    if (!validModeOwner(owner)) return null;
    await this.tails.get(owner);
    return copyRecord(this.records.get(owner) ?? null);
  }

  transact(
    owner: string,
    transition: (record: AccountModeRecord | null) => ModeReduction,
  ): Promise<ModeReduction> {
    if (!validModeOwner(owner))
      return Promise.reject(new Error("Missing account mode owner."));
    const previous = this.tails.get(owner) ?? Promise.resolve();
    const work = previous.then(() => {
      const result = transition(copyRecord(this.records.get(owner) ?? null));
      if (result.record !== null && result.record.owner !== owner) {
        throw new Error("Account mode owner changed inside a transaction.");
      }
      // A transition receives and returns copies, never a mutable stored record.
      if (result.record === null) this.records.delete(owner);
      else this.records.set(owner, { ...result.record });
      return copyResult(result);
    });
    const tail = work.then(
      () => undefined,
      () => undefined,
    );
    this.tails.set(owner, tail);
    void tail.then(() => {
      if (this.tails.get(owner) === tail) this.tails.delete(owner);
    });
    return work;
  }
}

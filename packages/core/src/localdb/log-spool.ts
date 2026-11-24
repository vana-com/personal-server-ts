// The sealed objects of a candidate, kept on disk until they are uploaded.
//
// A publish that carries a compaction builds, besides its segment, every part
// of the new snapshot and every piece of the bodies they name: the size of the
// log, not of the round. Held as ciphertext in the candidate they are the
// whole log in memory (a 300 MB log is ~290 MiB of objects). A spool holds
// them as rows of the local database, one object per row, and an object is
// read back when its upload starts and dropped when it ends.
//
// The spool belongs to one candidate. It lives while that candidate can still
// be sent: the candidate is retained until the registry's answer is known, and
// a retry sends the same objects again. `discard` deletes its rows when the
// candidate is released. A crash leaves rows nothing refers to; the next
// publish round of the connection starts with `clearSpool`.

import type { SqlDriver } from "./driver.js";

/** One sealed object waiting for upload, by its blob name in the log scope. */
export interface SpooledObject {
  readonly name: string;
  /** The sealed length. */
  readonly bytes: number;
  /** The sealed bytes, read when called. */
  read(): Promise<Uint8Array>;
}

export interface Spool {
  add(name: string, cipher: Uint8Array): Promise<void>;
  /** What was added, in order of addition, one entry per name. */
  objects(): readonly SpooledObject[];
  /** Delete the spool's rows. */
  discard(): Promise<void>;
}

/** Delete every spool row of a connection: those of a process that did not finish. */
export async function clearSpool(
  db: Pick<SqlDriver, "batch">,
  connectionId: string,
): Promise<void> {
  await db.batch([
    {
      sql: "DELETE FROM log_spool WHERE connection_id = ?",
      params: [connectionId],
    },
  ]);
}

export function openSpool(
  db: Pick<SqlDriver, "batch" | "query">,
  connectionId: string,
  owner: string,
): Spool {
  const added = new Map<string, SpooledObject>();
  return {
    async add(name, cipher) {
      await db.batch([
        {
          sql: `INSERT OR REPLACE INTO log_spool(connection_id, owner, name, bytes, cipher)
                VALUES (?, ?, ?, ?, ?)`,
          params: [connectionId, owner, name, cipher.length, cipher],
        },
      ]);
      added.set(name, {
        name,
        bytes: cipher.length,
        async read() {
          const [row] = await db.query<{ cipher: Uint8Array }>(
            "SELECT cipher FROM log_spool WHERE connection_id = ? AND owner = ? AND name = ?",
            [connectionId, owner, name],
          );
          if (!row) throw new Error(`publish: spooled object ${name} is gone`);
          return new Uint8Array(row.cipher);
        },
      });
    },
    objects: () => [...added.values()],
    async discard() {
      added.clear();
      await db.batch([
        {
          sql: "DELETE FROM log_spool WHERE connection_id = ? AND owner = ?",
          params: [connectionId, owner],
        },
      ]);
    },
  };
}

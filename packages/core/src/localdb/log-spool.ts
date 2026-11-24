// The sealed objects of a candidate, kept on disk until they are uploaded.
//
// A publish that carries a compaction builds, besides its segment, every part
// of the new snapshot and every piece of the bodies they name: the size of the
// log, not of the round. Held as ciphertext in the candidate they are the
// whole log in memory (a 300 MB log is ~290 MiB of objects). A spool holds
// them as rows of the local database, and an object is read back when its
// upload starts and dropped when it ends.
//
// The spool belongs to one candidate. It lives while that candidate can still
// be sent: the candidate is retained until the registry's answer is known, and
// a retry sends the same objects again. `discard` deletes its rows when the
// candidate is released. Nothing of a spool outlives its process: the table is
// created again on every open, and a purge deletes the connection's rows
// (`log-scratch.ts`).
//
// An object is stored in chunks of at most `SPOOL_CHUNK` bytes, one row each:
// a sealed object can be 4 MiB, and a phone's SQL bridge refuses a request or
// a reply frame over 4 MiB (a blob travels as base64, a third larger still).

import type { SqlDriver } from "./driver.js";

/** One sealed object waiting for upload, by its blob name in the log scope. */
export interface SpooledObject {
  readonly name: string;
  /** The sealed length. */
  readonly bytes: number;
  /** The sealed bytes, read when called. */
  read(): Promise<Uint8Array>;
}

/** The most one row holds. */
export const SPOOL_CHUNK = 1024 * 1024;

export interface Spool {
  add(name: string, cipher: Uint8Array): Promise<void>;
  /** What was added, in order of addition, one entry per name. */
  objects(): readonly SpooledObject[];
  /** Delete the spool's rows. */
  discard(): Promise<void>;
}

export function openSpool(
  db: Pick<SqlDriver, "batch" | "query">,
  connectionId: string,
  owner: string,
): Spool {
  const added = new Map<string, SpooledObject>();
  const mine = [connectionId, owner] as const;
  return {
    async add(name, cipher) {
      await db.batch([
        {
          sql: "DELETE FROM log_spool WHERE connection_id = ? AND owner = ? AND name = ?",
          params: [...mine, name],
        },
      ]);
      // One request per chunk: a request holds one chunk, not the object.
      const chunks = Math.max(1, Math.ceil(cipher.length / SPOOL_CHUNK));
      for (let chunk = 0; chunk < chunks; chunk++) {
        const part = cipher.subarray(
          chunk * SPOOL_CHUNK,
          (chunk + 1) * SPOOL_CHUNK,
        );
        await db.batch([
          {
            sql: `INSERT INTO log_spool(connection_id, owner, name, chunk, bytes, cipher)
                  VALUES (?, ?, ?, ?, ?, ?)`,
            params: [...mine, name, chunk, part.length, part],
          },
        ]);
      }
      // A handle keeps scalars. A closure over `cipher` would keep every
      // sealed object in memory for as long as the spool lives.
      const length = cipher.length;
      added.set(name, {
        name,
        bytes: length,
        async read() {
          const whole = new Uint8Array(length);
          let at = 0;
          for (let chunk = 0; chunk < chunks; chunk++) {
            const [row] = await db.query<{ cipher: Uint8Array }>(
              `SELECT cipher FROM log_spool
                WHERE connection_id = ? AND owner = ? AND name = ? AND chunk = ?`,
              [...mine, name, chunk],
            );
            if (!row)
              throw new Error(`publish: spooled object ${name} is gone`);
            whole.set(row.cipher, at);
            at += row.cipher.length;
          }
          if (at !== length)
            throw new Error(`publish: spooled object ${name} is cut short`);
          return whole;
        },
      });
    },
    objects: () => [...added.values()],
    async discard() {
      added.clear();
      await db.batch([
        {
          sql: "DELETE FROM log_spool WHERE connection_id = ? AND owner = ?",
          params: [...mine],
        },
      ]);
    },
  };
}

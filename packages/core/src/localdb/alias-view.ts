import type { SqlDriver, SqlReader } from "./driver.js";
import type { StatementGuard } from "./query.js";
import { pinStream } from "./complete-read.js";
import { PartialViewMoved } from "./partial-read.js";
import type { Connection, Stream } from "./read-selection.js";

/**
 * The state of a connection's streams a paged alias read is built on. The read
 * pages its rows after its queue turn ends, so it must know that none of them
 * changed since it began: `pinAliasStreams` takes the epochs before the heads
 * are read, and `aliasViewCheck` says whether those heads, the connection and
 * the epochs are still the ones the read was decided on (the rule of
 * `completePage`, over several streams).
 */
export async function pinAliasStreams(
  db: SqlDriver,
  connectionId: string,
  streams: readonly string[],
): Promise<ReadonlyMap<string, number>> {
  const epochs = new Map<string, number>();
  for (const stream of streams) {
    epochs.set(stream, await pinStream(db, connectionId, stream));
  }
  return epochs;
}

/**
 * True while every installed head, its epoch and the connection are as pinned.
 * `guard` is the same test as a condition of one statement: a read of bodies
 * that carries it returns none once the view has moved, so a body is never
 * read from rows that changed after they were sized.
 */
export interface AliasViewCheck {
  (): Promise<boolean>;
  readonly guard: StatementGuard;
}

export function aliasViewCheck(
  db: SqlReader,
  connection: Connection,
  installed: readonly Stream[],
  epochs: ReadonlyMap<string, number>,
): AliasViewCheck {
  const heads = installed.map(
    () => `EXISTS (SELECT 1 FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?
                AND s.head_version = ? AND s.head_data_hash = ?)
         AND COALESCE((SELECT m.epoch FROM stream_change_marks m
                        WHERE m.connection_id = ? AND m.stream = ?), 0) = ?`,
  );
  const condition = `(
       EXISTS (SELECT 1 FROM connections c WHERE c.connection_id = ? AND c.generation = ?
                 AND c.control_state = 'active' AND c.deleted_at IS NULL
                 AND NOT EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector))
       ${heads.map((h) => `AND ${h}`).join("\n       ")})`;
  const sql = `SELECT ${condition} AS ok`;
  const params = [
    connection.connection_id,
    connection.generation,
    ...installed.flatMap((s) => [
      connection.connection_id,
      s.stream,
      s.installed_version,
      s.head_data_hash!,
      connection.connection_id,
      s.stream,
      epochs.get(s.stream) ?? 0,
    ]),
  ];
  return Object.assign(
    async () => {
      const [row] = await db.query<{ ok: number }>(sql, params);
      return row?.ok === 1;
    },
    { guard: { sql: condition, params } },
  );
}

/** Ends a body whose view moved: the reader sees an aborted read and asks again. */
export async function assertViewCurrent(check: AliasViewCheck): Promise<void> {
  if (!(await check())) throw new PartialViewMoved();
}

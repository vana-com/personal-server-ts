import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver } from "./driver.js";
import { createRecordQuery, type RecordQuery } from "./query.js";

/** Host authority for one registered PDPP connection and declared stream.
 * Null means unknown, deleted or unresolved; the database never infers a link.
 */
export type ConnectionLink = (
  instance: string,
  stream: string,
) => {
  readonly connector: string;
  readonly namespace: string;
} | null;

/** Apply the host's consent identity before querying the owner's current generation. */
export function createLinkedRecordQuery(
  db: SqlDriver,
  link: ConnectionLink,
): RecordQuery {
  const query = createRecordQuery(db);
  const target = async (instance: string, stream: string) => {
    const resolved = link(instance, stream);
    if (!resolved || typeof resolved.namespace !== "string") return null;
    const id = controlScope(resolved.connector, resolved.namespace);
    const rows = await db.query<{ generation: number }>(
      `SELECT generation FROM connections WHERE connection_id=? AND control_state='active'
       AND NOT EXISTS (SELECT 1 FROM delete_intents WHERE connector=connections.connector)`,
      [id],
    );
    return rows.length > 0 && link(instance, stream) !== null ? id : null;
  };
  return {
    async listRecords(input) {
      const id = await target(input.connectionId, input.stream);
      return id === null
        ? { records: [], nextCursor: null }
        : query.listRecords({ ...input, connectionId: id });
    },
    async getRecord(input) {
      const id = await target(input.connectionId, input.stream);
      return id === null
        ? null
        : query.getRecord({ ...input, connectionId: id });
    },
    async changesSince(input) {
      const id = await target(input.connectionId, input.stream);
      return id === null
        ? "gone"
        : query.changesSince({ ...input, connectionId: id });
    },
    async *streamRecords(instance, stream) {
      const id = await target(instance, stream);
      if (id !== null) yield* query.streamRecords(id, stream);
    },
  };
}

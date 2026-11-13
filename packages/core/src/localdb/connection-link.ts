import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlReader } from "./driver.js";
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
  db: SqlReader,
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
    return rows.length > 0 ? { id, generation: rows[0]!.generation } : null;
  };
  const valid = async (
    target: { id: string; generation: number },
    instance: string,
    stream: string,
  ) => {
    const [state] = await db.query<{
      generation: number;
      control_state: string;
    }>(
      "SELECT generation,control_state FROM connections WHERE connection_id=?",
      [target.id],
    );
    const current = link(instance, stream);
    return (
      state?.control_state === "active" &&
      state.generation === target.generation &&
      current !== null &&
      controlScope(current.connector, current.namespace) === target.id
    );
  };
  return {
    async listRecords(input) {
      const selected = await target(input.connectionId, input.stream);
      if (!selected) return { records: [], nextCursor: null };
      const page = await query.listRecords({
        ...input,
        connectionId: selected.id,
      });
      return (await valid(selected, input.connectionId, input.stream))
        ? page
        : { records: [], nextCursor: null };
    },
    async getRecord(input) {
      const selected = await target(input.connectionId, input.stream);
      if (!selected) return null;
      const row = await query.getRecord({
        ...input,
        connectionId: selected.id,
      });
      return (await valid(selected, input.connectionId, input.stream))
        ? row
        : null;
    },
    async changesSince(input) {
      const selected = await target(input.connectionId, input.stream);
      if (!selected) return "gone";
      const page = await query.changesSince({
        ...input,
        connectionId: selected.id,
      });
      return (await valid(selected, input.connectionId, input.stream))
        ? page
        : "gone";
    },
    async *streamRecords(instance, stream) {
      const selected = await target(instance, stream);
      if (!selected) return;
      for await (const row of query.streamRecords(selected.id, stream)) {
        if (!(await valid(selected, instance, stream))) return;
        yield row;
      }
    },
  };
}

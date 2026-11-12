import {
  classifyControl,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  IDENTITYLESS_NS,
  parseScope,
  type ControlRead,
  type ControlHashes,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncHashes } from "../stream-sync/crypto.js";
import { applyConnection } from "./apply.js";
import type { ConnectionRow, LocalSyncDeps } from "./deps.js";
import { purgeConnection } from "./purge.js";
import { insideQueue } from "./slot.js";

// A connection id is its canonical control scope: pdpp.<connector>~<ns>.
function connectionId(connector: string, ns: string): string {
  return controlScope(connector, ns);
}

const SELECT_CONNECTIONS = `SELECT connection_id AS connectionId, connector, ns,
  generation, control_state AS controlState, control_version AS controlVersion
  FROM connections`;
type SqlConnection = ConnectionRow & Record<string, string | number>;

async function cachedConnection(deps: LocalSyncDeps, id: string) {
  const [row] = await deps.db.query<SqlConnection>(
    `${SELECT_CONNECTIONS} WHERE connection_id = ?`,
    [id],
  );
  return row ?? null;
}

async function hashes(deps: LocalSyncDeps): Promise<ControlHashes> {
  const keyCheck = await deriveKeyCheck((message) =>
    deps.keys.namespaceHmac(message),
  );
  return controlHashes(streamSyncHashes.keccak256, keyCheck);
}

async function saveControl(
  deps: LocalSyncDeps,
  connector: string,
  ns: string,
  read: ControlRead,
  control: ControlHashes,
): Promise<ConnectionRow> {
  const id = connectionId(connector, ns);
  const state = classifyControl(read, control);
  const version = read.found ? read.version : 0;
  const generation = state.kind === "active" ? state.generation : 1;
  await deps.db.batch([
    {
      sql: `INSERT OR IGNORE INTO connections
        (connection_id, connector, ns, generation, control_state, control_version)
        VALUES (?, ?, ?, ?, ?, ?)`,
      params: [id, connector, ns, generation, state.kind, version],
    },
    {
      // Preserve the last active generation and newer controls. Absence is
      // not authority to clear a local-only delete; a fresh active row is.
      sql: `UPDATE connections SET
        generation = CASE WHEN ? = 'active' THEN ? ELSE generation END,
        control_state = ?, control_version = ?
        WHERE connection_id = ? AND control_version <= ?
          AND NOT (control_state = 'deleted' AND ? = 'absent')`,
      params: [
        state.kind,
        generation,
        state.kind,
        version,
        id,
        version,
        state.kind,
      ],
    },
  ]);
  return (await cachedConnection(deps, id))!;
}

async function purgeDeleted(deps: LocalSyncDeps, row: ConnectionRow) {
  if (row.controlState !== "deleted") return;
  const present = await deps.db.query<{ present: number }>(
    `SELECT 1 AS present
      WHERE EXISTS (SELECT 1 FROM records WHERE connection_id = ?)
      OR EXISTS (SELECT 1 FROM run_rows rr JOIN runs r ON r.run_id = rr.run_id
                 WHERE r.connection_id = ?)
      OR EXISTS (SELECT 1 FROM head_parts WHERE connection_id = ?)
      OR EXISTS (SELECT 1 FROM blob_refs WHERE connection_id = ?)
      OR EXISTS (SELECT 1 FROM connections
                 WHERE connection_id = ? AND checkpoint IS NOT NULL)`,
    Array(5).fill(row.connectionId),
  );
  if (present.length > 0) {
    await purgeConnection(deps, row.connectionId, {
      controlVersion: row.controlVersion,
    });
  }
}

/**
 * C.0 step 1: list the registry's control rows and upsert one `connections`
 * row per control scope (classification is `classifyControl`). A deleted
 * control row whose connection still has rows runs the local purge (F.5).
 * Returns the connections now known. Spec: C.0.
 */
export async function bootstrapConnections(
  deps: LocalSyncDeps,
): Promise<readonly ConnectionRow[]> {
  const control = await hashes(deps);
  const rows = await deps.registry.listControlRows();
  for (const row of rows) {
    const parsed = parseScope(row.scope);
    if (parsed?.kind !== "control") continue;
    const id = connectionId(parsed.connector, parsed.ns);
    await deps.queue.run(id, "end", async () => {
      const locked = insideQueue(deps, id);
      const connection = await saveControl(
        locked,
        parsed.connector,
        parsed.ns,
        row.read,
        control,
      );
      await purgeDeleted(locked, connection);
    });
  }
  return deps.db.query<SqlConnection>(
    `${SELECT_CONNECTIONS} ORDER BY connection_id`,
  );
}

/**
 * C.0 step 2, inside the connection queue and before any row is staged:
 * read the control row and the stream rows, then apply every stream whose
 * registry version differs from `head_version` or whose `head_parts` is empty
 * while `head_version > 0`. `unreachable` = the registry did not answer (C.0
 * step 3); a caller with no connection stages `generation_unbound`.
 */
export async function syncBeforeBegin(
  deps: LocalSyncDeps,
  connector: string,
): Promise<{
  readonly connection: ConnectionRow | null;
  readonly unreachable: boolean;
}> {
  // The pinned intake contract has no account identity (R23).
  const ns = IDENTITYLESS_NS;
  const id = connectionId(connector, ns);
  return deps.queue.run(id, "end", async () => {
    const locked = insideQueue(deps, id);
    const control = await hashes(locked);
    let read: ControlRead;
    try {
      read = await deps.registry.read(controlScope(connector, ns));
    } catch {
      return {
        connection: await cachedConnection(locked, id),
        unreachable: true,
      };
    }
    const connection = await saveControl(locked, connector, ns, read, control);
    await purgeDeleted(locked, connection);
    let streams: Awaited<
      ReturnType<LocalSyncDeps["registry"]["listStreamRows"]>
    >;
    try {
      streams = await deps.registry.listStreamRows(connector);
    } catch {
      return {
        connection: await cachedConnection(locked, id),
        unreachable: true,
      };
    }
    if (connection.controlState === "active") {
      // applyConnection owns version/empty-head-parts selection. Reuse this
      // listing, so its registry availability matches the snapshot above.
      await applyConnection(
        {
          ...locked,
          registry: {
            read: (scope) => deps.registry.read(scope),
            post: (request) => deps.registry.post(request),
            listControlRows: () => deps.registry.listControlRows(),
            listStreamRows: (key) =>
              key === connector
                ? Promise.resolve(streams)
                : deps.registry.listStreamRows(key),
          },
        },
        id,
      );
    }
    return {
      connection: await cachedConnection(locked, id),
      unreachable: false,
    };
  });
}

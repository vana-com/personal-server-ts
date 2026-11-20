import type { SqlDriver } from "../../../core/src/localdb/driver.js";

/** Seed rows of the local database directly, as a finished apply leaves them. */
export async function addConnection(
  db: SqlDriver,
  connectionId: string,
  connector: string,
  options: {
    ns?: string;
    control?: "absent" | "active" | "deleted" | "foreign";
    generation?: number;
    deletedAt?: number | null;
  } = {},
): Promise<void> {
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state, control_version, deleted_at) VALUES (?, ?, ?, ?, ?, 2, ?)",
      params: [
        connectionId,
        connector,
        options.ns ?? "",
        options.generation ?? 2,
        options.control ?? "active",
        options.deletedAt ?? null,
      ],
    },
  ]);
}

/** One stream of a connection: its installed head, its newest version and its records. */
export async function addStream(
  db: SqlDriver,
  connectionId: string,
  stream: string,
  options: {
    records?: number;
    stampBase?: number;
    version?: number;
    generation?: number;
    complete?: boolean;
    observedAt?: number;
    lastDeleteVersion?: number;
    profile?: string | null;
  } = {},
): Promise<void> {
  const version = options.version ?? 2;
  const generation = options.generation ?? 2;
  const complete = options.complete ?? true;
  const blob = `head-${connectionId}-${stream}-${version}`;
  const records = options.records ?? 1;
  const stampBase = options.stampBase ?? 1000;
  await db.batch([
    {
      sql: `INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind)
            VALUES (?, ?, ?, ?, ?, 3, ?, ?, ?, 'applied')`,
      params: [
        connectionId,
        stream,
        version,
        generation,
        blob,
        records,
        options.observedAt ?? 5000,
        Number(complete),
      ],
    },
    {
      sql: `INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, profile_key, profile_version, complete,
              last_delete_version, head_version, head_generation, head_data_hash, head_blob)
            VALUES (?, ?, '["id"]', 'mutable_state', 0, ?, '1.0.0', ?, ?, ?, ?, ?, ?)`,
      params: [
        connectionId,
        stream,
        options.profile === undefined ? null : options.profile,
        Number(complete),
        options.lastDeleteVersion ?? 0,
        version,
        generation,
        `hash-${connectionId}-${stream}-${version}`,
        blob,
      ],
    },
    ...Array.from({ length: records }, (_, i) => ({
      sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, ?, ?, ?, ?, 'run', ?, 'fixture')",
      params: [
        connectionId,
        stream,
        `pk${String(i).padStart(4, "0")}`,
        `key${i}`,
        stampBase + i,
        JSON.stringify({ id: `${i}`, stream }),
      ],
    })),
  ]);
}

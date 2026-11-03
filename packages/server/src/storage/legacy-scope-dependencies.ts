import type { Database } from "better-sqlite3";

/** Persistent dependency facts. These triggers must also run on flag-off writers. */
export const LEGACY_SCOPE_DEPENDENCY_SCHEMA = `
CREATE INDEX IF NOT EXISTS idx_pdpp_records_blob_id ON pdpp_records(blob_id);
CREATE TABLE IF NOT EXISTS legacy_scope_stream_revisions (
 instance TEXT NOT NULL, stream TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0 AND revision<=9007199254740991),
 PRIMARY KEY(instance,stream));
CREATE TABLE IF NOT EXISTS legacy_scope_instance_revisions (
 instance TEXT NOT NULL PRIMARY KEY,
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>0 AND revision<=9007199254740991));
`;

const streamTables = [
  "pdpp_records",
  "pdpp_record_arrival",
  "pdpp_stream_completion",
  "pdpp_replica_quarantined_keys",
];
const instanceTables = [
  "pdpp_instance_binding",
  "pdpp_replica_quarantined_connections",
  "pdpp_replica_integrity_fences",
  "pdpp_replica_binding_conflicts",
];
const blobTables = [
  "pdpp_blobs",
  "pdpp_blob_bytes",
  "pdpp_replica_received_bytes",
  "pdpp_replica_pending_bytes",
  "pdpp_replica_view",
];
const binaryTables = ["pdpp_binary_manifests", "pdpp_binary_chunks"];
const optionalTables = [
  ...streamTables.slice(3),
  ...instanceTables.slice(1),
  ...blobTables.slice(2),
  ...binaryTables,
  "pdpp_replica_pending_batches",
];
const versionTables = [
  "pdpp_schema_version",
  "pdpp_replica_schema_version",
  "pdpp_replica_view_schema",
];
const pendingBatch = (id: string) =>
  `CASE WHEN json_valid(${id}) THEN json_extract(${id}, '$[0]') END`;
const pendingBlob = (id: string) =>
  `CASE WHEN json_valid(${id}) THEN json_extract(${id}, '$[1]') END`;
function tables(db: Database): Set<string> {
  return new Set(
    (
      db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as {
        name: string;
      }[]
    ).map((row) => row.name),
  );
}

/** UPDATE then INSERT avoids inheriting an outer upsert's conflict policy. */
function bumpStreams(selection: string): string {
  return `SELECT CASE WHEN EXISTS(SELECT 1 FROM legacy_scope_stream_revisions WHERE revision>=9007199254740991 AND (instance,stream) IN (${selection})) THEN RAISE(ABORT, 'legacy scope dependency overflow') END;
    UPDATE legacy_scope_stream_revisions SET revision=revision+1
    WHERE (instance,stream) IN (${selection});
    INSERT INTO legacy_scope_stream_revisions(instance,stream,revision)
    SELECT s.instance,s.stream,1 FROM (${selection}) s
    WHERE NOT EXISTS(SELECT 1 FROM legacy_scope_stream_revisions r WHERE r.instance=s.instance AND r.stream=s.stream);`;
}
function references(blob: string): string {
  return `SELECT DISTINCT instance,stream FROM pdpp_records INDEXED BY idx_pdpp_records_blob_id WHERE blob_id IN (${blob})`;
}

export function installLegacyScopeDependencies(db: Database): void {
  // Existing flag-off handles may still write while another handle opens.
  // Hold the writer lock across replacement so no mutation can miss a trigger.
  db.transaction(() => installTriggers(db)).immediate();
}

function installTriggers(db: Database): void {
  const present = tables(db);
  if (!present.has("legacy_scope_stream_revisions")) return;
  db.prepare(
    "SELECT instance,stream,revision FROM legacy_scope_stream_revisions LIMIT 0",
  ).all();
  db.prepare(
    "SELECT instance,revision FROM legacy_scope_instance_revisions LIMIT 0",
  ).all();
  // Recreate only at writable schema boundaries: optional sources may have arrived.
  for (const table of [
    ...streamTables,
    ...instanceTables,
    ...blobTables,
    ...binaryTables,
    "pdpp_replica_pending_batches",
  ]) {
    if (!present.has(table)) continue;
    for (const event of ["INSERT", "UPDATE", "DELETE"] as const) {
      const sides =
        event === "UPDATE"
          ? ["OLD", "NEW"]
          : [event === "INSERT" ? "NEW" : "OLD"];
      let body = "";
      for (const side of sides) {
        if (streamTables.includes(table))
          body += bumpStreams(
            `SELECT ${side}.instance AS instance,${side}.stream AS stream`,
          );
        if (instanceTables.includes(table)) {
          body += `SELECT CASE WHEN EXISTS(SELECT 1 FROM legacy_scope_instance_revisions WHERE instance=${side}.instance AND revision>=9007199254740991) THEN RAISE(ABORT, 'legacy scope dependency overflow') END;
            UPDATE legacy_scope_instance_revisions SET revision=revision+1 WHERE instance=${side}.instance;
            INSERT INTO legacy_scope_instance_revisions(instance,revision) SELECT ${side}.instance,1 WHERE NOT EXISTS(SELECT 1 FROM legacy_scope_instance_revisions WHERE instance=${side}.instance);`;
          // Descriptor eligibility can change independently of the record owner.
          if (present.has("pdpp_replica_view"))
            body += bumpStreams(
              references(
                `SELECT blob_id FROM pdpp_replica_view WHERE instance=${side}.instance`,
              ),
            );
        }
        if (
          table === "pdpp_replica_quarantined_keys" &&
          present.has("pdpp_replica_view")
        )
          body += bumpStreams(
            references(
              `SELECT blob_id FROM pdpp_replica_view WHERE instance=${side}.instance AND stream=${side}.stream AND record_key=${side}.record_key`,
            ),
          );
        if (blobTables.includes(table))
          body += bumpStreams(references(`SELECT ${side}.blob_id`));
        if (binaryTables.includes(table))
          body += bumpStreams(
            references(
              `SELECT CASE WHEN ${side}.namespace='pending' THEN ${pendingBlob(`${side}.blob_id`)} ELSE ${side}.blob_id END WHERE ${side}.namespace IN ('canonical','received','pending')`,
            ),
          );
        if (table === "pdpp_replica_pending_batches") {
          const custody = [];
          if (present.has("pdpp_replica_pending_bytes"))
            custody.push(
              `SELECT blob_id FROM pdpp_replica_pending_bytes WHERE batch_id=${side}.id`,
            );
          for (const binary of binaryTables)
            if (present.has(binary))
              custody.push(
                `SELECT ${pendingBlob("blob_id")} FROM ${binary} WHERE namespace='pending' AND ${pendingBatch("blob_id")}=${side}.id`,
              );
          if (custody.length)
            body += bumpStreams(references(custody.join(" UNION ")));
        }
      }
      const name = `legacy_scope_dep_${table}_${event.toLowerCase()}`;
      db.exec(
        `DROP TRIGGER IF EXISTS ${name}; CREATE TRIGGER ${name} ${event === "INSERT" ? "AFTER" : "BEFORE"} ${event} ON ${table} BEGIN ${body} END;`,
      );
    }
  }
  for (const table of binaryTables)
    if (present.has(table))
      db.exec(
        `CREATE INDEX IF NOT EXISTS legacy_scope_dep_${table}_batch ON ${table}(${pendingBatch("blob_id")}) WHERE namespace='pending'`,
      );
}

/** Null is unavailable evidence, never an all-zero proof. Caller owns the snapshot. */
export function readLegacyScopeDependencies(
  db: Database,
  instance: string,
  streams: readonly string[],
): string | null {
  const present = tables(db);
  if (
    ![
      "legacy_scope_stream_revisions",
      "legacy_scope_instance_revisions",
      "pdpp_store_metadata",
      ...streamTables.slice(0, 3),
      "pdpp_instance_binding",
      "pdpp_blobs",
      "pdpp_blob_bytes",
    ].every((table) => present.has(table))
  )
    return null;
  const installed = new Set(
    (
      db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='trigger' AND name GLOB 'legacy_scope_dep_*'",
        )
        .all() as { name: string }[]
    ).map((row) => row.name),
  );
  for (const table of [
    ...streamTables,
    ...instanceTables,
    ...blobTables,
    ...binaryTables,
    "pdpp_replica_pending_batches",
  ]) {
    if (
      present.has(table) &&
      ["insert", "update", "delete"].some(
        (event) => !installed.has(`legacy_scope_dep_${table}_${event}`),
      )
    )
      return null;
  }
  const epoch = db
    .prepare("SELECT epoch FROM pdpp_store_metadata WHERE id=1")
    .pluck()
    .get();
  if (typeof epoch !== "string") return null;
  const capabilities = [
    ...optionalTables.map((table) => [table, present.has(table)]),
    ...versionTables.map((table) => [
      table,
      present.has(table)
        ? (db.prepare(`SELECT version FROM ${table}`).pluck().get() ?? null)
        : null,
    ]),
  ];
  const safety =
    db
      .prepare(
        "SELECT revision FROM legacy_scope_instance_revisions WHERE instance=?",
      )
      .pluck()
      .get(instance) ?? 0;
  const read = db
    .prepare(
      "SELECT revision FROM legacy_scope_stream_revisions WHERE instance=? AND stream=?",
    )
    .pluck();
  return JSON.stringify([
    epoch,
    capabilities,
    safety,
    [...new Set(streams)]
      .sort()
      .map((stream) => [stream, read.get(instance, stream) ?? 0]),
  ]);
}

// Turns a RAW scenario capture into the transcript that compare.mjs compares,
// and holds the executable controls for the normalization.
//
// Everything here is pure: raw capture in, normalized transcript out.
//
// CLAIM, deliberately narrow. The controls below show that SPECIFIC edits to a
// capture survive normalization (listed in MUTANTS) and that SPECIFIC declared
// volatile edits do not (EQUIVALENCES). They do not show that normalization
// loses nothing: any difference outside the exercised scenario, or a kind of
// edit with no mutant here, is not covered. Time preservation across phases is
// asserted by the scenario itself (preservation-* operations), not here:
// auto-clock counts below cannot see an existing default timestamp rewritten.
//
// WHAT IS NORMALIZED (the complete list; anything else is compared verbatim)
//
//  1. SQLite wall-clock defaults. In a column whose DEFAULT is a SQLite clock
//     expression, a value is replaced by "<sqlite-clock:auto>" only when it is
//     a timestamp inside the real wall-clock window of this run (provenance:
//     the scenario clock lives in 2031, so a value in the real window can only
//     come from SQLite's own `now`). Every other value in such a column,
//     explicit timestamps included, and every NULL, is kept. Per table and
//     column the transcript also records how many values were auto and
//     whether they never decrease in rowid order.
//  2. Random UUIDs. Each distinct UUID in the whole transcript (bodies,
//     paths, headers, row values, file names, file contents, blob contents)
//     becomes `<uuid-N>` by first appearance. The map is global and bijective:
//     two ids never share a token, so a reference that points somewhere else
//     changes the token pattern. File and blob hashes are taken AFTER the map.
//     Files are ordered with ids blanked so random names cannot reorder them.
//  3. Volatile response headers (VOLATILE_HEADERS): the value becomes
//     "<volatile>"; presence is still compared.
//
// NOT NORMALIZED: ciphertext is never recorded. The scenario decrypts every
// uploaded blob with the tree's derived scope key, so the decrypted envelope
// (payload and metadata), its commitments and a fingerprint of each derived
// scope key are compared instead of ciphertext bytes.
//
// REMOVED BEFORE COMPARISON (compare.mjs, each value checked): the converged
// schema stamp, the default-off config key, and empty additive gate tables.
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const VOLATILE_HEADERS = new Set([
  "date",
  "x-request-id",
  "x-correlation-id",
]);
export const AUTO_CLOCK = "<sqlite-clock:auto>";
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const MAX_INLINE_TEXT = 100_000;
const SLACK_MS = 5000;
const sha256 = (text) =>
  createHash("sha256").update(text, "latin1").digest("hex");

/** Parse a SQLite or ISO timestamp; NaN when the value is not one. */
export function timestampMs(value) {
  if (typeof value !== "string") return Number.NaN;
  if (/^\d{4}-\d\d-\d\dT/.test(value)) return Date.parse(value);
  if (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?$/.test(value))
    return Date.parse(`${value.replace(" ", "T")}Z`);
  return Number.NaN;
}

function normalizeTables(raw) {
  const start = raw.meta.wallStartMs - SLACK_MS;
  const end = raw.meta.wallEndMs + SLACK_MS;
  const tables = {};
  for (const [name, table] of Object.entries(raw.tables)) {
    const clock = new Set(table.sqliteClockColumns);
    const autos = {};
    const rows = table.rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).map(([column, value]) => {
          const at = clock.has(column) ? timestampMs(value) : Number.NaN;
          if (at >= start && at <= end) {
            (autos[column] ??= []).push(at);
            return [column, AUTO_CLOCK];
          }
          return [column, value];
        }),
      ),
    );
    tables[name] = {
      rows,
      autoClock: Object.fromEntries(
        Object.entries(autos).map(([column, values]) => [
          column,
          {
            values: values.length,
            neverDecreasing: values.every(
              (value, index) => index === 0 || value >= values[index - 1],
            ),
          },
        ]),
      ),
    };
  }
  return tables;
}

function normalizeOperations(raw) {
  return raw.operations.map(({ name, value }) => {
    if (!value?.headers) return { name, value };
    return {
      name,
      value: {
        ...value,
        headers: Object.fromEntries(
          Object.entries(value.headers).map(([header, text]) => [
            header,
            VOLATILE_HEADERS.has(header) ? "<volatile>" : text,
          ]),
        ),
      },
    };
  });
}

/** Files are listed in name order, and some names are random ids. Order them
 * by path and content with every id blanked, so ids cannot reorder the list
 * (two files equal under blanking would be indistinguishable here too). */
function stableFileOrder(files) {
  const blank = (text) => text.replace(UUID, "<id>");
  const key = (file) => `${blank(file.path)}\0${blank(file.text)}`;
  return [...files].sort((a, b) =>
    key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0,
  );
}

export function normalize(raw) {
  const config = structuredClone(raw.config);
  const configFlag = config.legacyWriteShutdownEnabled ?? null;
  delete config.legacyWriteShutdownEnabled;
  const staged = {
    operations: normalizeOperations(raw),
    gateway: raw.gateway,
    storage: raw.storage,
    commitments: raw.commitments,
    scopeKeyFingerprints: raw.scopeKeyFingerprints,
    schema: raw.schema,
    gateRows: raw.gateRows,
    tables: normalizeTables(raw),
    files: stableFileOrder(raw.files),
    configFlag,
    config,
  };
  // One global, bijective id map over everything, applied to the JSON text.
  const ids = new Map();
  const mapped = JSON.parse(
    JSON.stringify(staged).replace(UUID, (id) => {
      const key = id.toLowerCase();
      if (!ids.has(key)) ids.set(key, `<uuid-${ids.size + 1}>`);
      return ids.get(key);
    }),
  );
  // Hash only after the map: contents keep their id relationships.
  mapped.files = mapped.files.map(({ path, size, text }) => ({
    path,
    size,
    sha256: sha256(text),
    ...(text.length <= MAX_INLINE_TEXT ? { text } : {}),
  }));
  for (const table of Object.values(mapped.tables))
    table.rows = table.rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).map(([column, value]) => [
          column,
          value && typeof value === "object" && "$blob" in value
            ? `<blob ${sha256(value.$blob)}>`
            : value,
        ]),
      ),
    );
  return mapped;
}

/** Deep differences as `/path: a != b` lines (at most `limit`). */
export function differences(a, b, path = "", out = [], limit = 40) {
  if (out.length >= limit || isDeepStrictEqual(a, b)) return out;
  if (
    a &&
    b &&
    typeof a === "object" &&
    typeof b === "object" &&
    Array.isArray(a) === Array.isArray(b)
  ) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
      differences(a[key], b[key], `${path}/${key}`, out, limit);
    return out;
  }
  out.push(`${path}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`);
  return out;
}

// --- Controls: each mutant edits the RAW capture the way a regression would;
// the normalized result MUST differ. Each equivalence edits only what is
// declared volatile; the normalized result MUST NOT differ. A mutant that does
// not apply to a capture is a harness defect (it returns null), never a pass.

/** `value` moved by `ms`, in the same textual form. */
function isoPlus(value, ms) {
  const iso = new Date(timestampMs(value) + ms).toISOString();
  if (value.includes(" ")) return iso.replace("T", " ").replace(/\.\d+Z$/, "");
  return value.includes(".") ? iso : iso.replace(".000Z", "Z");
}
const inWall = (raw, value) => {
  const at = timestampMs(value);
  return (
    at >= raw.meta.wallStartMs - SLACK_MS && at <= raw.meta.wallEndMs + SLACK_MS
  );
};
function firstCell(raw, accept) {
  for (const [name, table] of Object.entries(raw.tables))
    for (const row of table.rows)
      for (const column of Object.keys(row))
        if (accept(name, table, column, row[column]))
          return { row, column, table: name };
  return null;
}
const firstUpload = (raw) =>
  raw.storage.find((entry) => entry.method === "PUT" && entry.envelope);
function flipFirstString(node) {
  for (const [key, value] of Object.entries(node)) {
    if (typeof value === "string" && value.length > 0) {
      node[key] = String.fromCharCode(value.charCodeAt(0) ^ 1) + value.slice(1);
      return true;
    }
    if (value && typeof value === "object" && flipFirstString(value))
      return true;
  }
  return null;
}
const receipts = (raw) =>
  raw.files.filter((file) => file.path.includes("receipts/"));

export const MUTANTS = [
  {
    name: "NULL in a clock-default column became an autogenerated-looking value",
    // Real tables declare their clock-default columns NOT NULL, so a NULL
    // there exists only in a synthetic capture (normalize.test.mjs).
    optional: true,
    mutate(raw) {
      const cell = firstCell(
        raw,
        (_n, table, column, value) =>
          table.sqliteClockColumns.includes(column) && value === null,
      );
      if (!cell) return null;
      cell.row[cell.column] = new Date(
        raw.meta.wallStartMs + 1000,
      ).toISOString();
      return raw;
    },
  },
  {
    name: "explicit value in a clock-default column became NULL",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (_n, table, column, value) =>
          table.sqliteClockColumns.includes(column) &&
          Number.isFinite(timestampMs(value)) &&
          !inWall(raw, value),
      );
      if (!cell) return null;
      cell.row[cell.column] = null;
      return raw;
    },
  },
  {
    name: "explicit timestamp in a clock-default column changed",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (_n, table, column, value) =>
          table.sqliteClockColumns.includes(column) &&
          Number.isFinite(timestampMs(value)) &&
          !inWall(raw, value),
      );
      if (!cell) return null;
      cell.row[cell.column] = isoPlus(cell.row[cell.column], 1000);
      return raw;
    },
  },
  {
    name: "explicit collected_at changed",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (name, _t, column, value) =>
          name === "data_files" && column === "collected_at" && !!value,
      );
      if (!cell) return null;
      cell.row.collected_at = isoPlus(cell.row.collected_at, 1000);
      return raw;
    },
  },
  {
    name: "autogenerated clock value became an explicit value",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (_n, table, column, value) =>
          table.sqliteClockColumns.includes(column) && inWall(raw, value),
      );
      if (!cell) return null;
      cell.row[cell.column] = "2031-01-01T00:00:03Z";
      return raw;
    },
  },
  {
    name: "NULL became a value (non-clock column)",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (name, _t, column, value) =>
          name === "data_files" && column === "file_id" && value === null,
      );
      if (!cell) return null;
      cell.row.file_id = "unexpected";
      return raw;
    },
  },
  {
    name: "value became NULL (non-clock column)",
    mutate(raw) {
      const cell = firstCell(
        raw,
        (name, _t, column, value) =>
          name === "data_files" && column === "data_point_id" && !!value,
      );
      if (!cell) return null;
      cell.row.data_point_id = null;
      return raw;
    },
  },
  {
    name: "same-length uploaded payload changed (key and length unchanged)",
    mutate(raw) {
      const upload = firstUpload(raw);
      if (!upload || !flipFirstString(upload.envelope.data)) return null;
      return raw;
    },
  },
  {
    name: "uploaded payload metadata (collectedAt) changed",
    mutate(raw) {
      const upload = firstUpload(raw);
      if (!upload) return null;
      upload.envelope.collectedAt = isoPlus(upload.envelope.collectedAt, 1000);
      return raw;
    },
  },
  {
    name: "upload no longer decrypts with the derived scope key",
    mutate(raw) {
      const upload = firstUpload(raw);
      if (!upload) return null;
      delete upload.envelope;
      delete upload.plaintextSha256;
      upload.decryptError = "bad key";
      return raw;
    },
  },
  {
    name: "commitment no longer matches the uploaded plaintext",
    mutate(raw) {
      if (!raw.commitments.length) return null;
      raw.commitments[0].dataHashMatches = false;
      return raw;
    },
  },
  {
    name: "scope key derivation changed",
    mutate(raw) {
      const [scope] = Object.keys(raw.scopeKeyFingerprints);
      if (!scope) return null;
      raw.scopeKeyFingerprints[scope] = "0".repeat(64);
      return raw;
    },
  },
  {
    name: "two receipts' import-id references swapped",
    mutate(raw) {
      const [first, second] = receipts(raw);
      if (!first || !second) return null;
      const idOf = (file) => file.text.match(UUID)?.[0];
      const [a, b] = [idOf(first), idOf(second)];
      if (!a || !b || a === b) return null;
      first.text = first.text.split(a).join(b);
      second.text = second.text.split(b).join(a);
      return raw;
    },
  },
  {
    name: "meaningful response header removed",
    mutate(raw) {
      const op = raw.operations.find(
        (entry) => entry.value?.headers?.["content-type"],
      );
      if (!op) return null;
      delete op.value.headers["content-type"];
      return raw;
    },
  },
  {
    name: "meaningful response header value changed",
    mutate(raw) {
      const op = raw.operations.find(
        (entry) => entry.value?.headers?.["access-control-allow-origin"],
      );
      if (!op) return null;
      op.value.headers["access-control-allow-origin"] = "null";
      return raw;
    },
  },
];

export const EQUIVALENCES = [
  {
    name: "every UUID renamed consistently",
    mutate(raw) {
      const names = new Map();
      const rename = (text) =>
        text.replace(UUID, (id) => {
          const key = id.toLowerCase();
          if (!names.has(key))
            names.set(
              key,
              `${(names.size + 0x1000).toString(16).padStart(8, "0")}-aaaa-4bbb-8ccc-${String(names.size).padStart(12, "0")}`,
            );
          return names.get(key);
        });
      return JSON.parse(rename(JSON.stringify(raw)));
    },
  },
  {
    name: "every SQLite wall-clock value shifted inside the run window",
    mutate(raw) {
      let touched = false;
      for (const table of Object.values(raw.tables))
        for (const row of table.rows)
          for (const column of table.sqliteClockColumns)
            if (inWall(raw, row[column])) {
              row[column] = isoPlus(row[column], 2000);
              touched = true;
            }
      return touched ? raw : null;
    },
  },
  {
    name: "volatile response header values changed",
    mutate(raw) {
      let touched = false;
      for (const op of raw.operations)
        for (const header of Object.keys(op.value?.headers ?? {}))
          if (VOLATILE_HEADERS.has(header)) {
            op.value.headers[header] = `changed-${touched}`;
            touched = true;
          }
      // Without a volatile header in the capture there is nothing to check.
      return touched ? raw : structuredClone(raw);
    },
  },
];

/** Run every control against one raw capture. Returns the failures. */
export function runControls(raw, normalizeRaw = normalize) {
  const failures = [];
  const base = normalizeRaw(raw);
  const results = [];
  for (const [kind, controls] of [
    ["mutant", MUTANTS],
    ["equivalence", EQUIVALENCES],
  ])
    for (const control of controls) {
      const edited = control.mutate(structuredClone(raw));
      if (!edited) {
        // An optional control needs a shape only a synthetic capture has.
        if (control.optional)
          results.push({ kind, name: control.name, skipped: true });
        else
          failures.push(
            `${kind} "${control.name}" does not apply to this capture`,
          );
        continue;
      }
      const found = differences(base, normalizeRaw(edited), "", [], 3);
      const ok = kind === "mutant" ? found.length > 0 : found.length === 0;
      results.push({ kind, name: control.name, ok });
      if (!ok)
        failures.push(
          kind === "mutant"
            ? `mutant NOT detected: ${control.name}`
            : `equivalence broken: ${control.name}: ${found[0]}`,
        );
    }
  return { failures, results };
}

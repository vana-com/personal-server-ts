// Controls for the normalizer, on a hand-built RAW capture of the same shape
// the scenario writes. Run: node --test scripts/legacy-gate-differential/
//
// Set GATE_RAW_CAPTURE to a real raw-transcript.json to run the same controls
// on a real capture (compare.mjs does this on every run).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  EQUIVALENCES,
  MUTANTS,
  differences,
  normalize,
  runControls,
} from "./normalize.mjs";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const WALL = Date.parse("2026-10-24T19:00:00.000Z");
const headers = {
  "access-control-allow-origin": "*",
  "content-type": "application/json",
  date: "Sat, 24 Oct 2026 19:00:00 GMT",
};

function fixture() {
  const receipt = (id, scope) => ({
    path: `data/.scope-imports/receipts/${id}.json`,
    size: 90,
    text: JSON.stringify({
      importId: id,
      scope,
      completedAt: "2031-01-01T00:00:05.000Z",
    }),
  });
  return structuredClone({
    meta: {
      wallStartMs: WALL,
      wallEndMs: WALL + 20_000,
      clockBase: "2031-01-01",
    },
    operations: [
      {
        name: "begin",
        value: { status: 201, headers: { ...headers }, body: { importId: A } },
      },
      {
        name: "second",
        value: { status: 201, headers: { ...headers }, body: { importId: B } },
      },
      { name: "state", value: { entries: [1] } },
    ],
    gateway: [
      {
        method: "registerDataPoint",
        args: [{ scope: "a.b", dataHash: "0x01" }],
      },
    ],
    storage: [
      {
        method: "PUT",
        path: "/v1/chains/1/blobs/0xo/a.b/1",
        cipherBytes: 200,
        plaintextSha256: "ab",
        envelope: {
          version: "1.0",
          scope: "a.b",
          collectedAt: "2031-01-01T00:00:01.000Z",
          data: { profile: { name: "json" } },
        },
      },
    ],
    commitments: [
      {
        scope: "a.b",
        version: "1",
        registrations: 1,
        dataHashMatches: true,
        metadataHashMatches: true,
      },
    ],
    scopeKeyFingerprints: { "a.b": "f".repeat(64) },
    schema: { userVersion: 17, objects: [] },
    gateRows: {},
    tables: {
      data_files: {
        sqliteClockColumns: ["created_at"],
        rows: [
          {
            id: 1,
            file_id: null,
            collected_at: "2031-01-01T00:00:01.000Z",
            created_at: "2026-10-24T19:00:03Z",
            data_point_id: "dp-1",
            payload: { $blob: `blob ${A}` },
          },
          {
            id: 2,
            file_id: null,
            collected_at: "2031-01-01T00:00:02.000Z",
            created_at: "2026-10-24T19:00:04Z",
            data_point_id: "dp-2",
            payload: null,
          },
        ],
      },
      audit: {
        // A nullable column with a clock default: only a synthetic capture
        // has one, so this is where the NULL controls apply.
        sqliteClockColumns: ["seen_at"],
        rows: [
          { id: 1, seen_at: null },
          { id: 2, seen_at: "2026-10-24T19:00:06Z" },
        ],
      },
      authority: {
        sqliteClockColumns: ["established_at"],
        rows: [
          { scope: "x.y", established_at: "2030-12-31T23:59:59.000Z" },
          { scope: "z.w", established_at: "2026-10-24T19:00:05.123Z" },
        ],
      },
    },
    files: [receipt(A, "a.b"), receipt(B, "c.d")],
    config: { sync: { enabled: true }, legacyWriteShutdownEnabled: false },
  });
}

test("controls: every mutant is detected and every volatile-only edit is equal", () => {
  const { failures, results } = runControls(fixture());
  assert.deepEqual(failures, []);
  assert.equal(results.length, MUTANTS.length + EQUIVALENCES.length);
  // The synthetic capture exercises every control, optional ones included.
  assert.deepEqual(
    results.filter((entry) => entry.skipped),
    [],
  );
});

/** The first harness's normalization, kept only to prove the controls have
 * teeth: every clock-default column was one constant, every id collapsed
 * to one token inside file hashes, storage kept path and ciphertext length,
 * and responses kept status and body. */
function lossyNormalize(raw) {
  const sha = (text) =>
    createHash("sha256").update(text, "latin1").digest("hex");
  const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
  const out = {
    operations: raw.operations.map(({ name, value }) => ({
      name,
      value:
        value?.status === undefined
          ? value
          : { status: value.status, body: value.body },
    })),
    gateway: raw.gateway,
    storage: raw.storage.map(({ method, path, cipherBytes }) => ({
      method,
      path,
      bytes: cipherBytes,
    })),
    tables: Object.fromEntries(
      Object.entries(raw.tables).map(([name, table]) => [
        name,
        table.rows.map((row) =>
          Object.fromEntries(
            Object.entries(row).map(([column, value]) => [
              column,
              table.sqliteClockColumns.includes(column)
                ? "<sqlite-clock>"
                : value?.$blob !== undefined
                  ? `<blob ${sha(value.$blob)}>`
                  : value,
            ]),
          ),
        ),
      ]),
    ),
    files: raw.files.map((file) => ({
      path: file.path,
      sha256: sha(file.text.replace(UUID, "<uuid>")),
    })),
  };
  const ids = new Map();
  return JSON.parse(
    JSON.stringify(out).replace(UUID, (id) => {
      if (!ids.has(id)) ids.set(id, `<uuid-${ids.size + 1}>`);
      return ids.get(id);
    }),
  );
}

test("the controls fail the old lossy normalization (red), not the new one (green)", () => {
  const lossy = runControls(fixture(), lossyNormalize).failures;
  for (const name of [
    "explicit timestamp in a clock-default column changed",
    "autogenerated clock value became an explicit value",
    "same-length uploaded payload changed (key and length unchanged)",
    "uploaded payload metadata (collectedAt) changed",
    "two receipts' import-id references swapped",
    "meaningful response header removed",
    "meaningful response header value changed",
    "NULL in a clock-default column became an autogenerated-looking value",
    "explicit value in a clock-default column became NULL",
  ])
    assert.ok(
      lossy.includes(`mutant NOT detected: ${name}`),
      `the lossy normalizer should miss: ${name}`,
    );
  assert.deepEqual(runControls(fixture()).failures, []);
});

test("real capture controls", { skip: !process.env.GATE_RAW_CAPTURE }, () => {
  const raw = JSON.parse(readFileSync(process.env.GATE_RAW_CAPTURE, "utf8"));
  assert.deepEqual(runControls(raw).failures, []);
});

test("a mutant differs only where it edited", () => {
  const raw = fixture();
  const base = normalize(raw);
  const where = (name) => {
    const edited = MUTANTS.find((m) => m.name === name).mutate(
      structuredClone(raw),
    );
    return differences(base, normalize(edited)).map(
      (line) => line.split(":")[0],
    );
  };
  assert.deepEqual(
    where("same-length uploaded payload changed (key and length unchanged)"),
    ["/storage/0/envelope/data/profile/name"],
  );
  assert.deepEqual(where("meaningful response header removed"), [
    "/operations/0/value/headers/content-type",
  ]);
  assert.deepEqual(
    where("explicit timestamp in a clock-default column changed"),
    ["/tables/authority/rows/0/established_at"],
  );
  assert.deepEqual(where("NULL became a value (non-clock column)"), [
    "/tables/data_files/rows/0/file_id",
  ]);
  assert.deepEqual(
    where(
      "NULL in a clock-default column became an autogenerated-looking value",
    ),
    ["/tables/audit/rows/0/seen_at", "/tables/audit/autoClock/seen_at/values"],
  );
  assert.deepEqual(
    where("explicit value in a clock-default column became NULL"),
    ["/tables/authority/rows/0/established_at"],
  );
  assert.deepEqual(
    where("autogenerated clock value became an explicit value"),
    [
      "/tables/data_files/rows/0/created_at",
      "/tables/data_files/autoClock/created_at/values",
    ],
  );
  const swapped = where("two receipts' import-id references swapped");
  assert.ok(
    swapped.length > 0 && swapped.every((path) => path.startsWith("/files/")),
  );
});

test("the id map is global and bijective", () => {
  const raw = fixture();
  const out = JSON.stringify(normalize(raw));
  assert.ok(out.includes("<uuid-1>") && out.includes("<uuid-2>"));
  assert.ok(!out.includes(A) && !out.includes(B));
  // A receipt that names the other import is a different transcript.
  const crossed = fixture();
  crossed.files[0].text = crossed.files[0].text.replace(A, B);
  assert.ok(differences(normalize(raw), normalize(crossed)).length > 0);
});

test("explicit and NULL values survive; only in-window clock values are auto", () => {
  const { tables } = normalize(fixture());
  const [first, second] = tables.authority.rows;
  assert.equal(first.established_at, "2030-12-31T23:59:59.000Z");
  assert.equal(second.established_at, "<sqlite-clock:auto>");
  assert.equal(tables.data_files.rows[0].file_id, null);
  assert.equal(tables.audit.rows[0].seen_at, null);
  assert.deepEqual(tables.data_files.autoClock.created_at, {
    values: 2,
    neverDecreasing: true,
  });
});

test("an auto value that runs backwards is recorded", () => {
  const raw = fixture();
  raw.tables.data_files.rows[1].created_at = "2026-10-24T19:00:01Z";
  assert.equal(
    normalize(raw).tables.data_files.autoClock.created_at.neverDecreasing,
    false,
  );
});

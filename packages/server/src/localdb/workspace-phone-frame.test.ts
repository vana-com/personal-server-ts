import { expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  createSqlWorkspaceValues,
  openLogWorkspace,
  runtimeAdmission,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
const FRAME = 4 * 1024 * 1024;
const encode = (value: unknown): unknown =>
  typeof value === "bigint"
    ? { $: "i", v: String(value) }
    : value instanceof Uint8Array
      ? { $: "b", v: Buffer.from(value).toString("base64") }
      : Array.isArray(value)
        ? value.map(encode)
        : value && typeof value === "object"
          ? Object.fromEntries(
              Object.entries(value).map(([k, v]) => [k, encode(v)]),
            )
          : value;
// Contract fake of the phone driver's small-SQL frame path: tagged scalars,
// complete request/reply envelopes, incarnation binding and a 4 MiB cap.
// Workspace chunks never call the phone driver's large-value staging methods.
it("phone host workspace SQL conforms to encoded-envelope frame sizing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workspace-frame-")),
    base = openBetterSqlite3(join(dir, "db"));
  let inFlight = 0,
    peak = 0,
    maxBytes = 0;
  const frame = (value: unknown) => {
    const bytes = Buffer.byteLength(JSON.stringify(encode(value)));
    maxBytes = Math.max(maxBytes, bytes);
    expect(bytes).toBeLessThanOrEqual(FRAME);
  };
  const run = async <T>(request: unknown, fn: () => Promise<T>): Promise<T> => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    try {
      frame(request);
      const value = await fn();
      frame({ ok: true, value });
      return value;
    } finally {
      inFlight--;
    }
  };
  const db: SqlDriver = {
    ...base,
    info: { ...base.info, host: "phone" },
    query: (sql, params) =>
      run({ operation: "query.framed", sql, params, incarnation: 'db"é' }, () =>
        base.query(sql, params),
      ),
    batch: (statements) =>
      run(
        { operation: "batch", id: "id", statements, incarnation: 'db"é' },
        () => base.batch(statements),
      ),
  };
  try {
    await db.query("PRAGMA journal_mode=WAL");
    await db.query("PRAGMA synchronous=NORMAL");
    await migrate(db);
    await db.batch([
      {
        sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','t','d',0)",
      },
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','t','','active')",
      },
    ]);
    const b = {
      owner: "o",
      databaseIncarnation: 'db"é',
      connection: "c",
      generation: 1,
      keyCheck: "k",
      operation: "op",
      expectedHead: "h",
      codecVersion: 1,
    };
    const ws = await openLogWorkspace(db, b),
      values = createSqlWorkspaceValues(db, () => "value", FRAME);
    const part = Buffer.alloc(65536, 0xff),
      hash = createHash("sha256");
    for (let i = 0; i < 80; i++) hash.update(part);
    const writer = await values.begin(
      b,
      80 * part.length,
      hash.digest("hex"),
      "binary",
    );
    const lease = await runtimeAdmission.acquire("op", 1024 * 1024);
    try {
      for (let i = 0; i < 80; i++)
        await values.append(writer, i * part.length, part, lease);
    } finally {
      await lease.release();
    }
    const sealed = await values.seal(writer);
    expect(sealed.bytes).toBeGreaterThan(FRAME);
    const unit = await ws.unit("u", "d", 0);
    if (unit.state !== "staging") throw new Error("staging");
    await unit.stage("outputs", { objectKey: '\\"é', value: sealed });
    await unit.commit();
    expect(peak).toBe(1);
    expect(maxBytes).toBeLessThan(FRAME);
    // Mirrors frame maxChunkBytes: base64 expansion plus the ENTIRE envelope.
    const envelope = {
      operation: "stage.chunk",
      stagingId: '\\"é',
      offset: Number.MAX_SAFE_INTEGER,
      base64: "",
      digest: "0".repeat(64),
      incarnation: 'db"é',
    };
    const max =
      3 * Math.floor((FRAME - Buffer.byteLength(JSON.stringify(envelope))) / 4);
    frame({ ...envelope, base64: Buffer.alloc(max).toString("base64") });
    expect(
      Buffer.byteLength(
        JSON.stringify({
          ...envelope,
          base64: Buffer.alloc(max + 3).toString("base64"),
        }),
      ),
    ).toBeGreaterThan(FRAME);
  } finally {
    await base.close();
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);

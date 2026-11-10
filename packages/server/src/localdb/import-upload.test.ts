import { createHash } from "node:crypto";
import {
  mkdtempSync,
  rmSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  statSync,
  mkdirSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  stageLegacyImportUpload,
  openStagedLegacyImportUpload,
  acceptLegacyImportUpload,
} from "./import-upload.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { readBackLegacyImport } from "../../../core/src/localdb/import-readback.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
const dirs: string[] = [];
const dbs: SqlDriver[] = [];
afterEach(async () => {
  for (const db of dbs.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
function fixture(text = JSON.stringify({ id: "one", text: "é" }) + "\n") {
  const root = mkdtempSync(join(process.cwd(), ".import-upload-test-"));
  dirs.push(root);
  const bytes = Buffer.from(text);
  const revision = createHash("sha256").update(bytes).digest("hex");
  const options = {
    owner: "0xabc",
    network: "test",
    stagingRoot: root,
    upload: {
      source: "install",
      revision,
      artifactDigest: "retained",
      stream: "profile",
      body: {
        async *[Symbol.asyncIterator]() {
          yield bytes;
        },
      },
    },
    resolveArtifact: async (digest: string) =>
      digest === "retained"
        ? {
            connector: "profile-source",
            version: "1",
            streams: [
              {
                name: "profile",
                primaryKey: ["id"],
                semantics: "mutable_state" as const,
              },
            ],
          }
        : null,
    resolveTarget: async () => ({
      connectionId: "control",
      connector: "profile-source",
      stream: "profile",
      primaryKey: ["id"],
      semantics: "mutable_state" as const,
      incremental: true,
    }),
  };
  return { root, bytes, options };
}
it("upload-verified-artifact-only", async () => {
  const f = fixture();
  let pulled = false;
  const body = {
    async *[Symbol.asyncIterator]() {
      pulled = true;
      yield f.bytes;
    },
  };
  for (const upload of [
    { ...f.options.upload, artifactDigest: "unknown", body },
    { ...f.options.upload, stream: "undeclared", body },
  ])
    await expect(
      stageLegacyImportUpload({ ...f.options, upload }),
    ).rejects.toThrow("upload_artifact_unverified");
  expect(pulled).toBe(false);
  expect(readdirSync(f.root)).toEqual([]);
  await expect(
    stageLegacyImportUpload({ ...f.options, resolveTarget: async () => null }),
  ).rejects.toThrow("upload_identity_invalid");
});
it("upload-backpressure-4mib", async () => {
  const chunks = [
    Buffer.from(
      JSON.stringify({ id: "one", text: "x".repeat(600_000) }) + "\n",
    ),
    Buffer.from(
      JSON.stringify({ id: "two", text: "x".repeat(600_000) }) + "\n",
    ),
  ];
  const f = fixture(Buffer.concat(chunks).toString());
  let written = 0;
  const body = {
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) {
        if (written) {
          const pending = readdirSync(f.root).find((p) =>
            p.endsWith(".pending"),
          )!;
          expect(statSync(join(f.root, pending)).size).toBe(written);
        }
        yield chunk;
        written += chunk.length;
      }
    },
  };
  const source = await stageLegacyImportUpload({
    ...f.options,
    upload: { ...f.options.upload, body },
  });
  let count = 0;
  for await (const _record of source.records()) count++;
  expect(count).toBe(2);
});
it("upload-oversize-row-refuses", async () => {
  const f = fixture(
    JSON.stringify({ id: "one", text: "x".repeat(4 * 1024 * 1024) }) + "\n",
  );
  await expect(stageLegacyImportUpload(f.options)).rejects.toThrow(
    "upload_oversize",
  );
  expect(readdirSync(f.root)).toEqual([]);
});
it("upload-retry-same-revision", async () => {
  const f = fixture();
  const first = await stageLegacyImportUpload(f.options);
  const names = readdirSync(f.root);
  const saved = names.map((n) => readFileSync(join(f.root, n)).toString("hex"));
  expect((await stageLegacyImportUpload(f.options)).source).toBe(first.source);
  expect(readdirSync(f.root)).toEqual(names);
  await expect(
    stageLegacyImportUpload({
      ...f.options,
      upload: {
        ...f.options.upload,
        body: {
          async *[Symbol.asyncIterator]() {
            yield Buffer.from('{"id":"changed"}\n');
          },
        },
      },
    }),
  ).rejects.toThrow("source_changed");
  expect(
    names.map((n) => readFileSync(join(f.root, n)).toString("hex")),
  ).toEqual(saved);
});
it("upload-unicode-split-and-envelope-boundary", async () => {
  const f = fixture();
  const index = f.bytes.indexOf(Buffer.from("é")) + 1;
  const source = await stageLegacyImportUpload({
    ...f.options,
    upload: {
      ...f.options.upload,
      body: {
        async *[Symbol.asyncIterator]() {
          yield f.bytes.subarray(0, index);
          yield f.bytes.subarray(index);
        },
      },
    },
  });
  const records = [];
  for await (const record of source.records()) records.push(record);
  expect(records).toEqual([{ id: "one", text: "é" }]);
  const overhead =
    Buffer.byteLength(
      JSON.stringify({
        source: "install",
        revision: "0".repeat(64),
        artifactDigest: "retained",
        stream: "profile",
      }),
    ) + 1;
  const length =
    4 * 1024 * 1024 -
    overhead -
    Buffer.byteLength(JSON.stringify({ id: "one", text: "" }));
  const boundary = fixture(
    JSON.stringify({ id: "one", text: "x".repeat(length) }) + "\n",
  );
  expect((await stageLegacyImportUpload(boundary.options)).revision).toBe(
    boundary.options.upload.revision,
  );
  const over = fixture(
    JSON.stringify({ id: "one", text: "x".repeat(length + 1) }) + "\n",
  );
  await expect(stageLegacyImportUpload(over.options)).rejects.toThrow(
    "upload_oversize",
  );
});
it("upload-unsealed-malformed-and-changed-seal-refuse", async () => {
  const f = fixture();
  await expect(openStagedLegacyImportUpload(f.options)).rejects.toThrow();
  const bad = fixture('{"id":');
  await expect(stageLegacyImportUpload(bad.options)).rejects.toThrow(
    "invalid_record",
  );
  expect(readdirSync(bad.root)).toEqual([]);
  const missing = fixture('{"value":1}\n');
  await expect(stageLegacyImportUpload(missing.options)).rejects.toThrow(
    "invalid_record",
  );
  await stageLegacyImportUpload(f.options);
  const data = readdirSync(f.root).find((n) => n.endsWith(".ndjson"))!;
  writeFileSync(join(f.root, data), "{}\n");
  await expect(openStagedLegacyImportUpload(f.options)).rejects.toThrow(
    "source_changed",
  );
});
it("upload-symlinked-root-refuses-before-writing", async () => {
  const f = fixture();
  const target = join(f.root, "target");
  mkdirSync(target);
  const path = join(f.root, "link");
  symlinkSync(target, path);
  await expect(
    stageLegacyImportUpload({ ...f.options, stagingRoot: join(path, "new") }),
  ).rejects.toThrow("upload_path_refused");
  expect(readdirSync(target)).toEqual([]);
});
it("upload-d6-p7-close-reopen-readback", async () => {
  const f = fixture();
  const path = join(f.root, "local.sqlite");
  let db = await openLocalDb(openBetterSqlite3(path), {
    owner: "0xabc",
    network: "test",
    deviceId: "device",
  });
  dbs.push(db);
  await db.batch([
    {
      sql: "INSERT INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('control','profile-source','known',1,'active')",
    },
  ]);
  const unused = async (): Promise<never> => {
    throw new Error("unexpected external call");
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {
      read: unused,
      post: unused,
      listControlRows: unused,
      listStreamRows: unused,
    },
    blobs: { get: unused, put: unused },
    keys: {
      namespaceHmac: unused,
      encrypt: unused,
      encryptPart: unused,
      decrypt: unused,
    },
    signer: { signAddData: unused },
    logger: { info() {}, warn() {} },
    now: () => 1,
    newOp: () => `op-${++op}`,
  };
  for (const install of ["desktop-install", "phone-install"]) {
    const options = {
      ...f.options,
      upload: { ...f.options.upload, source: install },
    };
    await stageLegacyImportUpload(options);
    const source = await openStagedLegacyImportUpload(options);
    expect((await acceptLegacyImportUpload(deps, source)).kind).toBe(
      "imported",
    );
    await db.close();
    dbs.splice(dbs.indexOf(db), 1);
    db = await openLocalDb(openBetterSqlite3(path), {
      owner: "0xabc",
      network: "test",
      deviceId: "device",
    });
    dbs.push(db);
    Object.assign(deps, { db });
    const reopened = await openStagedLegacyImportUpload(options);
    expect((await readBackLegacyImport(deps, reopened)).pass).toBe(true);
    expect((await acceptLegacyImportUpload(deps, reopened)).kind).toBe(
      "already-imported",
    );
  }
  expect(await db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 1 },
  ]);
  expect(await db.query("SELECT count(*) AS n FROM import_ledger")).toEqual([
    { n: 2 },
  ]);
});
it("upload-seal-binds-target-and-owner", async () => {
  const f = fixture();
  await stageLegacyImportUpload(f.options);
  await expect(
    openStagedLegacyImportUpload({
      ...f.options,
      resolveTarget: async () => ({
        ...(await f.options.resolveTarget()),
        connectionId: "other",
      }),
    }),
  ).rejects.toThrow("upload_identity_changed");
  await expect(
    openStagedLegacyImportUpload({ ...f.options, owner: "0xdef" }),
  ).rejects.toThrow();
  expect(
    readdirSync(f.root).filter((name) => name.endsWith(".seal.json")),
  ).toHaveLength(1);
});
it("upload-changed-bytes-refuse-before-first-record", async () => {
  const f = fixture();
  const source = await stageLegacyImportUpload(f.options);
  const data = readdirSync(f.root).find((name) => name.endsWith(".ndjson"))!;
  writeFileSync(join(f.root, data), '{"id":"replacement"}\n');
  await expect(source.records()[Symbol.asyncIterator]().next()).rejects.toThrow(
    "source_changed",
  );
});

/**
 * Canonical record ingest on a REAL bootstrapped Personal Server.
 *
 * Everything goes through `createServer` with a real config, a real storage
 * root, real declaration files on disk, and a real owner token. These are the
 * storage-design G1 oracles for P1-P4:
 *
 *   - P1: a configured declaration mounts the RS on a fresh server that holds
 *     no legacy `data_files` rows, and a digest-pinned declaration whose bytes
 *     changed is refused.
 *   - P2: two sources that declare the same stream name keep separate
 *     declarations on ingest and read.
 *   - P3: each envelope gets an exact `accepted` | `unchanged` | `rejected`
 *     outcome, and `unchanged` writes nothing.
 *   - P4: the ingest body is bounded.
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { MAX_INGEST_BODY_BYTES } from "./routes/pdpp-records.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const CLAUDE = "https://registry.pdpp.dev/connectors/claude";
const OURA = "https://registry.pdpp.dev/connectors/oura";

// Both sources declare `profile`, with different primary keys. Only oura
// declares `sleep` (mutable) and `events` (append_only).
const CLAUDE_DECLARATION = JSON.stringify({
  source_id: CLAUDE,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "profile",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});
const OURA_DECLARATION = JSON.stringify({
  source_id: OURA,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "profile",
      fields: ["user_id", "email"],
      required_fields: ["user_id"],
      primary_key: ["user_id"],
    },
    {
      name: "events",
      semantics: "append_only",
      fields: ["id", "kind"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;

async function writeDeclaration(name: string, document: string) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${name}.json`);
  await writeFile(path, document, "utf-8");
  return path;
}

function sha256(document: string): string {
  return createHash("sha256").update(document, "utf8").digest("hex");
}

async function boot(
  declarationPaths: (string | { path: string; sha256: string })[],
) {
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: { enabled: true, declarationPaths },
    }),
    { serverDir: tempDir, dataDir: join(tempDir, "data") },
  );
}

async function bootBoth() {
  return boot([
    await writeDeclaration("claude", CLAUDE_DECLARATION),
    await writeDeclaration("oura", OURA_DECLARATION),
  ]);
}

async function ownerToken(context: ServerContext): Promise<string> {
  const response = await context.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: { authorization: `Bearer ${context.devToken}` },
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

interface IngestBody {
  accepted: number;
  unchanged: number;
  rejected: { index: number; reason: string }[];
  results: {
    index: number;
    outcome: "accepted" | "unchanged" | "rejected";
    reason?: string;
    flag?: string;
  }[];
}

async function ingest(
  context: ServerContext,
  token: string,
  stream: string,
  body: unknown,
): Promise<{ status: number; body: IngestBody }> {
  const response = await context.app.request(
    `/v1/streams/${stream}/records/ingest`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: typeof body === "string" ? body : JSON.stringify(body),
    },
  );
  return {
    status: response.status,
    body: (await response.json()) as IngestBody,
  };
}

async function read(context: ServerContext, token: string, path: string) {
  const response = await context.app.request(path, {
    headers: { authorization: `Bearer ${token}` },
  });
  return { status: response.status, body: (await response.json()) as any };
}

function outcomes(body: IngestBody) {
  return body.results.map((r) => r.outcome);
}

/** Write-clock value and history row count, read from the server's own DB. */
function storeCounters() {
  const db = new Database(join(tempDir, "index.db"), { readonly: true });
  try {
    const clock = db
      .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
      .get() as { value: number };
    const changes = db
      .prepare("SELECT COUNT(*) AS n FROM pdpp_record_changes")
      .get() as { n: number };
    return { clock: clock.value, changes: changes.n };
  } finally {
    db.close();
  }
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-storage-ingest-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("P1: configured declaration admission", () => {
  it("mounts the RS for a configured declaration on a server with no legacy data", async () => {
    ctx = await boot([await writeDeclaration("claude", CLAUDE_DECLARATION)]);
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "profile", {
      instance: `claude:${owner}`,
      key: "u1",
      data: { id: "u1", name: "A" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(result.status).toBe(200);
    expect(outcomes(result.body)).toEqual(["accepted"]);
  });

  it("follows the configured declaration across a restart that changes it", async () => {
    const path = await writeDeclaration("claude", CLAUDE_DECLARATION);
    ctx = await boot([path]);
    await ctx.cleanup();

    const upgraded = JSON.parse(CLAUDE_DECLARATION);
    upgraded.version = "2";
    upgraded.streams.push({
      name: "projects",
      fields: ["id"],
      required_fields: ["id"],
      primary_key: ["id"],
    });
    await writeFile(path, JSON.stringify(upgraded), "utf-8");
    ctx = await boot([path]);
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "projects", {
      instance: `claude:${owner}`,
      key: "p1",
      data: { id: "p1" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(result.status).toBe(200);
    expect(outcomes(result.body)).toEqual(["accepted"]);

    // And back: a downgrade re-points to the retained earlier version.
    await ctx.cleanup();
    await writeFile(path, CLAUDE_DECLARATION, "utf-8");
    ctx = await boot([path]);
    const downgraded = await ingest(ctx, await ownerToken(ctx), "projects", {
      instance: `claude:${owner}`,
      key: "p2",
      data: { id: "p2" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(downgraded.status).toBe(404);
  });

  it("admits a pinned declaration whose bytes match the configured digest", async () => {
    const path = await writeDeclaration("claude", CLAUDE_DECLARATION);
    ctx = await boot([{ path, sha256: sha256(CLAUDE_DECLARATION) }]);
    const token = await ownerToken(ctx);
    const streams = await read(ctx, token, "/v1/streams/profile");
    expect(streams.status).toBe(200);
  });

  it("refuses a pinned declaration whose bytes do not match the configured digest", async () => {
    const path = await writeDeclaration("claude", CLAUDE_DECLARATION);
    ctx = await boot([{ path, sha256: sha256(`${CLAUDE_DECLARATION} `) }]);
    // Nothing was retained, so neither the AS nor the RS mounts.
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization: `Bearer ${ctx.devToken}` },
    });
    expect(response.status).toBe(404);
  });
});

describe("P2: streams are keyed by source and stream name", () => {
  it("validates each source's profile against its own primary key", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);

    const claude = await ingest(ctx, token, "profile", {
      instance: `claude:${owner}`,
      key: "c1",
      data: { id: "c1", name: "Claude user" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    const oura = await ingest(ctx, token, "profile", {
      instance: `oura:${owner}`,
      key: "o1",
      data: { user_id: "o1", email: "o@example.com" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(claude.body)).toEqual(["accepted"]);
    expect(outcomes(oura.body)).toEqual(["accepted"]);

    // A record shaped for the other source's key is rejected.
    const crossed = await ingest(ctx, token, "profile", {
      instance: `claude:${owner}`,
      key: "o2",
      data: { user_id: "o2" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(crossed.body)).toEqual(["rejected"]);

    const c1 = await read(ctx, token, "/v1/streams/profile/records/c1");
    expect(c1.status).toBe(200);
    expect(c1.body.data).toEqual({ id: "c1", name: "Claude user" });
    const o1 = await read(ctx, token, "/v1/streams/profile/records/o1");
    expect(o1.body.data).toEqual({ user_id: "o1", email: "o@example.com" });
  });

  it("rejects a stream that the instance's source does not declare", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "events", {
      instance: `claude:${owner}`,
      key: "e1",
      data: { id: "e1", kind: "x" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(result.status).toBe(200);
    expect(result.body.results).toEqual([
      expect.objectContaining({
        index: 0,
        outcome: "rejected",
        reason: expect.stringContaining("does not declare"),
      }),
    ]);
    const listed = await read(ctx, token, "/v1/streams/events/records");
    expect(listed.body.data).toEqual([]);
  });

  it("refuses owner metadata for a stream name that two sources declare", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const ambiguous = await read(ctx, token, "/v1/streams/profile");
    expect(ambiguous.status).toBe(400);
    const unique = await read(ctx, token, "/v1/streams/events");
    expect(unique.status).toBe(200);
    expect(unique.body.primary_key).toEqual(["id"]);
  });
});

describe("P3: exact per-index outcomes", () => {
  const upsert = (key: string, data: object, emitted_at: string) => ({
    instance: `oura:${owner}`,
    key,
    data: { user_id: key, ...data },
    emitted_at,
  });
  const del = (key: string, emitted_at: string) => ({
    instance: `oura:${owner}`,
    key,
    data: null,
    emitted_at,
    op: "delete",
  });

  it("mutable_state: an equal replay is unchanged and writes nothing", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);

    const first = await ingest(ctx, token, "profile", [
      upsert(
        "k1",
        { email: "a", nested: { b: 1, a: 2 } },
        "2026-09-01T00:00:00Z",
      ),
    ]);
    expect(outcomes(first.body)).toEqual(["accepted"]);

    const baseline = await read(
      ctx,
      token,
      "/v1/streams/profile/records?changes_since=",
    );
    const token0 = baseline.body.next_changes_since as string;
    const before = storeCounters();

    // Same content, different key order and a later emitted_at.
    const replay = await ingest(ctx, token, "profile", [
      {
        instance: `oura:${owner}`,
        key: "k1",
        data: { nested: { a: 2, b: 1 }, email: "a", user_id: "k1" },
        emitted_at: "2026-09-02T00:00:00Z",
      },
    ]);
    expect(replay.body.results).toEqual([{ index: 0, outcome: "unchanged" }]);
    expect(replay.body.accepted).toBe(0);
    expect(replay.body.unchanged).toBe(1);
    expect(storeCounters()).toEqual(before);

    const after = await read(
      ctx,
      token,
      `/v1/streams/profile/records?changes_since=${encodeURIComponent(token0)}`,
    );
    expect(after.body.data).toEqual([]);

    const stored = await read(ctx, token, "/v1/streams/profile/records/k1");
    expect(stored.body.emitted_at).toBe("2026-09-01T00:00:00Z");
  });

  it("mutable_state: changed content, delete, repeated delete, and upsert over a tombstone", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "profile", [
      upsert("k1", { email: "a" }, "2026-09-01T00:00:00Z"),
      upsert("k1", { email: "b" }, "2026-09-02T00:00:00Z"),
      del("k1", "2026-09-03T00:00:00Z"),
      del("k1", "2026-09-04T00:00:00Z"),
      del("never", "2026-09-04T00:00:00Z"),
      upsert("k1", { email: "b" }, "2026-09-05T00:00:00Z"),
    ]);
    expect(outcomes(result.body)).toEqual([
      "accepted",
      "accepted",
      "accepted",
      "unchanged",
      "unchanged",
      "accepted",
    ]);
    const stored = await read(ctx, token, "/v1/streams/profile/records/k1");
    expect(stored.body.data).toEqual({ user_id: "k1", email: "b" });
    expect(stored.body.emitted_at).toBe("2026-09-05T00:00:00Z");
  });

  it("append_only: first write stands, conflicts are flagged, deletes are rejected", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const event = (kind: string, emitted_at: string) => ({
      instance: `oura:${owner}`,
      key: "e1",
      data: { id: "e1", kind },
      emitted_at,
    });
    const result = await ingest(ctx, token, "events", [
      event("wake", "2026-09-01T00:00:00Z"),
      event("wake", "2026-09-02T00:00:00Z"),
      event("sleep", "2026-09-03T00:00:00Z"),
      { ...event("wake", "2026-09-04T00:00:00Z"), data: null, op: "delete" },
    ]);
    expect(result.body.results).toEqual([
      { index: 0, outcome: "accepted" },
      { index: 1, outcome: "unchanged" },
      { index: 2, outcome: "unchanged", flag: "append_only_conflict" },
      {
        index: 3,
        outcome: "rejected",
        reason: expect.stringContaining("append_only"),
      },
    ]);
    const stored = await read(ctx, token, "/v1/streams/events/records/e1");
    expect(stored.body.data).toEqual({ id: "e1", kind: "wake" });
    expect(stored.body.emitted_at).toBe("2026-09-01T00:00:00Z");
  });

  it("treats op: null as absent (an upsert) and still rejects an invalid op", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "profile", [
      { ...upsert("k1", { email: "a" }, "2026-09-01T00:00:00Z"), op: null },
      { ...upsert("k1", { email: "a" }, "2026-09-02T00:00:00Z"), op: null },
      { ...upsert("k2", {}, "2026-09-01T00:00:00Z"), op: "remove" },
    ]);
    expect(result.body.results).toEqual([
      { index: 0, outcome: "accepted" },
      { index: 1, outcome: "unchanged" },
      {
        index: 2,
        outcome: "rejected",
        reason: "op must be 'upsert' or 'delete'",
      },
    ]);
    const stored = await read(ctx, token, "/v1/streams/profile/records/k1");
    expect(stored.body.data).toEqual({ user_id: "k1", email: "a" });
  });

  it("reports malformed envelopes by index without failing the request", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "profile", [
      upsert("k1", { email: "a" }, "2026-09-01T00:00:00Z"),
      null,
      { ...upsert("k2", {}, "2026-09-01T00:00:00Z"), key: "wrong" },
      { ...upsert("k3", {}, "2026-09-01T00:00:00Z"), data: ["not", "object"] },
      { ...upsert("k4", {}, "2026-09-01T00:00:00Z"), emitted_at: 7 },
    ]);
    expect(result.status).toBe(200);
    expect(outcomes(result.body)).toEqual([
      "accepted",
      "rejected",
      "rejected",
      "rejected",
      "rejected",
    ]);
    expect(result.body.rejected.map((r) => r.index)).toEqual([1, 2, 3, 4]);
  });
});

describe("P4: ingest body limit", () => {
  it("accepts a body larger than the old 1 MB default, up to the limit", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const result = await ingest(ctx, token, "profile", {
      instance: `oura:${owner}`,
      key: "big",
      data: { user_id: "big", email: "x".repeat(32 * 1024 * 1024) },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(result.status).toBe(200);
    expect(outcomes(result.body)).toEqual(["accepted"]);
  });

  it("refuses a body over the limit", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const oversized = JSON.stringify({
      instance: `oura:${owner}`,
      key: "huge",
      data: { user_id: "huge", email: "x".repeat(MAX_INGEST_BODY_BYTES) },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    const result = await ingest(ctx, token, "profile", oversized);
    expect(result.status).toBe(400);
    expect((result.body as any).error.code).toBe("invalid_request");
    const listed = await read(ctx, token, "/v1/streams/profile/records");
    expect(listed.body.data).toEqual([]);
  });
});

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
import { basename } from "node:path";
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
  methods?: { method_id: string; declaration_path: string }[],
) {
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths,
        methods:
          methods ??
          declarationPaths.map((entry) => {
            const path = typeof entry === "string" ? entry : entry.path;
            return {
              method_id: basename(path, ".json"),
              declaration_path: path,
            };
          }),
      },
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
  methodOverride?: string,
  generation = 1,
): Promise<{ status: number; body: IngestBody }> {
  const first = Array.isArray(body) ? body[0] : body;
  const instance =
    first && typeof first === "object" && !Array.isArray(first)
      ? (first as { instance?: string }).instance
      : undefined;
  const method = methodOverride ?? instance?.split(":", 1)[0] ?? "claude";
  const response = await context.app.request(
    `/v1/streams/${stream}/records/ingest?method=${encodeURIComponent(method)}&binding_generation=${generation}`,
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

async function reset(
  context: ServerContext,
  token: string,
  instance: string,
  expectedMethod: string,
  expectedGeneration: number,
  nextMethod: string | null,
) {
  return context.app.request(
    `/pdpp/instances/${encodeURIComponent(instance)}/reset`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        expected_method: expectedMethod,
        expected_generation: expectedGeneration,
        next_method: nextMethod,
      }),
    },
  );
}

async function uploadBlob(
  context: ServerContext,
  token: string,
  instance: string,
  method: string,
  generation: number,
  bytes: Uint8Array,
) {
  return context.app.request(
    `/v1/blobs/ingest?instance=${encodeURIComponent(instance)}&method=${encodeURIComponent(method)}&binding_generation=${generation}`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/octet-stream",
      },
      body: bytes,
    },
  );
}

async function read(context: ServerContext, token: string, path: string) {
  const response = await context.app.request(path, {
    headers: { authorization: `Bearer ${token}` },
  });
  return { status: response.status, body: (await response.json()) as any };
}

async function replace(
  context: ServerContext,
  token: string,
  stream: string,
  body: unknown,
  method = "oura",
  generation = 1,
) {
  const response = await context.app.request(
    `/v1/streams/${stream}/records/replace?method=${encodeURIComponent(method)}&binding_generation=${generation}`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    },
  );
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

function blobStoreCounters() {
  const db = new Database(join(tempDir, "index.db"), { readonly: true });
  try {
    return {
      metadata: (
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_blobs").get() as {
          n: number;
        }
      ).n,
      bytes: (
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_blob_bytes").get() as {
          n: number;
        }
      ).n,
      claims: (
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_blob_claims").get() as {
          n: number;
        }
      ).n,
    };
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

describe("P8: active method, owner reset, and generation-fenced blobs", () => {
  it("locks an instance when configuration names multiple active methods", async () => {
    const ouraPath = await writeDeclaration("oura", OURA_DECLARATION);
    ctx = await boot(
      [ouraPath],
      [
        { method_id: "oura", declaration_path: ouraPath },
        { method_id: "oura-browser", declaration_path: ouraPath },
      ],
    );
    const token = await ownerToken(ctx);
    const response = await ingest(ctx, token, "events", {
      instance: `oura:${owner}`,
      key: "event-locked",
      data: { id: "event-locked", kind: "locked" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(response.status).toBe(409);
    expect((response.body as any).error.code).toBe(
      "config_multiple_active_methods",
    );
  });

  it("rejects an unclaimed blob reference without binding an empty instance", async () => {
    const ouraPath = await writeDeclaration("oura", OURA_DECLARATION);
    ctx = await boot([ouraPath]);
    const token = await ownerToken(ctx);
    const instance = `oura:${owner}`;
    const result = await ingest(
      ctx,
      token,
      "events",
      {
        instance,
        key: "event-unclaimed",
        data: {
          id: "event-unclaimed",
          kind: "image",
          blob_ref: { blob_id: "sha256:missing" },
        },
        emitted_at: "2026-09-01T00:00:00Z",
      },
      "oura",
    );
    expect(result.body.results).toEqual([
      { index: 0, outcome: "rejected", reason: "blob_unclaimed" },
    ]);
    const binding = await read(
      ctx,
      token,
      `/pdpp/instances/${encodeURIComponent(instance)}/binding`,
    );
    expect(binding.body).toMatchObject({ method: null, empty: true });
    expect(storeCounters()).toEqual({ clock: 0, changes: 0 });
  });

  it("rejects stale A writes after reset to B and expires pre-reset change tokens", async () => {
    const ouraPath = await writeDeclaration("oura", OURA_DECLARATION);
    const claudePath = await writeDeclaration("claude", CLAUDE_DECLARATION);
    ctx = await boot([claudePath, ouraPath]);
    const token = await ownerToken(ctx);
    const instance = `oura:${owner}`;
    const binding = await read(
      ctx,
      token,
      `/pdpp/instances/${encodeURIComponent(instance)}/binding`,
    );
    expect(binding.body).toMatchObject({
      method: null,
      generation: 1,
      empty: true,
      configured_active_method: "oura",
    });
    const uploaded = await uploadBlob(
      ctx,
      token,
      instance,
      "oura",
      1,
      new TextEncoder().encode("method A image"),
    );
    expect(uploaded.status).toBe(200);
    const blob = (await uploaded.json()) as { blob_id: string };

    const event = await ingest(ctx, token, "events", {
      instance,
      key: "event-a",
      data: {
        id: "event-a",
        kind: "sleep",
        blob_ref: { blob_id: blob.blob_id },
      },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(event.body)).toEqual(["accepted"]);
    const mutable = await ingest(ctx, token, "profile", {
      instance,
      key: "user-a",
      data: { user_id: "user-a", email: "a@example.com" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(mutable.body)).toEqual(["accepted"]);

    const baseline = await read(
      ctx,
      token,
      "/v1/streams/events/records?changes_since=",
    );
    const oldToken = baseline.body.next_changes_since as string;
    const switched = await reset(
      ctx,
      token,
      instance,
      "oura",
      1,
      "oura-browser",
    );
    expect(switched.status).toBe(200);
    expect(await switched.json()).toMatchObject({
      method: "oura-browser",
      generation: 2,
    });
    expect(storeCounters()).toEqual({ clock: 4, changes: 0 });

    const staleAAfterReset = await ingest(
      ctx,
      token,
      "events",
      {
        instance,
        key: "event-a-after-switch",
        data: { id: "event-a-after-switch", kind: "late" },
        emitted_at: "2026-09-02T00:00:00Z",
      },
      "oura",
      1,
    );
    expect(staleAAfterReset.status).toBe(409);
    expect((staleAAfterReset.body as any).error.code).toBe(
      "binding_generation_mismatch",
    );
    const blobCountersAfterSwitch = blobStoreCounters();
    const staleABlobAfterReset = await uploadBlob(
      ctx,
      token,
      instance,
      "oura",
      1,
      new TextEncoder().encode("stale A bytes after switch"),
    );
    expect(staleABlobAfterReset.status).toBe(409);
    expect((await staleABlobAfterReset.json()).error.code).toBe(
      "binding_generation_mismatch",
    );
    expect(blobStoreCounters()).toEqual(blobCountersAfterSwitch);

    const resetAgain = await reset(
      ctx,
      token,
      instance,
      "oura",
      1,
      "oura-browser",
    );
    expect(resetAgain.status).toBe(200);
    expect(await resetAgain.json()).toMatchObject({ status: "already_reset" });
    const afterReset = await read(
      ctx,
      token,
      `/v1/streams/events/records?changes_since=${encodeURIComponent(oldToken)}`,
    );
    expect(afterReset.status).toBe(410);

    await ctx.cleanup();
    ctx = await boot(
      [claudePath, ouraPath],
      [
        { method_id: "claude", declaration_path: claudePath },
        { method_id: "oura-browser", declaration_path: ouraPath },
      ],
    );
    const newToken = await ownerToken(ctx);

    const staleRecord = await ingest(
      ctx,
      newToken,
      "events",
      {
        instance,
        key: "event-a-late",
        data: { id: "event-a-late", kind: "late" },
        emitted_at: "2026-09-02T00:00:00Z",
      },
      "oura",
      1,
    );
    expect(staleRecord.status).toBe(409);
    expect(
      (staleRecord.body as unknown as { error: { code: string } }).error.code,
    ).toBe("method_inactive");
    const staleBlob = await uploadBlob(
      ctx,
      newToken,
      instance,
      "oura",
      1,
      new TextEncoder().encode("late A bytes"),
    );
    expect(staleBlob.status).toBe(409);
    expect((await staleBlob.json()).error.code).toBe("method_inactive");
    const beforeStaleBlob = blobStoreCounters();
    const staleGenerationBlob = await uploadBlob(
      ctx,
      newToken,
      instance,
      "oura-browser",
      1,
      new TextEncoder().encode("old generation browser bytes"),
    );
    expect(staleGenerationBlob.status).toBe(409);
    expect((await staleGenerationBlob.json()).error.code).toBe(
      "binding_generation_mismatch",
    );
    expect(blobStoreCounters()).toEqual(beforeStaleBlob);

    const pendingBBlob = await uploadBlob(
      ctx,
      newToken,
      instance,
      "oura-browser",
      2,
      new TextEncoder().encode("pending B bytes"),
    );
    expect(pendingBBlob.status).toBe(200);
    const repeatedReset = await reset(
      ctx,
      newToken,
      instance,
      "oura",
      1,
      "oura-browser",
    );
    expect(repeatedReset.status).toBe(200);
    expect(await repeatedReset.json()).toMatchObject({
      status: "already_reset",
    });

    const beforeStaleGeneration = storeCounters();
    const staleGeneration = await ingest(
      ctx,
      newToken,
      "events",
      {
        instance,
        key: "event-b-stale-generation",
        data: { id: "event-b-stale-generation", kind: "browser" },
        emitted_at: "2026-09-02T00:00:00Z",
      },
      "oura-browser",
      1,
    );
    expect(staleGeneration.status).toBe(409);
    expect(
      (staleGeneration.body as unknown as { error: { code: string } }).error
        .code,
    ).toBe("binding_generation_mismatch");
    expect(storeCounters()).toEqual(beforeStaleGeneration);

    const bRecord = await ingest(
      ctx,
      newToken,
      "events",
      {
        instance,
        key: "event-b",
        data: { id: "event-b", kind: "browser" },
        emitted_at: "2026-09-02T00:00:00Z",
      },
      "oura-browser",
      2,
    );
    expect(bRecord.status).toBe(200);
    expect(outcomes(bRecord.body)).toEqual(["accepted"]);
  });

  it("persists claimed blob bytes and sweeps stale and orphaned rows after restart", async () => {
    const ouraPath = await writeDeclaration("oura", OURA_DECLARATION);
    ctx = await boot([ouraPath]);
    const token = await ownerToken(ctx);
    const instance = `oura:${owner}`;
    const payload = new TextEncoder().encode("persistent blob bytes");
    const response = await uploadBlob(ctx, token, instance, "oura", 1, payload);
    expect(response.status).toBe(200);
    const { blob_id: blobId } = (await response.json()) as { blob_id: string };
    const record = await ingest(ctx, token, "events", {
      instance,
      key: "event-with-blob",
      data: {
        id: "event-with-blob",
        kind: "image",
        blob_ref: { blob_id: blobId },
      },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(record.body)).toEqual(["accepted"]);
    const pendingUpload = await uploadBlob(
      ctx,
      token,
      instance,
      "oura",
      1,
      new TextEncoder().encode("pending current generation bytes"),
    );
    expect(pendingUpload.status).toBe(200);
    const pendingBlobId = (await pendingUpload.json()).blob_id as string;

    const db = new Database(join(tempDir, "index.db"));
    try {
      const staleId = "sha256:stale-claim";
      const orphanId = "sha256:orphan";
      for (const id of [staleId, orphanId]) {
        db.prepare(
          "INSERT INTO pdpp_blobs (blob_id, mime_type, size_bytes, sha256) VALUES (?, ?, ?, ?)",
        ).run(id, "application/octet-stream", 3, id.slice("sha256:".length));
        db.prepare(
          "INSERT INTO pdpp_blob_bytes (blob_id, bytes) VALUES (?, ?)",
        ).run(id, Buffer.from("old"));
      }
      db.prepare(
        "INSERT INTO pdpp_blob_claims (blob_id, instance, generation) VALUES (?, ?, ?)",
      ).run(staleId, instance, 0);
    } finally {
      db.close();
    }

    await ctx.cleanup();
    ctx = await boot([ouraPath]);
    const newToken = await ownerToken(ctx);
    const fetched = await ctx.app.request(
      `/v1/blobs/${encodeURIComponent(blobId)}`,
      {
        headers: { authorization: `Bearer ${newToken}` },
      },
    );
    expect(fetched.status).toBe(200);
    expect(new Uint8Array(await fetched.arrayBuffer())).toEqual(payload);

    const verify = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      const stale = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blobs WHERE blob_id = ?")
        .get("sha256:stale-claim") as { n: number };
      const orphan = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blobs WHERE blob_id = ?")
        .get("sha256:orphan") as { n: number };
      const live = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blob_claims WHERE blob_id = ?")
        .get(blobId) as { n: number };
      const pending = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blob_claims WHERE blob_id = ?")
        .get(pendingBlobId) as { n: number };
      const staleBytes = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blob_bytes WHERE blob_id = ?")
        .get("sha256:stale-claim") as { n: number };
      const orphanBytes = verify
        .prepare("SELECT COUNT(*) AS n FROM pdpp_blob_bytes WHERE blob_id = ?")
        .get("sha256:orphan") as { n: number };
      expect({
        stale: stale.n,
        orphan: orphan.n,
        live: live.n,
        pending: pending.n,
        staleBytes: staleBytes.n,
        orphanBytes: orphanBytes.n,
      }).toEqual({
        stale: 0,
        orphan: 0,
        live: 1,
        pending: 1,
        staleBytes: 0,
        orphanBytes: 0,
      });
    } finally {
      verify.close();
    }
  });
});

describe("$pdpp import over POST /v1/data", () => {
  it("writes no canonical row and settles the envelope when no method is configured", async () => {
    const WHOOP = "https://registry.pdpp.dev/connectors/whoop";
    const document = JSON.stringify({
      source_id: WHOOP,
      source_kind: "connector",
      version: "1",
      streams: [
        {
          name: "sleep",
          fields: ["id", "score"],
          required_fields: ["id"],
          primary_key: ["id"],
          schema: {
            type: "object",
            properties: { id: { type: "string" }, score: { type: "integer" } },
            required: ["id"],
            additionalProperties: false,
          },
        },
      ],
    });
    const path = await writeDeclaration("whoop", document);
    ctx = await boot([path], []);
    const logs: unknown[] = [];
    const warn = ctx.logger.warn.bind(ctx.logger);
    ctx.logger.warn = ((...args: unknown[]) => {
      logs.push(args[0]);
      return (warn as (...a: unknown[]) => void)(...args);
    }) as typeof ctx.logger.warn;

    const response = await ctx.app.request("/v1/data/whoop.sleep", {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx.devToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        id: "s1",
        score: "not-an-integer",
        extra: true,
        $pdpp: {
          version: 1,
          sourceId: WHOOP,
          declaration: {
            source: "whoop",
            version: "1",
            upstreamCommit: null,
            digest: `sha256:${sha256(document)}`,
          },
          stream: {
            name: "sleep",
            scope: "whoop.sleep",
            semantics: "mutable_state",
            primaryKey: ["id"],
          },
          record: { key: { id: "s1" }, op: "upsert" },
        },
      }),
    });
    expect(response.status).toBe(201);

    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      expect(
        db.prepare("SELECT COUNT(*) AS n FROM pdpp_records").get(),
      ).toEqual({ n: 0 });
    } finally {
      db.close();
    }
    expect(storeCounters()).toEqual({ clock: 0, changes: 0 });
    expect(logs).toContainEqual(
      expect.objectContaining({
        code: "method_authority",
        message: "method_required",
        permanent: true,
      }),
    );
  });
});

describe("P10c and method authority over HTTP", () => {
  async function bootSwitchable() {
    const ouraPath = await writeDeclaration("oura", OURA_DECLARATION);
    const claudePath = await writeDeclaration("claude", CLAUDE_DECLARATION);
    ctx = await boot([claudePath, ouraPath]);
    return { ouraPath, claudePath, token: await ownerToken(ctx) };
  }

  async function seedEvents(
    token: string,
    instance: string,
    keys: string[],
    firstDay = 1,
  ) {
    const result = await ingest(
      ctx!,
      token,
      "events",
      keys.map((key, i) => ({
        instance,
        key,
        data: { id: key, kind: "a" },
        emitted_at: `2026-09-0${i + firstDay}T00:00:00Z`,
      })),
      "oura",
    );
    expect(outcomes(result.body)).toEqual(keys.map(() => "accepted"));
  }

  it("expires pre-reset list and changes_since page cursors, and never mixes A and B rows", async () => {
    const { ouraPath, claudePath, token } = await bootSwitchable();
    const instance = `oura:${owner}`;
    await seedEvents(token, instance, ["a1", "a2", "a3"]);

    const listPage = await read(
      ctx!,
      token,
      "/v1/streams/events/records?order=asc&limit=1",
    );
    expect(listPage.body.data.map((r: any) => r.id)).toEqual(["a1"]);
    const listCursor = listPage.body.next_cursor as string;
    const changesPage = await read(
      ctx!,
      token,
      "/v1/streams/events/records?changes_since=&limit=1",
    );
    const changesCursor = changesPage.body.next_cursor as string;
    expect(changesCursor).toBeTruthy();

    expect(
      (await reset(ctx!, token, instance, "oura", 1, "oura-browser")).status,
    ).toBe(200);
    await ctx!.cleanup();
    ctx = await boot(
      [claudePath, ouraPath],
      [
        { method_id: "claude", declaration_path: claudePath },
        { method_id: "oura-browser", declaration_path: ouraPath },
      ],
    );
    const newToken = await ownerToken(ctx);
    const bRecord = await ingest(
      ctx,
      newToken,
      "events",
      ["b1", "b2"].map((key, i) => ({
        instance,
        key,
        data: { id: key, kind: "b" },
        emitted_at: `2026-09-0${i + 8}T00:00:00Z`,
      })),
      "oura-browser",
      2,
    );
    expect(outcomes(bRecord.body)).toEqual(["accepted", "accepted"]);

    const staleList = await read(
      ctx,
      newToken,
      `/v1/streams/events/records?order=asc&limit=1&cursor=${encodeURIComponent(listCursor)}`,
    );
    expect(staleList.status).toBe(410);
    expect(staleList.body.error.code).toBe("cursor_expired");
    const staleChanges = await read(
      ctx,
      newToken,
      `/v1/streams/events/records?changes_since=&limit=1&cursor=${encodeURIComponent(changesCursor)}`,
    );
    expect(staleChanges.status).toBe(410);

    // A listing started after the reset pages through B rows only. Its
    // cursor is re-encoded by the route and must keep the store's horizon,
    // or page 2 would be refused as a pre-reset cursor.
    const bPage1 = await read(
      ctx,
      newToken,
      "/v1/streams/events/records?order=asc&limit=1",
    );
    expect(bPage1.body.data.map((r: any) => r.id)).toEqual(["b1"]);
    const bPage2 = await read(
      ctx,
      newToken,
      `/v1/streams/events/records?order=asc&limit=1&cursor=${encodeURIComponent(bPage1.body.next_cursor)}`,
    );
    expect(bPage2.status).toBe(200);
    expect(bPage2.body.data.map((r: any) => r.id)).toEqual(["b2"]);
  });

  it("refuses a changes_since horizon that is not a non-negative integer", async () => {
    const { token } = await bootSwitchable();
    const instance = `oura:${owner}`;
    await seedEvents(token, instance, ["a1", "a2"]);
    const page = await read(
      ctx!,
      token,
      "/v1/streams/events/records?changes_since=&limit=1",
    );
    const cursor = page.body.next_cursor as string;
    const full = await read(
      ctx!,
      token,
      "/v1/streams/events/records?changes_since=&limit=10",
    );
    const token1 = full.body.next_changes_since as string;
    expect(token1).toBeTruthy();
    const forge = (encoded: string, patch: Record<string, unknown>) =>
      Buffer.from(
        JSON.stringify({
          ...JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")),
          ...patch,
        }),
      ).toString("base64url");

    // A reset after the session starts: a NaN horizon would compare false
    // against reset_clock and pass the fence.
    expect((await reset(ctx!, token, instance, "oura", 1, null)).status).toBe(
      200,
    );
    for (const horizon of ["abc", "-1", "1.5", null]) {
      const forged = await read(
        ctx!,
        token,
        `/v1/streams/events/records?changes_since=&limit=1&cursor=${encodeURIComponent(forge(cursor, { horizon }))}`,
      );
      expect(forged.status).toBe(400);
      expect(forged.body.error.code).toBe("invalid_cursor");
    }
    const since = await read(
      ctx!,
      token,
      `/v1/streams/events/records?changes_since=&limit=1&cursor=${encodeURIComponent(forge(cursor, { sinceHorizon: "abc" }))}`,
    );
    expect(since.status).toBe(400);
    const forgedSince = await read(
      ctx!,
      token,
      `/v1/streams/events/records?changes_since=${encodeURIComponent(forge(token1, { horizon: "abc" }))}&limit=1`,
    );
    expect(forgedSince.status).toBe(400);
    expect(forgedSince.body.error.code).toBe("invalid_cursor");
  });

  it("reads a binding over HTTP without creating a binding row", async () => {
    const { token } = await bootSwitchable();
    const instance = `oura:${owner}`;
    const bindingRows = () => {
      const db = new Database(join(tempDir, "index.db"), { readonly: true });
      try {
        return (
          db
            .prepare("SELECT COUNT(*) AS n FROM pdpp_instance_binding")
            .get() as { n: number }
        ).n;
      } finally {
        db.close();
      }
    };
    const binding = await read(
      ctx!,
      token,
      `/pdpp/instances/${encodeURIComponent(instance)}/binding`,
    );
    expect(binding.status).toBe(200);
    expect(binding.body).toMatchObject({
      method: null,
      generation: 1,
      empty: true,
      configured_active_method: "oura",
    });
    expect(bindingRows()).toBe(0);
    await seedEvents(token, instance, ["a1"]);
    expect(bindingRows()).toBe(1);
  });

  it("keeps a keyset cursor valid across later writes without a reset", async () => {
    const { token } = await bootSwitchable();
    const instance = `oura:${owner}`;
    await seedEvents(token, instance, ["a1", "a2"]);
    const page1 = await read(
      ctx!,
      token,
      "/v1/streams/events/records?order=asc&limit=1",
    );
    await seedEvents(token, instance, ["a3"], 3);
    const page2 = await read(
      ctx!,
      token,
      `/v1/streams/events/records?order=asc&limit=5&cursor=${encodeURIComponent(page1.body.next_cursor)}`,
    );
    expect(page2.status).toBe(200);
    expect(page2.body.data.map((r: any) => r.id)).toEqual(["a2", "a3"]);
  });

  it("rejects an unknown method and another source's method as method_inactive", async () => {
    const { token } = await bootSwitchable();
    const instance = `oura:${owner}`;
    for (const method of ["no-such-method", "claude"]) {
      const response = await ingest(
        ctx!,
        token,
        "events",
        {
          instance,
          key: `k-${method}`,
          data: { id: `k-${method}`, kind: "x" },
          emitted_at: "2026-09-01T00:00:00Z",
        },
        method,
      );
      expect(response.status).toBe(409);
      expect((response.body as any).error.code).toBe("method_inactive");
      const blob = await uploadBlob(
        ctx!,
        token,
        instance,
        method,
        1,
        new TextEncoder().encode(`bytes for ${method}`),
      );
      expect(blob.status).toBe(409);
      expect((await blob.json()).error.code).toBe("method_inactive");
    }
    expect(storeCounters()).toEqual({ clock: 0, changes: 0 });
    expect(blobStoreCounters()).toEqual({ metadata: 0, bytes: 0, claims: 0 });
  });

  it("requires an owner reset before a configured method writes to a migrated instance", async () => {
    const { ouraPath, claudePath } = await bootSwitchable();
    const instance = `oura:${owner}`;
    await ctx!.cleanup();
    // A pre-binding instance: rows exist, the binding has no method.
    const db = new Database(join(tempDir, "index.db"));
    try {
      db.prepare(
        `INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, deleted, deleted_at, blob_id)
         VALUES (?, 'events', 'legacy', ?, 1, '2026-08-01T00:00:00Z', 0, NULL, NULL)`,
      ).run(instance, JSON.stringify({ id: "legacy", kind: "old" }));
    } finally {
      db.close();
    }
    ctx = await boot([claudePath, ouraPath]);
    const token = await ownerToken(ctx);

    const binding = await read(
      ctx,
      token,
      `/pdpp/instances/${encodeURIComponent(instance)}/binding`,
    );
    expect(binding.body).toMatchObject({
      method: null,
      generation: 1,
      empty: false,
    });
    const write = await ingest(ctx, token, "events", {
      instance,
      key: "new",
      data: { id: "new", kind: "a" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(write.status).toBe(409);
    expect((write.body as any).error.code).toBe("binding_required");
    const blob = await uploadBlob(
      ctx,
      token,
      instance,
      "oura",
      1,
      new TextEncoder().encode("migrated bytes"),
    );
    expect(blob.status).toBe(409);
    expect((await blob.json()).error.code).toBe("binding_required");

    const adopted = await ctx.app.request(
      `/pdpp/instances/${encodeURIComponent(instance)}/reset`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          expected_method: null,
          expected_generation: 1,
          next_method: "oura",
        }),
      },
    );
    expect(adopted.status).toBe(200);
    const after = await ingest(
      ctx,
      token,
      "events",
      {
        instance,
        key: "new",
        data: { id: "new", kind: "a" },
        emitted_at: "2026-09-01T00:00:00Z",
      },
      "oura",
      2,
    );
    expect(outcomes(after.body)).toEqual(["accepted"]);
    const listed = await read(ctx, token, "/v1/streams/events/records");
    expect(listed.body.data.map((r: any) => r.id)).toEqual(["new"]);
  });
});

describe("P7: stream snapshot replace", () => {
  const record = (key: string, email: string, emitted_at: string) => ({
    key,
    data: { user_id: key, email },
    emitted_at,
  });

  /** Every current row of the oura instance, including tombstones. */
  function currentRows() {
    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      return db
        .prepare(
          "SELECT stream, record_key, data, version, emitted_at, deleted, deleted_at FROM pdpp_records ORDER BY stream, record_key",
        )
        .all();
    } finally {
      db.close();
    }
  }

  async function seed(context: ServerContext, token: string) {
    const instance = `oura:${owner}`;
    const seeded = await ingest(
      context,
      token,
      "profile",
      ["k1", "k2", "k3"].map((key) => ({
        instance,
        ...record(key, `${key}@a`, "2026-09-01T00:00:00Z"),
      })),
    );
    expect(outcomes(seeded.body)).toEqual(["accepted", "accepted", "accepted"]);
    return instance;
  }

  it("upserts the snapshot and tombstones exactly the live keys it lacks", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = await seed(ctx, token);
    const baseline = await read(
      ctx,
      token,
      "/v1/streams/profile/records?changes_since=",
    );
    const token0 = baseline.body.next_changes_since as string;
    const before = storeCounters();

    const result = await replace(ctx, token, "profile", {
      instance,
      emitted_at: "2026-09-02T12:00:00Z",
      records: [
        record("k1", "k1@a", "2026-09-02T00:00:00Z"),
        record("k2", "k2@b", "2026-09-02T00:00:00Z"),
        record("k4", "k4@b", "2026-09-02T00:00:00Z"),
      ],
    });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      accepted: 2,
      unchanged: 1,
      deleted: 1,
      rejected: [],
    });
    expect(result.body.results.map((r: any) => r.outcome)).toEqual([
      "unchanged",
      "accepted",
      "accepted",
    ]);
    // k2 new version, k4 version 1, k3 tombstone: three clock ticks.
    expect(storeCounters()).toEqual({
      clock: before.clock + 3,
      changes: before.changes + 3,
    });

    const listed = await read(ctx, token, "/v1/streams/profile/records");
    expect(
      listed.body.data.map((r: any) => [r.id, r.data.email]).sort(),
    ).toEqual([
      ["k1", "k1@a"],
      ["k2", "k2@b"],
      ["k4", "k4@b"],
    ]);
    const k1 = await read(ctx, token, "/v1/streams/profile/records/k1");
    expect(k1.body.emitted_at).toBe("2026-09-01T00:00:00Z");

    const changed = await read(
      ctx,
      token,
      `/v1/streams/profile/records?changes_since=${encodeURIComponent(token0)}`,
    );
    const byKey = Object.fromEntries(
      changed.body.data.map((r: any) => [r.id, r]),
    );
    expect(Object.keys(byKey).sort()).toEqual(["k2", "k3", "k4"]);
    expect(byKey.k3.deleted).toBe(true);
    expect(byKey.k3.deleted_at).toBe("2026-09-02T12:00:00Z");

    // The same snapshot again is exact: nothing written.
    const settled = storeCounters();
    const again = await replace(ctx, token, "profile", {
      instance,
      emitted_at: "2026-09-03T00:00:00Z",
      records: [
        record("k1", "k1@a", "2026-09-03T00:00:00Z"),
        record("k2", "k2@b", "2026-09-03T00:00:00Z"),
        record("k4", "k4@b", "2026-09-03T00:00:00Z"),
      ],
    });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ accepted: 0, unchanged: 3, deleted: 0 });
    expect(storeCounters()).toEqual(settled);
  });

  it("writes nothing when any record is rejected", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = await seed(ctx, token);
    const before = { counters: storeCounters(), rows: currentRows() };

    const cases: { records: unknown[]; index: number; reason: RegExp }[] = [
      {
        // Key does not match data's primary key.
        records: [
          record("k1", "changed", "2026-09-02T00:00:00Z"),
          {
            key: "k9",
            data: { user_id: "other" },
            emitted_at: "2026-09-02T00:00:00Z",
          },
        ],
        index: 1,
        reason: /primary_key/,
      },
      {
        records: [
          record("k1", "changed", "2026-09-02T00:00:00Z"),
          record("k1", "again", "2026-09-02T00:00:00Z"),
        ],
        index: 1,
        reason: /duplicate key/,
      },
      {
        records: [
          record("k1", "changed", "2026-09-02T00:00:00Z"),
          {
            key: "k2",
            data: null,
            emitted_at: "2026-09-02T00:00:00Z",
            op: "delete",
          },
        ],
        index: 1,
        reason: /must be upserts/,
      },
      {
        records: [
          record("k1", "changed", "2026-09-02T00:00:00Z"),
          {
            key: "k5",
            data: {
              user_id: "k5",
              blob_ref: { blob_id: `sha256:${"0".repeat(64)}` },
            },
            emitted_at: "2026-09-02T00:00:00Z",
          },
        ],
        index: 1,
        reason: /blob_unclaimed/,
      },
    ];
    for (const { records, index, reason } of cases) {
      const result = await replace(ctx, token, "profile", {
        instance,
        emitted_at: "2026-09-02T12:00:00Z",
        records,
      });
      expect(result.status).toBe(422);
      expect(result.body.rejected).toHaveLength(1);
      expect(result.body.rejected[0].index).toBe(index);
      expect(result.body.rejected[0].reason).toMatch(reason);
      expect({ counters: storeCounters(), rows: currentRows() }).toEqual(
        before,
      );
    }
  });

  it("tombstones only inside the replaced (instance, stream)", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = `oura:${owner}`;
    // Same stream name on another instance, and another stream on this one.
    const claude = await ingest(ctx, token, "profile", {
      instance: `claude:${owner}`,
      key: "c1",
      data: { id: "c1", name: "c" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(claude.body)).toEqual(["accepted"]);
    const events = await ingest(ctx, token, "events", {
      instance,
      key: "e1",
      data: { id: "e1", kind: "x" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(events.body)).toEqual(["accepted"]);
    const profile = await ingest(
      ctx,
      token,
      "profile",
      ["k1", "k2"].map((key) => ({
        instance,
        ...record(key, `${key}@a`, "2026-09-01T00:00:00Z"),
      })),
    );
    expect(outcomes(profile.body)).toEqual(["accepted", "accepted"]);
    const before = storeCounters();

    const result = await replace(ctx, token, "profile", {
      instance,
      emitted_at: "2026-09-02T12:00:00Z",
      records: [record("k1", "k1@a", "2026-09-02T00:00:00Z")],
    });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      accepted: 0,
      unchanged: 1,
      deleted: 1,
    });
    expect(storeCounters()).toEqual({
      clock: before.clock + 1,
      changes: before.changes + 1,
    });
    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      expect(
        db
          .prepare(
            "SELECT instance, stream, record_key, version, deleted FROM pdpp_records ORDER BY instance, stream, record_key",
          )
          .all(),
      ).toEqual([
        {
          instance: `claude:${owner}`,
          stream: "profile",
          record_key: "c1",
          version: 1,
          deleted: 0,
        },
        {
          instance,
          stream: "events",
          record_key: "e1",
          version: 1,
          deleted: 0,
        },
        {
          instance,
          stream: "profile",
          record_key: "k1",
          version: 1,
          deleted: 0,
        },
        {
          instance,
          stream: "profile",
          record_key: "k2",
          version: 2,
          deleted: 1,
        },
      ]);
    } finally {
      db.close();
    }
  });

  it("rolls back every upsert and tombstone when a write faults mid-transaction", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = await seed(ctx, token);
    const before = { counters: storeCounters(), rows: currentRows() };

    // The tombstone of k3 is the last history insert of the replace.
    const db = new Database(join(tempDir, "index.db"));
    db.exec(`CREATE TRIGGER fault_replace BEFORE INSERT ON pdpp_record_changes
      WHEN NEW.record_key = 'k3' AND NEW.deleted = 1
      BEGIN SELECT RAISE(ABORT, 'injected replace fault'); END`);
    try {
      const result = await replace(ctx, token, "profile", {
        instance,
        emitted_at: "2026-09-02T12:00:00Z",
        records: [
          record("k1", "k1@b", "2026-09-02T00:00:00Z"),
          record("k4", "k4@b", "2026-09-02T00:00:00Z"),
        ],
      });
      expect(result.status).toBe(500);
      expect({ counters: storeCounters(), rows: currentRows() }).toEqual(
        before,
      );
    } finally {
      db.exec("DROP TRIGGER fault_replace");
      db.close();
    }
  });

  it("refuses append_only streams, inactive methods, and stale generations with no change", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = await seed(ctx, token);
    const events = await ingest(ctx, token, "events", {
      instance,
      key: "e1",
      data: { id: "e1", kind: "x" },
      emitted_at: "2026-09-01T00:00:00Z",
    });
    expect(outcomes(events.body)).toEqual(["accepted"]);
    const before = { counters: storeCounters(), rows: currentRows() };
    const snapshot = {
      instance,
      emitted_at: "2026-09-02T12:00:00Z",
      records: [record("k1", "k1@b", "2026-09-02T00:00:00Z")],
    };

    const appendOnly = await replace(ctx, token, "events", {
      ...snapshot,
      records: [],
    });
    expect(appendOnly.status).toBe(400);
    expect(appendOnly.body.error.message).toMatch(/mutable_state/);

    const inactive = await replace(
      ctx,
      token,
      "profile",
      snapshot,
      "oura-browser",
    );
    expect(inactive.status).toBe(409);
    expect(inactive.body.error.code).toBe("method_inactive");

    const stale = await replace(ctx, token, "profile", snapshot, "oura", 2);
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe("binding_generation_mismatch");

    const notOwned = await replace(ctx, token, "profile", {
      ...snapshot,
      instance: "oura:0x0000000000000000000000000000000000000001",
    });
    expect(notOwned.status).toBe(401);

    const malformed = await replace(ctx, token, "profile", {
      instance,
      records: [],
    });
    expect(malformed.status).toBe(400);

    expect({ counters: storeCounters(), rows: currentRows() }).toEqual(before);

    // After a reset the old generation is fenced; the new one replaces.
    const resetResponse = await reset(ctx, token, instance, "oura", 1, "oura");
    expect(resetResponse.status).toBe(200);
    const old = await replace(ctx, token, "profile", snapshot, "oura", 1);
    expect(old.status).toBe(409);
    expect(old.body.error.code).toBe("binding_generation_mismatch");
    const fresh = await replace(ctx, token, "profile", snapshot, "oura", 2);
    expect(fresh.status).toBe(200);
    expect(fresh.body).toMatchObject({ accepted: 1, deleted: 0 });
  });

  it("binds an empty unbound instance, and an empty snapshot tombstones every live key", async () => {
    ctx = await bootBoth();
    const token = await ownerToken(ctx);
    const instance = `oura:${owner}`;
    const binding = async () =>
      read(
        ctx!,
        token,
        `/pdpp/instances/${encodeURIComponent(instance)}/binding`,
      );
    expect((await binding()).body.method).toBeNull();

    const first = await replace(ctx, token, "profile", {
      instance,
      emitted_at: "2026-09-01T12:00:00Z",
      records: [
        record("k1", "k1@a", "2026-09-01T00:00:00Z"),
        record("k2", "k2@a", "2026-09-01T00:00:00Z"),
      ],
    });
    expect(first.status).toBe(200);
    expect((await binding()).body).toMatchObject({
      method: "oura",
      generation: 1,
    });

    const cleared = await replace(ctx, token, "profile", {
      instance,
      emitted_at: "2026-09-02T12:00:00Z",
      records: [],
    });
    expect(cleared.status).toBe(200);
    expect(cleared.body).toMatchObject({ accepted: 0, deleted: 2 });
    const listed = await read(ctx, token, "/v1/streams/profile/records");
    expect(listed.body.data).toEqual([]);
  });

  it("is not mounted when PDPP is disabled", async () => {
    ctx = await createServer(
      ServerConfigSchema.parse({ tunnel: { enabled: false } }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
    );
    const response = await ctx.app.request(
      "/v1/streams/profile/records/replace?method=oura&binding_generation=1",
      { method: "POST", body: "{}" },
    );
    expect(response.status).toBe(404);
  });
});

describe("P5: record data is validated against the declared stream schema", () => {
  const WHOOP = "https://registry.pdpp.dev/connectors/whoop";

  // A normative §5 declaration. `stages` uses 2020-12 `prefixItems` with
  // `items: false`: a tuple of exactly [string, number]. Under draft-07 the
  // same `items: false` would forbid every element, so an accepted tuple
  // proves the 2020-12 dialect. `recorded_at` has a `format`, which 2020-12
  // treats as an annotation.
  function whoopDeclaration(version: string, requireScore: boolean) {
    return JSON.stringify({
      protocol_version: "0.1.0",
      source: { kind: "connector", id: WHOOP },
      declaration_version: version,
      publisher: { id: "https://registry.pdpp.dev" },
      display: { name: "Whoop" },
      streams: [
        {
          name: "sleep",
          semantics: "mutable_state",
          primary_key: ["id"],
          schema: {
            $schema: "https://json-schema.org/draft/2020-12/schema",
            type: "object",
            properties: {
              id: { type: "string" },
              score: { type: "integer", minimum: 0 },
              stages: {
                type: "array",
                prefixItems: [{ type: "string" }, { type: "number" }],
                items: false,
              },
              recorded_at: { type: "string", format: "date-time" },
            },
            required: requireScore ? ["id", "score"] : ["id"],
            additionalProperties: false,
          },
        },
      ],
    });
  }

  const instance = () => `whoop:${owner}`;
  const envelope = (
    data: Record<string, unknown>,
    emitted_at = "2026-09-01T00:00:00Z",
  ) => ({
    instance: instance(),
    key: data.id as string,
    data,
    emitted_at,
  });

  function sleepRows() {
    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      return db
        .prepare(
          "SELECT record_key, data, version, deleted FROM pdpp_records WHERE stream = 'sleep' ORDER BY record_key",
        )
        .all();
    } finally {
      db.close();
    }
  }

  async function bootWhoop(version = "1", requireScore = true) {
    const path = await writeDeclaration(
      "whoop",
      whoopDeclaration(version, requireScore),
    );
    return boot([path]);
  }

  it("ingest: rejects each non-conforming record by index and writes only the conforming ones", async () => {
    ctx = await bootWhoop();
    const token = await ownerToken(ctx);
    const before = storeCounters();

    const result = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", score: 80, stages: ["deep", 1.5] }),
      envelope({ id: "s2", score: "high" }),
      envelope({ id: "s3" }),
      envelope({ id: "s4", score: 1, extra: true }),
      envelope({ id: "s5", score: 1, stages: ["deep", 1.5, "rem"] }),
      envelope({ id: "s6", score: 70, recorded_at: "not a date" }),
    ]);
    expect(result.status).toBe(200);
    expect(result.body.results).toEqual([
      { index: 0, outcome: "accepted" },
      {
        index: 1,
        outcome: "rejected",
        reason: "schema_violation: /score must be integer",
      },
      {
        index: 2,
        outcome: "rejected",
        reason: "schema_violation: (root) must have required property 'score'",
      },
      {
        index: 3,
        outcome: "rejected",
        reason: "schema_violation: (root) must NOT have additional properties",
      },
      {
        index: 4,
        outcome: "rejected",
        reason: "schema_violation: /stages must NOT have more than 2 items",
      },
      { index: 5, outcome: "accepted" },
    ]);
    // Two writes, two clock ticks: a rejected record leaves no trace.
    expect(storeCounters()).toEqual({
      clock: before.clock + 2,
      changes: before.changes + 2,
    });
    expect(sleepRows().map((r: any) => r.record_key)).toEqual(["s1", "s6"]);
  });

  it("ingest: a non-conforming upsert over a stored record leaves it unchanged, and a delete is not schema-checked", async () => {
    ctx = await bootWhoop();
    const token = await ownerToken(ctx);
    await ingest(ctx, token, "sleep", [envelope({ id: "s1", score: 80 })]);
    const rows = sleepRows();
    const counters = storeCounters();

    const bad = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", score: -1 }, "2026-09-02T00:00:00Z"),
    ]);
    expect(bad.body.results).toEqual([
      {
        index: 0,
        outcome: "rejected",
        reason: "schema_violation: /score must be >= 0",
      },
    ]);
    // The same request is rejected with the same reason every time.
    const replay = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", score: -1 }, "2026-09-02T00:00:00Z"),
    ]);
    expect(replay.body).toEqual(bad.body);
    expect(sleepRows()).toEqual(rows);
    expect(storeCounters()).toEqual(counters);

    const deleted = await ingest(ctx, token, "sleep", [
      {
        instance: instance(),
        key: "s1",
        op: "delete",
        emitted_at: "2026-09-03T00:00:00Z",
      },
    ]);
    expect(outcomes(deleted.body)).toEqual(["accepted"]);
  });

  it("replace: applies a conforming snapshot, and one non-conforming record rejects it with nothing written", async () => {
    ctx = await bootWhoop();
    const token = await ownerToken(ctx);
    const seeded = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", score: 1 }),
      envelope({ id: "s2", score: 2 }),
    ]);
    expect(outcomes(seeded.body)).toEqual(["accepted", "accepted"]);

    const applied = await replace(
      ctx,
      token,
      "sleep",
      {
        instance: instance(),
        emitted_at: "2026-09-02T00:00:00Z",
        records: [
          envelope({ id: "s1", score: 1 }),
          envelope({ id: "s3", score: 3 }),
        ],
      },
      "whoop",
    );
    expect(applied.status).toBe(200);
    expect(applied.body).toMatchObject({
      accepted: 1,
      unchanged: 1,
      deleted: 1,
      rejected: [],
    });

    const rows = sleepRows();
    const counters = storeCounters();
    // The invalid record is last, after an upsert and a new key, and the
    // snapshot would tombstone s3: none of it may be written.
    const rejected = await replace(
      ctx,
      token,
      "sleep",
      {
        instance: instance(),
        emitted_at: "2026-09-03T00:00:00Z",
        records: [
          envelope({ id: "s1", score: 10 }),
          envelope({ id: "s4", score: 4 }),
          envelope({ id: "s5", score: 5, stages: [1, "deep"] }),
        ],
      },
      "whoop",
    );
    expect(rejected.status).toBe(422);
    expect(rejected.body.rejected).toEqual([
      { index: 2, reason: "schema_violation: /stages/0 must be string" },
    ]);
    expect(sleepRows()).toEqual(rows);
    expect(storeCounters()).toEqual(counters);
  });

  it("replace: checks the binding before the schema, so a stale generation is 409 whatever the records hold", async () => {
    ctx = await bootWhoop();
    const token = await ownerToken(ctx);
    await ingest(ctx, token, "sleep", [envelope({ id: "s1", score: 1 })]);
    const counters = storeCounters();

    const stale = await replace(
      ctx,
      token,
      "sleep",
      {
        instance: instance(),
        emitted_at: "2026-09-02T00:00:00Z",
        records: [envelope({ id: "s1", score: "bad" })],
      },
      "whoop",
      2,
    );
    expect(stale.status).toBe(409);
    expect(stale.body.error.code).toBe("binding_generation_mismatch");
    expect(storeCounters()).toEqual(counters);
  });

  it("validates new writes against the configured declaration version across restarts, and leaves stored rows alone", async () => {
    // Version 1 does not require `score`.
    ctx = await bootWhoop("1", false);
    let token = await ownerToken(ctx);
    const v1 = await ingest(ctx, token, "sleep", [envelope({ id: "s1" })]);
    expect(outcomes(v1.body)).toEqual(["accepted"]);
    await ctx.cleanup();

    // Version 2 requires it. The stored row is not revalidated or removed,
    // but re-sending the same content is rejected, on both write paths,
    // even though it equals what is stored.
    ctx = await bootWhoop("2", true);
    token = await ownerToken(ctx);
    const rows = sleepRows();
    const counters = storeCounters();
    const missing =
      "schema_violation: (root) must have required property 'score'";
    const again = await ingest(ctx, token, "sleep", [envelope({ id: "s1" })]);
    expect(again.body.results).toEqual([
      { index: 0, outcome: "rejected", reason: missing },
    ]);
    const replaced = await replace(
      ctx,
      token,
      "sleep",
      {
        instance: instance(),
        emitted_at: "2026-09-02T00:00:00Z",
        records: [envelope({ id: "s1" })],
      },
      "whoop",
    );
    expect(replaced.status).toBe(422);
    expect(replaced.body.rejected).toEqual([{ index: 0, reason: missing }]);
    expect(sleepRows()).toEqual(rows);
    expect(storeCounters()).toEqual(counters);
    const stored = await read(ctx, token, "/v1/streams/sleep/records/s1");
    expect(stored.status).toBe(200);
    expect(stored.body.data).toEqual({ id: "s1" });
    await ctx.cleanup();

    // Back to version 1: the same record is `unchanged` again.
    ctx = await bootWhoop("1", false);
    token = await ownerToken(ctx);
    const back = await ingest(ctx, token, "sleep", [envelope({ id: "s1" })]);
    expect(outcomes(back.body)).toEqual(["unchanged"]);
  });

  it("refuses a declaration whose stream schema names another dialect, so nothing can be written under it", async () => {
    const draft07 = JSON.parse(whoopDeclaration("1", true));
    draft07.streams[0].schema.$schema =
      "http://json-schema.org/draft-07/schema#";
    const path = await writeDeclaration("whoop", JSON.stringify(draft07));
    ctx = await boot([path]);
    const response = await ctx.app.request("/pdpp/v1/owner/token", {
      method: "POST",
      headers: { authorization: `Bearer ${ctx.devToken}` },
    });
    expect(response.status).toBe(404);
  });

  function declarationWith(
    source: string,
    stream: string,
    schema: Record<string, unknown>,
  ) {
    return JSON.stringify({
      protocol_version: "0.1.0",
      source: {
        kind: "connector",
        id: `https://registry.pdpp.dev/connectors/${source}`,
      },
      declaration_version: "1",
      publisher: { id: "https://registry.pdpp.dev" },
      display: { name: source },
      streams: [
        {
          name: stream,
          semantics: "mutable_state",
          primary_key: ["id"],
          schema: {
            $schema: "https://json-schema.org/draft/2020-12/schema",
            ...schema,
          },
        },
      ],
    });
  }

  it("rejects every upsert of a stream whose schema does not compile, with nothing written", async () => {
    const path = await writeDeclaration(
      "whoop",
      declarationWith("whoop", "sleep", {
        type: "object",
        properties: {
          id: { type: "string" },
          score: { $ref: "#/$defs/missing" },
        },
      }),
    );
    ctx = await boot([path]);
    const token = await ownerToken(ctx);
    const before = storeCounters();

    const result = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", score: 1 }),
      envelope({ id: "s2" }),
    ]);
    expect(result.status).toBe(200);
    const unavailable =
      "schema_unavailable: can't resolve reference #/$defs/missing from id #";
    expect(result.body.results).toEqual([
      { index: 0, outcome: "rejected", reason: unavailable },
      { index: 1, outcome: "rejected", reason: unavailable },
    ]);
    expect(sleepRows()).toEqual([]);
    expect(storeCounters()).toEqual(before);
  });

  it("validates each source's stream against its own schema when two sources declare the same stream name", async () => {
    const schemaWith = (type: string) => ({
      type: "object",
      properties: { id: { type: "string" }, v: { type } },
    });
    ctx = await boot([
      await writeDeclaration(
        "alpha",
        declarationWith("alpha", "profile", schemaWith("string")),
      ),
      await writeDeclaration(
        "beta",
        declarationWith("beta", "profile", schemaWith("number")),
      ),
    ]);
    const token = await ownerToken(ctx);
    const at = (source: string, id: string, v: unknown) => ({
      instance: `${source}:${owner}`,
      key: id,
      data: { id, v },
      emitted_at: "2026-09-01T00:00:00Z",
    });

    const alpha = await ingest(ctx, token, "profile", [
      at("alpha", "p1", "text"),
    ]);
    expect(alpha.body.results).toEqual([{ index: 0, outcome: "accepted" }]);
    const beta = await ingest(ctx, token, "profile", [
      at("beta", "p1", "text"),
      at("beta", "p2", 7),
    ]);
    expect(beta.body.results).toEqual([
      {
        index: 0,
        outcome: "rejected",
        reason: "schema_violation: /v must be number",
      },
      { index: 1, outcome: "accepted" },
    ]);
  });

  it("keeps record-data keys out of the reason: only segments the schema names are shown", async () => {
    const path = await writeDeclaration(
      "whoop",
      declarationWith("whoop", "sleep", {
        type: "object",
        $defs: {
          contact: {
            type: "object",
            properties: { phone: { type: "string" } },
          },
        },
        properties: {
          id: { type: "string" },
          contacts: {
            type: "object",
            additionalProperties: { $ref: "#/$defs/contact" },
          },
          tags: { type: "array", items: { type: "string" } },
          byId: { type: "object", additionalProperties: { type: "string" } },
        },
      }),
    );
    ctx = await boot([path]);
    const token = await ownerToken(ctx);

    const result = await ingest(ctx, token, "sleep", [
      envelope({ id: "s1", contacts: { "alice@example.com": { phone: 5 } } }),
      envelope({ id: "s2", tags: ["a", 1] }),
      envelope({ id: "s3", byId: { "5551234": 1 } }),
      envelope({ id: "s4", contacts: { "bob@example.com": "x" } }),
    ]);
    expect(result.body.results).toEqual([
      {
        index: 0,
        outcome: "rejected",
        reason: "schema_violation: /contacts/*/phone must be string",
      },
      {
        index: 1,
        outcome: "rejected",
        reason: "schema_violation: /tags/1 must be string",
      },
      {
        index: 2,
        outcome: "rejected",
        reason: "schema_violation: /byId/* must be string",
      },
      {
        index: 3,
        outcome: "rejected",
        reason: "schema_violation: /contacts/* must be object",
      },
    ]);
    expect(JSON.stringify(result.body)).not.toMatch(/alice|bob|5551234/);
  });
});

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

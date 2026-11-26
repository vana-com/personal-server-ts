/**
 * Locked PDPP Core v0.1.0 held-data lifecycle at the Authorization Server
 * (work package 6): §7 "Held data after a grant ends" through "Lifecycle
 * durability" (spec-core L1532-L1830), §9 AS items 39-47, and the held-data
 * conformance cases P1-P9, C1-C9 and D1-D5 for the AS role.
 *
 * Every case runs against a real SQLite store, a real anchor file and a
 * controllable AS clock. Client-side assertions of each case (stop use,
 * delete, relay, reconciliation scheduling) are out of scope for an AS test
 * and are named as such; only what the AS returns, records and shows is
 * asserted here.
 */

import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultAnchorIo, type AnchorIo } from "./history.js";
import {
  DELETION_BOUND_MS,
  GrantLifecycleService,
  PDPP_GRANT_LIFECYCLE_TYPE,
  RECONCILIATION_INTERVAL_MS,
  RETRY_INTERVAL_MS,
  STOP_USE_BOUND_MS,
  type LifecycleAnswer,
  type LifecycleHttpResult,
} from "./lifecycle.js";
import { hashToken, openPdppAuthStore, type PdppAuthStore } from "./store.js";
import { PdppTokenService } from "./tokens.js";
import { SUPPORTED_PROCESSING_PERMISSIONS } from "./public-validation.js";
import { PDPP_GRANT_VERSION, type AccessMode, type Grant } from "./types.js";

const OWNER = "user_abc123";
const CLIENT = "music_recommendations";
const OTHER_CLIENT = "other_app";
const REDIRECT = "https://app.example.com/callback";
const H = 60 * 60 * 1000;

let dir: string;
let dbPath: string;
let clockMs: number;
const clock = () => new Date(clockMs);
const advance = (ms: number) => {
  clockMs += ms;
};
let failAnchorWrites: number[] = [];
let failAllAnchorWrites = false;
let anchorWrites = 0;
const anchorIo: AnchorIo = {
  read: defaultAnchorIo.read,
  writeDurably(path, content) {
    anchorWrites += 1;
    if (failAllAnchorWrites || failAnchorWrites.includes(anchorWrites)) {
      throw new Error("injected anchor failure");
    }
    defaultAnchorIo.writeDurably(path, content);
  },
};
let store: PdppAuthStore;
let tokens: PdppTokenService;
let lifecycle: GrantLifecycleService;

function open(options: { queries?: number } = {}) {
  store = openPdppAuthStore(dbPath, { anchorIo });
  tokens = new PdppTokenService(store, { clock });
  lifecycle = new GrantLifecycleService(store, {
    clock,
    ...(options.queries && { queriesPerRetryInterval: options.queries }),
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-wp6-"));
  dbPath = join(dir, "auth.db");
  clockMs = Date.parse("2026-11-01T08:00:00.000Z");
  failAnchorWrites = [];
  failAllAnchorWrites = false;
  anchorWrites = 0;
  open();
});

afterEach(() => {
  try {
    store.close();
  } catch {
    // already closed by a restore test
  }
  rmSync(dir, { recursive: true, force: true });
});

let seq = 0;
function seed(
  mode: AccessMode = "continuous",
  overrides: Partial<Grant> = {},
  clientId = CLIENT,
): { grant: Grant; code: string } {
  seq += 1;
  const grant: Grant = {
    version: PDPP_GRANT_VERSION,
    grant_id: `grt_wp6_${seq}_${Math.random().toString(16).slice(2, 8)}`,
    issued_at: new Date(clockMs + seq).toISOString(),
    subject: { id: OWNER },
    client: { client_id: clientId, client_display: { name: "Concert Finder" } },
    source: {
      kind: "connector",
      id: "https://registry.pdpp.dev/connectors/spotify",
    },
    source_declaration: { version: "2026-08-11" },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: mode,
    streams: [
      {
        name: "top_artists",
        instance_ids: ["spotify-account-a"],
        fields: ["id", "name"],
        required_fields: ["id"],
      },
    ],
    ...overrides,
  };
  const code = `code_${seq}_${Math.random().toString(16).slice(2)}`;
  store.insertGrantWithAuthCode({
    grant,
    subjectId: OWNER,
    reviewDigest: "d",
    code,
    authCode: {
      grantId: grant.grant_id,
      clientId,
      redirectUri: REDIRECT,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(clockMs + 60_000).toISOString(),
    },
  });
  return { grant, code };
}

function redeem(code: string, clientId = CLIENT) {
  const result = tokens.redeemAuthorizationCode({
    code,
    clientId,
    redirectUri: REDIRECT,
  });
  if (!result.ok) throw new Error(result.failure.message);
  return result.issued;
}

/** A grant with a delivered token, so its held data may remain. */
function issued(
  mode: AccessMode = "continuous",
  overrides: Partial<Grant> = {},
  clientId = CLIENT,
) {
  const { grant, code } = seed(mode, overrides, clientId);
  return { grant, ...redeem(code, clientId) };
}

function call(fields: Record<string, string | string[]>): LifecycleHttpResult {
  const params = new Map<string, string[]>();
  for (const [k, v] of Object.entries(fields))
    params.set(k, Array.isArray(v) ? v : [v]);
  return lifecycle.handleLifecycleRequest(params);
}

function answer(
  token: string,
  grantId: string,
  extra: Record<string, string> = {},
) {
  const r = call({ grant_id: grantId, token, ...extra });
  expect(r.status).toBe(200);
  if (r.status !== 200) throw new Error("unreachable");
  return r.body.grants[0] as LifecycleAnswer & { error?: string };
}

const all = () => true;

function ownerEnd(
  action: "revoke" | "disconnect_client" | "narrowing",
  dispositions: Record<string, "keep" | "delete">,
  extra: { clientId?: string; grantIds?: string[]; actionId?: string } = {},
) {
  return lifecycle.endGrantsForOwner({
    subjectId: OWNER,
    action,
    dispositions,
    actionId: extra.actionId ?? `act_${Math.random()}`,
    inScope: all,
    ...(extra.clientId && { clientId: extra.clientId }),
    ...(extra.grantIds && { grantIds: extra.grantIds }),
  });
}

function view(grantId: string) {
  return lifecycle.ownerView(store.getGrant(grantId)!);
}

/** Simulate a restore: replace the database file with an earlier copy. */
function restoreFrom(backup: string, alsoAnchor?: string) {
  store.close();
  for (const suffix of ["-wal", "-shm"]) {
    if (existsSync(dbPath + suffix)) rmSync(dbPath + suffix);
  }
  copyFileSync(backup, dbPath);
  if (alsoAnchor) copyFileSync(alsoAnchor, `${dbPath}.history-anchor.json`);
  open();
}

function backup(name: string): { db: string; anchor: string } {
  // A consistent file copy: checkpoint the WAL first.
  (store as unknown as { db: Database.Database }).db.pragma(
    "wal_checkpoint(TRUNCATE)",
  );
  const db = join(dir, `${name}.db`);
  const anchor = join(dir, `${name}.anchor`);
  copyFileSync(dbPath, db);
  copyFileSync(`${dbPath}.history-anchor.json`, anchor);
  return { db, anchor };
}

// ===========================================================================
// AS item 39 — the grant lifecycle operation
// ===========================================================================

describe("AS item 39 — grant lifecycle operation", () => {
  it("answers a query with an active token: active, permitted, assessed now", () => {
    const t = issued();
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a).toEqual({
      grant_id: t.grant.grant_id,
      assessed_at: clock().toISOString(),
      read_state: "active",
      held_data: "permitted",
    });
  });

  it("accepts expired, superseded and revoked tokens for a query", () => {
    const t = issued();
    const rotated = tokens.refresh({ refreshToken: t.refresh_token! });
    expect(rotated.ok).toBe(true);
    advance(2 * H); // the first access token has expired
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe(
      "permitted",
    );
    expect(
      answer(t.refresh_token!, t.grant.grant_id, {
        token_type_hint: "refresh_token",
      }).read_state,
    ).toBe("active");
    tokens.revokeGrant(t.grant.grant_id);
    expect(answer(t.access_token, t.grant.grant_id).read_state).toBe("revoked");
  });

  it("D2: unknown, foreign and uncovered grants get identical invalid_grant entries", () => {
    const mine = issued();
    const another = issued(); // same client, a grant the token does not cover
    const foreign = issued("continuous", {}, OTHER_CLIENT);
    const entries = [
      another.grant.grant_id,
      foreign.grant.grant_id,
      "grt_never_issued",
    ].map((g) => {
      const r = call({ grant_id: g, token: mine.access_token });
      expect(r.status).toBe(200);
      return r.status === 200 ? r.body.grants[0] : null;
    });
    for (const [i, g] of [
      another.grant.grant_id,
      foreign.grant.grant_id,
      "grt_never_issued",
    ].entries()) {
      expect(entries[i]).toEqual({ grant_id: g, error: "invalid_grant" });
      expect(Object.keys(entries[i]!)).toEqual(["grant_id", "error"]);
    }
  });

  it("refuses an unknown token, another client's token and a missing token at request level", () => {
    const t = issued();
    expect(
      call({ grant_id: t.grant.grant_id, token: "pdpp_at_unknown" }),
    ).toMatchObject({
      status: 401,
      body: { error: "invalid_token" },
    });
    expect(
      call({
        grant_id: t.grant.grant_id,
        token: t.access_token,
        client_id: OTHER_CLIENT,
      }),
    ).toMatchObject({ status: 401, body: { error: "invalid_token" } });
    expect(call({ grant_id: t.grant.grant_id })).toMatchObject({
      status: 401,
      body: { error: "invalid_client" },
    });
  });

  it.each([
    [
      "both report and pdpp_disposition",
      {
        report: "received",
        pdpp_disposition: "delete",
        instruction_id: "x",
        reported_at: "2026-11-01T07:00:00Z",
      },
    ],
    ["an unknown report value", { report: "deleted" }],
    ["an unknown disposition value", { pdpp_disposition: "keep" }],
    ["an unknown token_type_hint", { token_type_hint: "id_token" }],
    [
      "a report without instruction_id",
      { report: "received", reported_at: "2026-11-01T07:00:00Z" },
    ],
    [
      "a report without reported_at",
      { report: "completed", instruction_id: "ers_x" },
    ],
    [
      "reported_at later than the request",
      {
        report: "received",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T09:00:00Z",
      },
    ],
    [
      "a malformed reported_at",
      { report: "received", instruction_id: "ers_x", reported_at: "yesterday" },
    ],
    [
      "retained without retained_until",
      {
        report: "retained",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T07:00:00Z",
      },
    ],
    [
      "retained_until in none of its forms",
      {
        report: "retained",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T07:00:00Z",
        retained_until: "next year",
      },
    ],
    [
      "an empty event: form",
      {
        report: "retained",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T07:00:00Z",
        retained_until: "event:   ",
      },
    ],
    [
      "a date-time retained_until before reported_at",
      {
        report: "retained",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T07:00:00Z",
        retained_until: "2026-10-01T00:00:00Z",
      },
    ],
    [
      "retention_basis without report=retained",
      {
        report: "completed",
        instruction_id: "ers_x",
        reported_at: "2026-11-01T07:00:00Z",
        retention_basis: "tax law",
      },
    ],
  ])("rejects %s with 400 invalid_request (L1709, L1748)", (_name, extra) => {
    const t = issued();
    expect(
      call({ grant_id: t.grant.grant_id, token: t.access_token, ...extra }),
    ).toMatchObject({
      status: 400,
      body: { error: "invalid_request" },
    });
  });

  it("rejects a write that names two grants, and a public client that repeats grant_id", () => {
    const t = issued();
    const u = issued();
    expect(
      call({
        grant_id: [t.grant.grant_id, u.grant.grant_id],
        token: t.access_token,
        pdpp_disposition: "delete",
      }),
    ).toMatchObject({ status: 400 });
    expect(
      call({
        grant_id: [t.grant.grant_id, u.grant.grant_id],
        token: t.access_token,
      }),
    ).toMatchObject({ status: 400 });
  });

  it("stores token digests, never tokens", () => {
    const t = issued();
    const db = new Database(dbPath, { readonly: true });
    const dump = JSON.stringify([
      db.prepare("SELECT * FROM pdpp_access_tokens").all(),
      db.prepare("SELECT * FROM pdpp_refresh_tokens").all(),
    ]);
    db.close();
    expect(dump).not.toContain(t.access_token);
    expect(dump).not.toContain(t.refresh_token!);
    expect(dump).toContain(hashToken(t.access_token));
  });

  it("disables any issued token for lifecycle use, including one never presented, and changes nothing else", () => {
    const t = issued();
    expect(
      lifecycle.disableForLifecycle({
        tokenDigests: [hashToken(t.refresh_token!)],
      }),
    ).toBe(1);
    expect(
      call({ grant_id: t.grant.grant_id, token: t.refresh_token! }),
    ).toMatchObject({ status: 401, body: { error: "invalid_token" } });
    // The grant, its read access and its access token are untouched.
    expect(tokens.resolveToken(t.access_token).active).toBe(true);
    expect(answer(t.access_token, t.grant.grant_id).read_state).toBe("active");
    expect(store.lifecycle.latestDisposition(t.grant.grant_id)).toBeNull();
  });

  it("C1a: admits one query per grant per retry interval, then 429 with Retry-After", () => {
    store.close();
    open({ queries: 1 });
    const t = issued();
    const u = issued();
    expect(
      call({ grant_id: t.grant.grant_id, token: t.access_token }).status,
    ).toBe(200);
    const limited = call({ grant_id: t.grant.grant_id, token: t.access_token });
    expect(limited.status).toBe(429);
    expect(
      "retryAfterSeconds" in limited && limited.retryAfterSeconds,
    ).toBeLessThanOrEqual(3600);
    // Another grant of the same client is admitted in the same interval.
    expect(
      call({ grant_id: u.grant.grant_id, token: u.access_token }).status,
    ).toBe(200);
    advance(RETRY_INTERVAL_MS);
    expect(
      call({ grant_id: t.grant.grant_id, token: t.access_token }).status,
    ).toBe(200);
  });

  it("records a client-conveyed delete as received only when reported_at is sent (AS item 39)", () => {
    const withTime = issued();
    const without = issued();
    const q = new Date(clockMs - 30 * 60 * 1000).toISOString();
    const a = answer(withTime.access_token, withTime.grant.grant_id, {
      pdpp_disposition: "delete",
      reported_at: q,
    });
    expect(a.held_data).toBe("erase");
    expect(a.read_state).toBe("revoked");
    expect(
      store.lifecycle.getInstruction(withTime.grant.grant_id)!
        .receiptReportedAt,
    ).toBe(q);
    const b = answer(without.access_token, without.grant.grant_id, {
      pdpp_disposition: "delete",
    });
    expect(b.held_data).toBe("erase");
    expect(
      store.lifecycle.getInstruction(without.grant.grant_id)!.receiptReportedAt,
    ).toBeNull();
    expect(
      view(without.grant.grant_id).erasure!.deletion_due_by,
    ).toBeUndefined();
  });

  it("returns invalid_instruction for an instruction of another grant", () => {
    const t = issued();
    answer(t.access_token, t.grant.grant_id, { pdpp_disposition: "delete" });
    // The grant is revoked now, so writes need recovery; use a fresh grant
    // with an active token to exercise the instruction check.
    const u = issued();
    const other = store.lifecycle.getInstruction(
      t.grant.grant_id,
    )!.instructionId;
    expect(
      answer(u.access_token, u.grant.grant_id, {
        report: "received",
        instruction_id: other,
        reported_at: clock().toISOString(),
      }),
    ).toEqual({ grant_id: u.grant.grant_id, error: "invalid_instruction" });
  });
});

// ===========================================================================
// AS item 40 — positive assessment
// ===========================================================================

describe("AS item 40 — positive assessment", () => {
  it("is positive whatever the read state while no instruction applies", () => {
    const active = issued();
    const single = issued("single_use");
    const expiring = issued("continuous", {
      expires_at: new Date(clockMs + H).toISOString(),
    });
    const revoked = issued();
    tokens.revokeGrant(revoked.grant.grant_id);
    advance(2 * H);
    expect(answer(active.access_token, active.grant.grant_id).held_data).toBe(
      "permitted",
    );
    const s = answer(single.access_token, single.grant.grant_id);
    expect(s).toMatchObject({
      read_state: "window_closed",
      held_data: "permitted",
    });
    expect(s.ended_at).toBeUndefined();
    expect(
      answer(expiring.access_token, expiring.grant.grant_id),
    ).toMatchObject({
      read_state: "expired",
      ended_at: expiring.grant.expires_at,
      held_data: "permitted",
    });
    expect(answer(revoked.access_token, revoked.grant.grant_id).held_data).toBe(
      "permitted",
    );
  });

  it("returns no token response (a positive assessment) once an instruction applies", () => {
    const { grant, code } = seed();
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: grant.grant_id,
      advance: false,
      actionId: "a",
      inScope: all,
    });
    const result = tokens.redeemAuthorizationCode({
      code,
      clientId: CLIENT,
      redirectUri: REDIRECT,
    });
    expect(result.ok).toBe(false);
  });
});

// ===========================================================================
// AS items 41, 42 and cases P1-P9
// ===========================================================================

describe("P1 / AS item 41 — owner withdrawal at the AS (disconnect a client)", () => {
  it("lists the complete affected set, requires a disposition per grant, applies no default", () => {
    const continuous = issued("continuous");
    const consumed = issued("single_use");
    const expired = issued("continuous", {
      expires_at: new Date(clockMs + 10 * 60 * 1000).toISOString(),
    });
    seed("continuous"); // never redeemed: no held data, but active, so it ends too
    issued("continuous", {}, OTHER_CLIENT); // another client's grant: out of scope
    advance(2 * H);

    const affected = lifecycle.affectedSet({
      subjectId: OWNER,
      action: "disconnect_client",
      clientId: CLIENT,
      inScope: all,
    });
    expect(affected.ok).toBe(true);
    if (!affected.ok) return;
    const byId = new Map(affected.grants.map((g) => [g.grant_id, g]));
    expect(byId.get(continuous.grant.grant_id)).toMatchObject({
      effect: "end",
      preselected: null,
      disposition_required: true,
    });
    expect(byId.get(consumed.grant.grant_id)).toMatchObject({
      read_state: "window_closed",
      effect: "end",
    });
    expect(byId.get(expired.grant.grant_id)).toMatchObject({
      read_state: "expired",
      effect: "record",
    });
    expect(affected.grants.every((g) => g.client_id === CLIENT)).toBe(true);
    expect(affected.grants).toHaveLength(4);
    const options = byId.get(continuous.grant.grant_id)!.options;
    expect(options.keep.surviving_use).toMatch(/approved purpose/);
    expect(options.keep.retention_limit).toMatch(/no retention limit/);
    expect(options.delete.statements.join(" ")).toMatch(/30 days of receiving/);

    // A programmatic request without a disposition is rejected.
    const none = ownerEnd("disconnect_client", {}, { clientId: CLIENT });
    expect(none).toMatchObject({ ok: false, code: "disposition_required" });
    if (!none.ok) expect(none.missing).toHaveLength(4);
    // Partial dispositions are rejected too: no default for the rest.
    const partial = ownerEnd(
      "disconnect_client",
      { [continuous.grant.grant_id]: "keep" },
      { clientId: CLIENT },
    );
    expect(partial).toMatchObject({ ok: false, code: "disposition_required" });
    expect(tokens.resolveToken(continuous.access_token).active).toBe(false); // expired by time only
    expect(store.getGrant(continuous.grant.grant_id)!.revokedAt).toBeNull();

    const dispositions = Object.fromEntries(
      affected.grants.map((g) => [
        g.grant_id,
        g.grant_id === consumed.grant.grant_id ? "delete" : "keep",
      ]),
    ) as Record<string, "keep" | "delete">;
    const done = ownerEnd("disconnect_client", dispositions, {
      clientId: CLIENT,
    });
    expect(done.ok && done.result.complete).toBe(true);

    expect(
      answer(continuous.access_token, continuous.grant.grant_id),
    ).toMatchObject({ read_state: "revoked", held_data: "permitted" });
    expect(
      answer(consumed.access_token, consumed.grant.grant_id),
    ).toMatchObject({ read_state: "revoked", held_data: "erase" });
    // The expired grant keeps its first ending.
    expect(answer(expired.access_token, expired.grant.grant_id)).toMatchObject({
      read_state: "expired",
      ended_at: expired.grant.expires_at,
    });
  });

  it("variant: later erasure of a keep grant records a new instruction", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "keep" },
      { grantIds: [t.grant.grant_id] },
    );
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe(
      "permitted",
    );
    expect(view(t.grant.grant_id)).toMatchObject({
      disposition: "keep",
      erasure_request_available: true,
    });
    const r = lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: false,
      actionId: "b",
      inScope: all,
    });
    expect(r.ok).toBe(true);
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a.held_data).toBe("erase");
    // L1586 / item 42: the ended grant keeps its ending.
    expect(a.ended_at).toBe(store.getGrant(t.grant.grant_id)!.revokedAt);
  });
});

describe("P1a (whole-client analogue; packages are not supported) — per-grant results", () => {
  it("reports pending and recorded per grant, never complete on a partial, and a retry keeps clocks", () => {
    const a = issued();
    ownerEnd(
      "revoke",
      { [a.grant.grant_id]: "keep" },
      { grantIds: [a.grant.grant_id] },
    );
    const endedAtA = store.getGrant(a.grant.grant_id)!.revokedAt;
    advance(H);
    const b = issued();
    const affected = lifecycle.affectedSet({
      subjectId: OWNER,
      action: "disconnect_client",
      clientId: CLIENT,
      inScope: all,
    });
    if (!affected.ok) throw new Error();
    // Newest first: B is recorded, then the evidence advance for A fails.
    expect(affected.grants.map((g) => g.grant_id)).toEqual([
      b.grant.grant_id,
      a.grant.grant_id,
    ]);
    failAnchorWrites = [anchorWrites + 2];
    const first = ownerEnd(
      "disconnect_client",
      { [a.grant.grant_id]: "delete", [b.grant.grant_id]: "delete" },
      { clientId: CLIENT, actionId: "act_p1a" },
    );
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.result.complete).toBe(false);
    expect(first.result.grants).toEqual([
      expect.objectContaining({
        grant_id: b.grant.grant_id,
        state: "recorded",
      }),
      expect.objectContaining({ grant_id: a.grant.grant_id, state: "pending" }),
    ]);
    const bInstruction = store.lifecycle.getInstruction(b.grant.grant_id)!;
    advance(10 * 60 * 1000);
    const retry = ownerEnd(
      "disconnect_client",
      { [a.grant.grant_id]: "delete", [b.grant.grant_id]: "delete" },
      { clientId: CLIENT, actionId: "act_p1a" },
    );
    expect(retry.ok && retry.result.complete).toBe(true);
    expect(store.lifecycle.getInstruction(b.grant.grant_id)).toEqual(
      expect.objectContaining({
        instructionId: bInstruction.instructionId,
        acceptedAt: bInstruction.acceptedAt,
        effectiveAt: bInstruction.effectiveAt,
      }),
    );
    const answerA = answer(a.access_token, a.grant.grant_id);
    expect(answerA).toMatchObject({
      held_data: "erase",
      read_state: "revoked",
      ended_at: endedAtA,
    });
    expect(answer(b.access_token, b.grant.grant_id).held_data).toBe("erase");
  });
});

describe("P2 (separate-grant analogue; packages are not supported) — withdraw one of two", () => {
  it("A answers erase; B still reads and answers permitted", () => {
    const a = issued();
    const b = issued();
    ownerEnd(
      "revoke",
      { [a.grant.grant_id]: "delete" },
      { grantIds: [a.grant.grant_id] },
    );
    expect(answer(a.access_token, a.grant.grant_id).held_data).toBe("erase");
    expect(tokens.resolveToken(b.access_token).active).toBe(true);
    expect(answer(b.access_token, b.grant.grant_id)).toMatchObject({
      read_state: "active",
      held_data: "permitted",
    });
    // Client-side derivative deletion: out of scope for the AS.
  });
});

describe("P3 / AS item 46 — narrowing", () => {
  it("states the effect of each disposition before the final step; G answers erase", () => {
    const g = issued();
    const affected = lifecycle.affectedSet({
      subjectId: OWNER,
      action: "narrowing",
      grantIds: [g.grant.grant_id],
      inScope: all,
    });
    if (!affected.ok) throw new Error();
    const opts = affected.grants[0]!.options;
    expect(opts.delete.statements[0]).toMatch(
      /delete its copy from the old grant/,
    );
    expect(opts.delete.statements[0]).toMatch(/read again under the new grant/);
    expect(opts.keep.surviving_use).toMatch(
      /including data that the new grant does not cover/,
    );
    ownerEnd(
      "narrowing",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
    expect(
      store.lifecycle.listOwnerDispositions(g.grant.grant_id)[0]!.path,
    ).toBe("narrowing");
    // Reacquisition under G2 and relabelling: client-side, out of scope.
  });
});

describe("P4 — revocation at the owner's direction (RFC 7009 with pdpp_disposition)", () => {
  it("records the owner's choice time as receipt despite delayed delivery", () => {
    const t = issued();
    const ownerChoice = new Date(clockMs).toISOString();
    advance(6 * H); // the AS was unreachable
    const r = tokens.revokeClientToken({
      token: t.refresh_token!,
      clientId: CLIENT,
      disposition: "delete",
      reportedAt: ownerChoice,
    });
    expect(r).toMatchObject({ ok: true, dispositionRecorded: true });
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a.held_data).toBe("erase");
    const instruction = store.lifecycle.getInstruction(t.grant.grant_id)!;
    expect(instruction.receiptReportedAt).toBe(ownerChoice);
    expect(instruction.origin).toBe("client");
    expect(view(t.grant.grant_id).erasure!.deletion_due_by).toBe(
      new Date(Date.parse(ownerChoice) + DELETION_BOUND_MS).toISOString(),
    );
  });

  it("without reported_at records no receipt and shows no deletion date", () => {
    const t = issued();
    tokens.revokeClientToken({
      token: t.refresh_token!,
      clientId: CLIENT,
      disposition: "delete",
    });
    const v = view(t.grant.grant_id).erasure!;
    expect(v.deletion_due_by).toBeUndefined();
    expect(v.stages.receipt_reported).toBeUndefined();
  });

  it("variant: a superseded refresh token alone ends the grant but records no disposition", () => {
    const t = issued();
    tokens.refresh({ refreshToken: t.refresh_token! });
    // Revoking with the superseded token: no current authentication.
    const r = tokens.revokeClientToken({
      token: t.refresh_token!,
      clientId: CLIENT,
      disposition: "delete",
    });
    expect(r).toMatchObject({ ok: true, dispositionRecorded: false });
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
    expect(store.lifecycle.getInstruction(t.grant.grant_id)).toBeNull();
    // A confidential client with current authentication: not applicable (no
    // confidential clients on this AS).
  });

  it("variant: crash after the durable record, before acknowledgement; a retry completes it without moving clocks", () => {
    const t = issued();
    failAnchorWrites = [anchorWrites + 1];
    expect(() =>
      tokens.revokeClientToken({
        token: t.refresh_token!,
        clientId: CLIENT,
        disposition: "delete",
        reportedAt: clock().toISOString(),
      }),
    ).toThrow(/evidence/);
    const first = store.lifecycle.getInstruction(t.grant.grant_id)!;
    advance(5 * 60 * 1000);
    const retry = tokens.revokeClientToken({
      token: t.refresh_token!,
      clientId: CLIENT,
      disposition: "delete",
      reportedAt: first.receiptReportedAt!,
    });
    expect(retry.ok).toBe(true);
    expect(store.lifecycle.getInstruction(t.grant.grant_id)).toEqual(first);
    expect(store.listDispositions(t.grant.grant_id)).toHaveLength(1);
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe("erase");
  });
});

describe("P5 — token revocation without a disposition", () => {
  it("family revocation ends the grant; revoked, permitted, no instruction", () => {
    const t = issued();
    tokens.revokeClientToken({ token: t.refresh_token!, clientId: CLIENT });
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
    expect(store.lifecycle.getInstruction(t.grant.grant_id)).toBeNull();
  });

  it("an access token a family covers ends only itself", () => {
    const t = issued();
    tokens.revokeClientToken({ token: t.access_token, clientId: CLIENT });
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "active",
      held_data: "permitted",
    });
  });

  it("variant: an access token no family covers ends its grant", () => {
    const t = issued("single_use");
    tokens.revokeClientToken({ token: t.access_token, clientId: CLIENT });
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
  });
});

describe("P6 / AS item 42 — expiry and the advance election", () => {
  it("expiry: reads end, answer expired + permitted", () => {
    const t = issued("continuous", {
      expires_at: new Date(clockMs + H).toISOString(),
    });
    advance(H);
    expect(tokens.resolveToken(t.access_token).active).toBe(false);
    expect(tokens.refresh({ refreshToken: t.refresh_token! }).ok).toBe(false);
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "expired",
      ended_at: t.grant.expires_at,
      held_data: "permitted",
    });
  });

  it("variant: an advance election takes effect at expires_at and does not end the grant earlier", () => {
    const t = issued("continuous", {
      expires_at: new Date(clockMs + 4 * H).toISOString(),
    });
    const r = lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    expect(r.ok).toBe(true);
    expect(tokens.resolveToken(t.access_token).active).toBe(true);
    expect(tokens.refresh({ refreshToken: t.refresh_token! }).ok).toBe(true);
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "active",
      held_data: "permitted",
    });
    expect(view(t.grant.grant_id).erasure).toMatchObject({
      advance: true,
      latest_stage: "requested",
    });
    expect(view(t.grant.grant_id).erasure!.effective_at).toBeUndefined();
    advance(4 * H);
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a).toMatchObject({ read_state: "expired", held_data: "erase" });
    expect(a.erasure!.effective_at).toBe(t.grant.expires_at);
    expect(a.erasure!.stop_use_by).toBe(
      new Date(
        Date.parse(t.grant.expires_at!) + STOP_USE_BOUND_MS,
      ).toISOString(),
    );
  });

  it("an immediate request after an advance election ends the grant and keeps the instruction id and acceptance", () => {
    const t = issued();
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    const elected = store.lifecycle.getInstruction(t.grant.grant_id)!;
    advance(H);
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: false,
      actionId: "now",
      inScope: all,
    });
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a.erasure).toMatchObject({
      instruction_id: elected.instructionId,
      accepted_at: elected.acceptedAt,
      effective_at: clock().toISOString(),
    });
    expect(a.read_state).toBe("revoked");
  });
});

describe("P7 / AS item 46 — security revocation", () => {
  it("creates no instruction; the owner sees the ending, its reason, and the offered disposition", () => {
    const t = issued();
    expect(
      lifecycle.securityRevoke({
        grantIds: [t.grant.grant_id],
        reason: "client delisted",
      }),
    ).toEqual([t.grant.grant_id]);
    expect(answer(t.access_token, t.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
    expect(view(t.grant.grant_id)).toMatchObject({
      ending: { reason: "security", detail: "client delisted" },
      disposition: "offered",
      erasure_request_available: true,
    });
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: false,
      actionId: "x",
      inScope: all,
    });
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe("erase");
  });
});

describe("P8 — refresh replay", () => {
  it("revokes the family, does not end the grant, and the superseded token still queries", () => {
    const t = issued();
    expect(tokens.refresh({ refreshToken: t.refresh_token! }).ok).toBe(true);
    expect(tokens.refresh({ refreshToken: t.refresh_token! }).ok).toBe(false);
    expect(store.getGrant(t.grant.grant_id)!.revokedAt).toBeNull();
    expect(store.lifecycle.getInstruction(t.grant.grant_id)).toBeNull();
    expect(answer(t.refresh_token!, t.grant.grant_id)).toMatchObject({
      read_state: "active",
      held_data: "permitted",
    });
  });
});

describe("P9 / AS item 46 — AS decommission", () => {
  it("offers a disposition for every grant whose held data may remain and warns about undelivered deletes", () => {
    const notSent = issued();
    const sent = issued();
    const kept = issued();
    const offered = issued();
    ownerEnd(
      "revoke",
      { [notSent.grant.grant_id]: "delete" },
      { grantIds: [notSent.grant.grant_id] },
    );
    ownerEnd(
      "revoke",
      { [sent.grant.grant_id]: "delete" },
      { grantIds: [sent.grant.grant_id] },
    );
    answer(sent.access_token, sent.grant.grant_id); // first return
    ownerEnd(
      "revoke",
      { [kept.grant.grant_id]: "keep" },
      { grantIds: [kept.grant.grant_id] },
    );
    const v = lifecycle.decommissionView({ subjectId: OWNER, inScope: all });
    const byId = new Map(v.grants.map((g) => [g.grant_id, g]));
    expect(byId.get(notSent.grant.grant_id)).toMatchObject({
      stage: "recorded",
      disposition: "delete",
    });
    expect(byId.get(notSent.grant.grant_id)!.warning).toMatch(
      /cannot learn of it/,
    );
    expect(byId.get(sent.grant.grant_id)).toMatchObject({ stage: "sent" });
    expect(byId.get(sent.grant.grant_id)!.warning).toMatch(
      /not reported receiving/,
    );
    expect(byId.get(kept.grant.grant_id)).toMatchObject({
      stage: "recorded",
      disposition: "keep",
    });
    expect(byId.get(kept.grant.grant_id)!.warning).toBeUndefined();
    expect(byId.get(offered.grant.grant_id)).toMatchObject({
      stage: "offered",
      preselected: null,
    });

    const missing = lifecycle.confirmDecommission({
      subjectId: OWNER,
      dispositions: {},
      actionId: "dc",
      inScope: all,
    });
    expect(missing).toMatchObject({
      ok: false,
      code: "disposition_required",
      missing: [offered.grant.grant_id],
    });
    const ok = lifecycle.confirmDecommission({
      subjectId: OWNER,
      dispositions: { [offered.grant.grant_id]: "keep" },
      actionId: "dc",
      inScope: all,
    });
    expect(ok.ok).toBe(true);
    if (!ok.ok) return;
    expect(ok.view.confirmed_at).toBe(clock().toISOString());
    expect(answer(offered.access_token, offered.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
  });
});

// ===========================================================================
// AS items 42, 43 — erasure records and owner statements
// ===========================================================================

describe("AS items 42, 43 — instruction records, stages and statements", () => {
  it("an immediate instruction revokes an active grant; it is terminal; a repeat returns it", () => {
    const t = issued();
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: false,
      actionId: "1",
      inScope: all,
    });
    const first = store.lifecycle.getInstruction(t.grant.grant_id)!;
    expect(store.getGrant(t.grant.grant_id)!.revokedAt).toBe(first.effectiveAt);
    advance(H);
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: t.grant.grant_id,
      advance: false,
      actionId: "2",
      inScope: all,
    });
    // A later keep does not cancel it either.
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "keep" },
      { grantIds: [t.grant.grant_id] },
    );
    expect(store.lifecycle.getInstruction(t.grant.grant_id)).toEqual(first);
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe("erase");
  });

  it("records acceptance, first return, reported receipt and reported completion separately", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const accepted = clock().toISOString();
    let v = view(t.grant.grant_id).erasure!;
    expect(v.latest_stage).toBe("requested");
    expect(v.summary).toMatch(/not yet sent/);
    expect(v.deletion_due_by).toBeUndefined();

    advance(3 * H);
    const a = answer(t.access_token, t.grant.grant_id);
    const sentAt = clock().toISOString();
    v = view(t.grant.grant_id).erasure!;
    expect(v.stages).toMatchObject({ requested_at: accepted, sent_at: sentAt });
    expect(v.latest_stage).toBe("sent");
    expect(v.summary).toBe(
      `sent on ${sentAt.slice(0, 10)}; no receipt reported`,
    );
    // L1661: never a receipt-based date from acceptance or first return.
    expect(v.deletion_due_by).toBeUndefined();
    expect(v.stop_use_by).toBe(a.erasure!.stop_use_by);
    expect(v.statements[0]).toContain(a.erasure!.stop_use_by);
    expect(v.statements.join(" ")).toMatch(/not proof of remote deletion/);
    expect(v.statements.join(" ")).toMatch(/no maximum delivery delay/);

    // Reports need recovery after the revocation (D5 covers that path).
    const rec = recover([t.grant.grant_id]);
    const q = new Date(clockMs - H).toISOString();
    answer(rec, t.grant.grant_id, {
      report: "received",
      instruction_id: a.erasure!.instruction_id,
      reported_at: q,
    });
    advance(24 * H);
    const done = clock().toISOString();
    answer(rec, t.grant.grant_id, {
      report: "completed",
      instruction_id: a.erasure!.instruction_id,
      reported_at: done,
    });
    v = view(t.grant.grant_id).erasure!;
    expect(v.stages.receipt_reported!.reported_at).toBe(q);
    expect(v.stages.completion_reported!.reported_at).toBe(done);
    expect(v.latest_stage).toBe("completion_reported");
    expect(v.deletion_due_by).toBe(
      new Date(Date.parse(q) + DELETION_BOUND_MS).toISOString(),
    );
    expect(view(t.grant.grant_id).held_data_may_remain).toBe(false);
  });
});

/** Run the lifecycle recovery approval and redeem it. Returns the token. */
function recover(grantIds: string[]): string {
  const opened = lifecycle.openRecoverySession({
    subjectId: OWNER,
    clientId: CLIENT,
    grantIds,
    redirectUri: REDIRECT,
    inScope: all,
  });
  if (!opened.ok) throw new Error(opened.message);
  const review = lifecycle.recoveryReview(opened.session_id, OWNER);
  if (!review.ok) throw new Error();
  const approved = lifecycle.approveRecovery({
    sessionId: opened.session_id,
    subjectId: OWNER,
    reviewDigest: review.review.review_digest,
  });
  if (!approved.ok) throw new Error(approved.code);
  const code = new URL(approved.redirect_uri).searchParams.get("code")!;
  const redeemed = lifecycle.redeemRecoveryCode({
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
  });
  if (!redeemed.ok) throw new Error(redeemed.message);
  return redeemed.issued.access_token;
}

// ===========================================================================
// AS item 47 and cases D2, D3, D5 — lifecycle authentication and recovery
// ===========================================================================

describe("D2 — lifecycle authentication with an expired token", () => {
  it("an expired access token of a revoked grant queries but cannot write", () => {
    const t = issued("single_use");
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    advance(2 * H);
    const a = answer(t.access_token, t.grant.grant_id);
    expect(a.held_data).toBe("erase");
    expect(
      answer(t.access_token, t.grant.grant_id, {
        report: "received",
        instruction_id: a.erasure!.instruction_id,
        reported_at: clock().toISOString(),
      }),
    ).toEqual({
      grant_id: t.grant.grant_id,
      error: "current_authentication_required",
    });
  });
});

describe("D3 / AS item 47 — recovery after lifecycle compromise", () => {
  it("disabled tokens get invalid_token; the recovery token authenticates queries and writes for approved grants only", () => {
    const g1 = issued();
    const g2 = issued();
    ownerEnd(
      "revoke",
      { [g1.grant.grant_id]: "delete" },
      { grantIds: [g1.grant.grant_id] },
    );
    lifecycle.disableForLifecycle({
      clientId: CLIENT,
      grantIds: [g1.grant.grant_id, g2.grant.grant_id],
    });
    expect(
      call({ grant_id: g1.grant.grant_id, token: g1.access_token }),
    ).toMatchObject({ status: 401, body: { error: "invalid_token" } });

    const opened = lifecycle.openRecoverySession({
      subjectId: OWNER,
      clientId: CLIENT,
      grantIds: [g1.grant.grant_id],
      redirectUri: REDIRECT,
      inScope: all,
    });
    if (!opened.ok) throw new Error();
    const review = lifecycle.recoveryReview(opened.session_id, OWNER);
    if (!review.ok) throw new Error();
    expect(review.review.grants[0]).toMatchObject({
      grant_id: g1.grant.grant_id,
      client: { client_id: CLIENT, display_name: "Concert Finder" },
      source_id: g1.grant.source.id,
      purpose_code: g1.grant.purpose_code,
      issued_at: g1.grant.issued_at,
    });
    expect(review.review.statement).toMatch(
      /no access to read your data and no processing authority/,
    );
    const approved = lifecycle.approveRecovery({
      sessionId: opened.session_id,
      subjectId: OWNER,
      reviewDigest: review.review.review_digest,
    });
    if (!approved.ok) throw new Error();
    const code = new URL(approved.redirect_uri).searchParams.get("code")!;
    const redeemed = lifecycle.redeemRecoveryCode({
      code,
      clientId: CLIENT,
      redirectUri: REDIRECT,
    });
    if (!redeemed.ok) throw new Error();
    // No refresh token, no grant, no held_data: not a positive assessment.
    expect(Object.keys(redeemed.issued).sort()).toEqual([
      "access_token",
      "authorization_details",
      "token_type",
    ]);
    expect(redeemed.issued.authorization_details).toEqual([
      { type: PDPP_GRANT_LIFECYCLE_TYPE, grant_ids: [g1.grant.grant_id] },
    ]);
    const rt = redeemed.issued.access_token;
    // No read access: the RS path and introspection both see it inactive.
    expect(tokens.resolveToken(rt).active).toBe(false);
    expect(tokens.introspect(rt)).toEqual({ active: false });
    // Queries and writes for the approved grant.
    const a = answer(rt, g1.grant.grant_id);
    expect(a.held_data).toBe("erase");
    expect(
      answer(rt, g1.grant.grant_id, {
        report: "received",
        instruction_id: a.erasure!.instruction_id,
        reported_at: clock().toISOString(),
      }).held_data,
    ).toBe("erase");
    // Not for another grant.
    expect(answer(rt, g2.grant.grant_id)).toEqual({
      grant_id: g2.grant.grant_id,
      error: "invalid_grant",
    });
    // Recovery opened no read window.
    expect(store.getGrant(g1.grant.grant_id)!.revokedAt).not.toBeNull();
    // A replayed recovery code redeems nothing.
    expect(
      lifecycle.redeemRecoveryCode({
        code,
        clientId: CLIENT,
        redirectUri: REDIRECT,
      }).ok,
    ).toBe(false);
  });

  it("rejects a recovery detail with extra members or bad grant_ids, and a grant of another client without saying which", () => {
    expect(
      GrantLifecycleService.parseRecoveryDetail({
        type: PDPP_GRANT_LIFECYCLE_TYPE,
        grant_ids: ["a"],
        streams: [],
      }).ok,
    ).toBe(false);
    expect(
      GrantLifecycleService.parseRecoveryDetail({
        type: PDPP_GRANT_LIFECYCLE_TYPE,
        grant_ids: [],
      }).ok,
    ).toBe(false);
    expect(
      GrantLifecycleService.parseRecoveryDetail({
        type: PDPP_GRANT_LIFECYCLE_TYPE,
        grant_ids: ["a", "a"],
      }).ok,
    ).toBe(false);
    expect(
      GrantLifecycleService.parseRecoveryDetail({
        type: PDPP_GRANT_LIFECYCLE_TYPE,
        grant_ids: [""],
      }).ok,
    ).toBe(false);
    const mine = issued();
    const theirs = issued("continuous", {}, OTHER_CLIENT);
    const a = lifecycle.openRecoverySession({
      subjectId: OWNER,
      clientId: CLIENT,
      grantIds: [mine.grant.grant_id, theirs.grant.grant_id],
      redirectUri: REDIRECT,
      inScope: all,
    });
    const b = lifecycle.openRecoverySession({
      subjectId: OWNER,
      clientId: CLIENT,
      grantIds: ["grt_unknown"],
      redirectUri: REDIRECT,
      inScope: all,
    });
    expect(a).toEqual(b);
    expect(a.ok).toBe(false);
  });

  it("the recovery token authenticates writes until the deletion bound after the reported receipt", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const rt = recover([t.grant.grant_id]);
    const id = answer(rt, t.grant.grant_id).erasure!.instruction_id;
    advance(20 * 24 * H);
    const q = clock().toISOString();
    answer(rt, t.grant.grant_id, {
      report: "received",
      instruction_id: id,
      reported_at: q,
    });
    advance(29 * 24 * H); // 49 days after issuance, 29 after receipt
    expect(
      answer(rt, t.grant.grant_id, {
        report: "completed",
        instruction_id: id,
        reported_at: clock().toISOString(),
      }).held_data,
    ).toBe("erase");
  });
});

describe("D5 — reports after revocation", () => {
  it("a revoked token delivers the instruction; reports need recovery; the owner sees the stages", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const a = answer(t.refresh_token!, t.grant.grant_id);
    expect(a.held_data).toBe("erase");
    const q = clock().toISOString();
    for (const report of ["received", "completed"]) {
      expect(
        answer(t.refresh_token!, t.grant.grant_id, {
          report,
          instruction_id: a.erasure!.instruction_id,
          reported_at: q,
        }),
      ).toEqual({
        grant_id: t.grant.grant_id,
        error: "current_authentication_required",
      });
    }
    const v = view(t.grant.grant_id).erasure!;
    expect(v.latest_stage).toBe("sent");
    expect(v.deletion_due_by).toBeUndefined();
    advance(2 * H);
    const rt = recover([t.grant.grant_id]);
    answer(rt, t.grant.grant_id, {
      report: "received",
      instruction_id: a.erasure!.instruction_id,
      reported_at: q,
    });
    answer(rt, t.grant.grant_id, {
      report: "completed",
      instruction_id: a.erasure!.instruction_id,
      reported_at: clock().toISOString(),
    });
    expect(view(t.grant.grant_id).erasure!.deletion_due_by).toBe(
      new Date(Date.parse(q) + DELETION_BOUND_MS).toISOString(),
    );
  });

  it("variant: an owner delete in the client conveyed with current authentication and reported_at is the receipt", () => {
    const t = issued();
    const q = new Date(clockMs - 10 * 60 * 1000).toISOString();
    answer(t.access_token, t.grant.grant_id, {
      pdpp_disposition: "delete",
      reported_at: q,
    });
    expect(view(t.grant.grant_id).erasure).toMatchObject({
      latest_stage: "receipt_reported",
      stages: { receipt_reported: { reported_at: q } },
    });
  });
});

// ===========================================================================
// Cases C1-C9 (AS-side assertions)
// ===========================================================================

describe("C1-C9 — time limits and clocks, AS side", () => {
  it("fixes the four held-data limits", () => {
    expect(RECONCILIATION_INTERVAL_MS).toBe(24 * H);
    expect(RETRY_INTERVAL_MS).toBe(H);
    expect(STOP_USE_BOUND_MS).toBe(48 * H);
    expect(DELETION_BOUND_MS).toBe(30 * 24 * H);
  });

  it("C1: after a reconciliation interval the client's old token still gets an answer (client scheduling: out of scope)", () => {
    const t = issued();
    advance(RECONCILIATION_INTERVAL_MS + H);
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe(
      "permitted",
    );
  });

  it("C2/C4: stop_use_by is effective + 48 h; redelivery the next day moves no clock", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const first = answer(t.access_token, t.grant.grant_id);
    expect(
      Date.parse(first.erasure!.stop_use_by) -
        Date.parse(first.erasure!.effective_at),
    ).toBe(STOP_USE_BOUND_MS);
    const firstReturn = store.lifecycle.getInstruction(
      t.grant.grant_id,
    )!.firstReturnedAt;
    advance(24 * H);
    const again = answer(t.access_token, t.grant.grant_id);
    expect(again.erasure).toEqual(first.erasure);
    expect(again.assessed_at).not.toBe(first.assessed_at);
    expect(
      store.lifecycle.getInstruction(t.grant.grant_id)!.firstReturnedAt,
    ).toBe(firstReturn);
    expect(view(t.grant.grant_id).erasure!.deletion_due_by).toBeUndefined();
  });

  it("C5a: an AS clock that moves backwards moves no deadline", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const before = answer(t.access_token, t.grant.grant_id).erasure!;
    advance(-6 * H);
    expect(answer(t.access_token, t.grant.grant_id).erasure).toEqual(before);
  });

  it("C6: an instruction always requires deletion, even when retention says anonymize", () => {
    const t = issued("continuous", {
      retention: { max_duration: "P30D", on_expiry: "anonymize" },
    });
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    expect(answer(t.access_token, t.grant.grant_id).held_data).toBe("erase");
    expect(view(t.grant.grant_id).erasure!.statements.join(" ")).toMatch(
      /delete covered data within 30 days/,
    );
  });

  it("C7: not applicable — this AS supports no processing permission", () => {
    expect(SUPPORTED_PROCESSING_PERMISSIONS).toEqual([]);
  });

  it("C9: retained reports keep their end form, correct without overwriting, and are never completion", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const rt = recover([t.grant.grant_id]);
    const id = answer(rt, t.grant.grant_id).erasure!.instruction_id;
    const r1 = clock().toISOString();
    answer(rt, t.grant.grant_id, {
      report: "retained",
      instruction_id: id,
      reported_at: r1,
      retained_until: "event:close of the 2026 tax audit",
      retention_basis: "tax record-keeping law",
      retention_scope: "invoices for 2026",
    });
    let v = view(t.grant.grant_id).erasure!;
    expect(v.latest_stage).toBe("exception_reported");
    expect(v.stages.completion_reported).toBeUndefined();
    expect(v.stages.exceptions).toEqual([
      expect.objectContaining({
        retained_until: { kind: "event", value: "close of the 2026 tax audit" },
        retention_basis: "tax record-keeping law",
        retention_scope: "invoices for 2026",
      }),
    ]);
    expect(view(t.grant.grant_id).held_data_may_remain).toBe(true);
    advance(H);
    answer(rt, t.grant.grant_id, {
      report: "retained",
      instruction_id: id,
      reported_at: clock().toISOString(),
      retained_until: "2027-06-30T00:00:00Z",
    });
    answer(rt, t.grant.grant_id, {
      report: "retained",
      instruction_id: id,
      reported_at: clock().toISOString(),
      retained_until: "unknown",
    });
    v = view(t.grant.grant_id).erasure!;
    expect(v.stages.exceptions!.map((e) => e.retained_until.kind)).toEqual([
      "event",
      "date",
      "unknown",
    ]);
    advance(H);
    answer(rt, t.grant.grant_id, {
      report: "completed",
      instruction_id: id,
      reported_at: clock().toISOString(),
    });
    expect(view(t.grant.grant_id).erasure!.latest_stage).toBe(
      "completion_reported",
    );
  });

  it("C8: answers carry absolute RFC 3339 deadlines (relay to downstream holders: client side, out of scope)", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const e = answer(t.access_token, t.grant.grant_id).erasure!;
    for (const v of [e.accepted_at, e.effective_at, e.stop_use_by])
      expect(v).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ===========================================================================
// AS item 44 and cases D1, D1a, D4 — durability
// ===========================================================================

describe("AS item 44 — the recorded-event log", () => {
  it("hash-chains every recorded event and anchors the head outside the SQLite file", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    const db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare(
        "SELECT seq, kind, prev_hash, hash FROM pdpp_history_log ORDER BY seq",
      )
      .all() as Array<{
      seq: number;
      kind: string;
      prev_hash: string;
      hash: string;
    }>;
    db.close();
    expect(rows.map((r) => r.kind)).toEqual(
      expect.arrayContaining([
        "grant_issued",
        "code_redeemed",
        "owner_disposition",
        "grant_revoked",
        "erasure_instruction",
      ]),
    );
    for (let i = 1; i < rows.length; i++)
      expect(rows[i]!.prev_hash).toBe(rows[i - 1]!.hash);
    const anchor = JSON.parse(
      readFileSync(`${dbPath}.history-anchor.json`, "utf8"),
    );
    expect(anchor.seq).toBe(rows.at(-1)!.seq);
    expect(anchor.hash).toBe(rows.at(-1)!.hash);
    expect(anchor.erasures[t.grant.grant_id].instruction_id).toBe(
      store.lifecycle.getInstruction(t.grant.grant_id)!.instructionId,
    );
  });

  it("never acknowledges when the evidence cannot be advanced (case D4, injected failure)", () => {
    const t = issued();
    failAnchorWrites = [anchorWrites + 1];
    const r = ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    expect(r.ok && r.result.complete).toBe(false);
    expect(r.ok && r.result.grants[0]!.state).toBe("pending");
  });

  it("uses random grant and instruction identifiers", () => {
    const t = issued();
    ownerEnd(
      "revoke",
      { [t.grant.grant_id]: "delete" },
      { grantIds: [t.grant.grant_id] },
    );
    expect(
      store.lifecycle.getInstruction(t.grant.grant_id)!.instructionId,
    ).toMatch(/^ers_[0-9a-f]{32}$/);
  });
});

describe("D1 — restore after an acknowledged erasure", () => {
  it("fails closed: no token or active introspection; lifecycle 503 or the anchored instruction", () => {
    const g = issued();
    const other = issued();
    const { db } = backup("before");
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    const acknowledged = store.lifecycle.getInstruction(g.grant.grant_id)!;
    restoreFrom(db);
    expect(store.history.current()).toEqual({
      current: false,
      reason: "history_behind_anchor",
    });
    expect(tokens.resolveToken(g.access_token).active).toBe(false);
    expect(tokens.introspect(other.access_token)).toEqual({ active: false });
    expect(tokens.refresh({ refreshToken: g.refresh_token! })).toMatchObject({
      ok: false,
      failure: { code: "temporarily_unavailable" },
    });
    // The anchored, complete instruction MAY be returned (L1820)...
    expect(answer(g.access_token, g.grant.grant_id)).toMatchObject({
      held_data: "erase",
      read_state: "revoked",
      erasure: {
        instruction_id: acknowledged.instructionId,
        effective_at: acknowledged.effectiveAt,
      },
    });
    // ...but nothing positive: the other grant gets 503 with Retry-After.
    const r = call({
      grant_id: other.grant.grant_id,
      token: other.access_token,
    });
    expect(r).toMatchObject({
      status: 503,
      body: { error: "temporarily_unavailable" },
    });
    expect("retryAfterSeconds" in r && r.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("variant: a restored advance election never yields the old schedule after an immediate request", () => {
    const g = issued("continuous", {
      expires_at: new Date(clockMs + 48 * H).toISOString(),
    });
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    const { db } = backup("elected");
    advance(H);
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: false,
      actionId: "now",
      inScope: all,
    });
    const authoritative = store.lifecycle.getInstruction(g.grant.grant_id)!;
    restoreFrom(db);
    advance(72 * H); // past the originally scheduled time
    const a = answer(g.access_token, g.grant.grant_id);
    expect(a.erasure!.effective_at).toBe(authoritative.effectiveAt);
    expect(a.erasure!.effective_at).not.toBe(g.grant.expires_at);
  });
});

describe("D1a — restore across issuance paths", () => {
  it("refresh, code exchange, introspection and lifecycle writes all fail for a revived grant", () => {
    const g = issued();
    const pending = seed(); // an unredeemed code in the backup
    const single = seed("single_use");
    const { db } = backup("live");
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "keep" },
      { grantIds: [g.grant.grant_id] },
    );
    redeem(single.code); // consumption + redemption after the backup
    restoreFrom(db);
    expect(tokens.refresh({ refreshToken: g.refresh_token! }).ok).toBe(false);
    expect(
      tokens.redeemAuthorizationCode({
        code: pending.code,
        clientId: CLIENT,
        redirectUri: REDIRECT,
      }).ok,
    ).toBe(false);
    // The single_use code redeemed after the backup is not redeemed again.
    expect(
      tokens.redeemAuthorizationCode({
        code: single.code,
        clientId: CLIENT,
        redirectUri: REDIRECT,
      }).ok,
    ).toBe(false);
    expect(tokens.introspect(g.access_token)).toEqual({ active: false });
    expect(
      call({
        grant_id: g.grant.grant_id,
        token: g.access_token,
        pdpp_disposition: "delete",
      }).status,
    ).toBe(503);
    // Package fan-out and token re-delivery: this AS has neither path.
    // Cached introspection at the RS: an RS-side assertion, out of scope here.
  });
});

describe("D4 — history loss", () => {
  it("variant 1: the store ends before the anchored position; owner revocation is accepted, pending, applied first", () => {
    const g = issued();
    const h = issued();
    const { db } = backup("old");
    issued(); // an event after the backup
    restoreFrom(db);
    expect(store.history.isCurrent()).toBe(false);
    const call503 = call({ grant_id: h.grant.grant_id, token: h.access_token });
    expect(call503.status).toBe(503);
    // The owner revokes G with delete while the history is unavailable.
    const pending = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    expect(pending.ok).toBe(true);
    if (!pending.ok) return;
    expect(pending.result.complete).toBe(false);
    expect(pending.result.grants).toEqual([
      { grant_id: g.grant.grant_id, state: "pending", disposition: "delete" },
    ]);
    expect(pending.result.statement).toMatch(/recorded and pending/);
    // F5: a grant the stale store lacks is accepted too (L1827).
    const unknown = ownerEnd(
      "revoke",
      { grt_unknown: "keep" },
      { grantIds: ["grt_unknown"] },
    );
    expect(unknown.ok && unknown.result.grants[0]!.state).toBe("pending");
    // The owner's ceiling still applies to a grant the store holds.
    expect(
      lifecycle.endGrantsForOwner({
        subjectId: OWNER,
        action: "revoke",
        grantIds: [h.grant.grant_id],
        dispositions: { [h.grant.grant_id]: "keep" },
        actionId: "scoped",
        inScope: () => false,
      }),
    ).toMatchObject({ ok: false, code: "not_found" });
    // A request without a disposition is still rejected meanwhile.
    expect(
      ownerEnd("revoke", {}, { grantIds: [g.grant.grant_id] }),
    ).toMatchObject({ ok: false, code: "disposition_required" });

    // Re-establishing needs an explicit disposition for every other grant it ends.
    const missing = lifecycle.reestablishHistory({
      dispositions: {},
      actionId: "re",
    });
    expect(missing).toMatchObject({ ok: false, code: "disposition_required" });
    if (missing.ok) return;
    expect(missing.missing).not.toContain(g.grant.grant_id);
    const ok = lifecycle.reestablishHistory({
      dispositions: Object.fromEntries(
        missing.missing.map((id) => [id, "keep"]),
      ),
      actionId: "re",
    });
    expect(ok.ok).toBe(true);
    expect(store.history.isCurrent()).toBe(true);
    expect(answer(g.access_token, g.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "erase",
    });
    expect(answer(h.access_token, h.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "permitted",
    });
    expect(view(h.grant.grant_id).ending).toMatchObject({
      reason: "history_restore",
    });
    expect(lifecycle.pendingOwnerActions(OWNER)).toHaveLength(0);
    // The reopened store issues again only under new grants.
    expect(tokens.refresh({ refreshToken: h.refresh_token! }).ok).toBe(false);
  });

  it("variant 2: losing only the suffix with E keeps E's evidence; every other answer fails closed", () => {
    const e = issued();
    const other = issued();
    const { db } = backup("before-e");
    ownerEnd(
      "revoke",
      { [e.grant.grant_id]: "delete" },
      { grantIds: [e.grant.grant_id] },
    );
    restoreFrom(db);
    expect(answer(e.access_token, e.grant.grant_id).held_data).toBe("erase");
    expect(
      call({ grant_id: other.grant.grant_id, token: other.access_token })
        .status,
    ).toBe(503);
    expect(tokens.resolveToken(other.access_token).active).toBe(false);
  });

  it("variant 3: a single store restored to a snapshot before E fails closed for E's grant", () => {
    const e = issued();
    const { db } = backup("snap");
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: e.grant.grant_id,
      advance: false,
      actionId: "e",
      inScope: all,
    });
    restoreFrom(db);
    expect(tokens.resolveToken(e.access_token).active).toBe(false);
    expect(tokens.refresh({ refreshToken: e.refresh_token! }).ok).toBe(false);
    expect(answer(e.access_token, e.grant.grant_id).held_data).toBe("erase");
  });

  it("variant 4: a rollback of database and anchor together is undetected, and the statement says so", () => {
    const e = issued();
    const snap = backup("vm");
    ownerEnd(
      "revoke",
      { [e.grant.grant_id]: "delete" },
      { grantIds: [e.grant.grant_id] },
    );
    restoreFrom(snap.db, snap.anchor);
    // Undetected: the revived grant reads active again.
    expect(store.history.isCurrent()).toBe(true);
    expect(tokens.resolveToken(e.access_token).active).toBe(true);
    const statement = readFileSync(
      fileURLToPath(
        new URL(
          "../../../../docs/pdpp-durability-statement.md",
          import.meta.url,
        ),
      ),
      "utf8",
    ).replace(/\s+/g, " ");
    expect(statement).toMatch(/virtual-machine snapshot/);
    expect(statement).toMatch(/revive revoked grants/);
    expect(statement).toMatch(/lose recorded deletions/);
  });

  it("detects a missing anchor for an anchored store", () => {
    issued();
    store.close();
    rmSync(`${dbPath}.history-anchor.json`);
    open();
    expect(store.history.current()).toEqual({
      current: false,
      reason: "anchor_missing",
    });
  });

  it("detects a database from another history (epoch mismatch)", () => {
    issued();
    store.close();
    // A different database (here: a fresh one) beside the existing anchor.
    for (const s of ["", "-wal", "-shm"])
      if (existsSync(dbPath + s)) rmSync(dbPath + s);
    open();
    expect(store.history.current()).toEqual({
      current: false,
      reason: "epoch_mismatch",
    });
  });
});

// ===========================================================================
// WP6 review round 2: the reviewer's durability probes (probe.mjs S1-S4,
// probe2.mjs S3c) as regression tests, plus F3/F4/F5/F7 details.
// ===========================================================================

describe("review probes — AS item 44 durability regressions", () => {
  const anchorDoc = () =>
    JSON.parse(readFileSync(`${dbPath}.history-anchor.json`, "utf8"));

  it("S1 (F2): an advance election survives a detected restore and ends in erase at expiry", () => {
    const g = issued("continuous", {
      expires_at: new Date(clockMs + 10 * H).toISOString(),
    });
    const { db } = backup("b");
    const adv = lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    expect(adv.ok && adv.result.complete).toBe(true);
    const elected = store.lifecycle.getInstruction(g.grant.grant_id)!;
    expect(anchorDoc().elections[g.grant.grant_id]).toMatchObject({
      instruction_id: elected.instructionId,
      accepted_at: elected.acceptedAt,
      advance: true,
    });
    restoreFrom(db);
    expect(store.history.isCurrent()).toBe(false);
    advance(20 * H);
    expect(lifecycle.reestablishAffected()).toEqual([]);
    expect(
      lifecycle.reestablishHistory({ dispositions: {}, actionId: "re" }).ok,
    ).toBe(true);
    const a = answer(g.access_token, g.grant.grant_id);
    expect(a).toMatchObject({ read_state: "expired", held_data: "erase" });
    expect(a.erasure).toMatchObject({
      instruction_id: elected.instructionId,
      accepted_at: elected.acceptedAt,
      effective_at: g.grant.expires_at,
    });
  });

  it("S1b (F2): a restored election locks the re-establishment choice to delete", () => {
    const g = issued("continuous", {
      expires_at: new Date(clockMs + 100 * H).toISOString(),
    });
    const { db } = backup("b");
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    restoreFrom(db);
    const ends = lifecycle.reestablishAffected();
    expect(ends).toEqual([
      expect.objectContaining({
        grant_id: g.grant.grant_id,
        disposition_locked: "delete",
        disposition_required: false,
      }),
    ]);
    // The owner's keep cannot cancel the election (L1622).
    lifecycle.reestablishHistory({
      dispositions: { [g.grant.grant_id]: "keep" },
      actionId: "re",
    });
    expect(answer(g.access_token, g.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "erase",
    });
  });

  it("S2 (F4): disabled tokens and recovery tokens stay refused after a detected restore", () => {
    const g = issued();
    const rt = recover([g.grant.grant_id]);
    const { db } = backup("b");
    expect(
      lifecycle.disableForLifecycle({
        clientId: CLIENT,
        grantIds: [g.grant.grant_id],
      }),
    ).toBe(3);
    expect(anchorDoc().disabled_digests).toHaveLength(3);
    restoreFrom(db);
    // While not current the anchored disablings already hold.
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }).status,
    ).toBe(401);
    lifecycle.reestablishHistory({
      dispositions: { [g.grant.grant_id]: "keep" },
      actionId: "re",
    });
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }),
    ).toMatchObject({ status: 401, body: { error: "invalid_token" } });
    expect(
      call({
        grant_id: g.grant.grant_id,
        token: rt,
        pdpp_disposition: "delete",
      }),
    ).toMatchObject({ status: 401, body: { error: "invalid_token" } });
    expect(store.lifecycle.getInstruction(g.grant.grant_id)).toBeNull();
  });

  it("F4: re-establishment revokes and disables every recovery token, even one the anchor never saw", () => {
    const g = issued();
    const { db } = backup("b");
    store.close();
    // A recovery token issued, then the database restored without it is
    // not this case; here the token is in the restored store itself.
    open();
    const rt = recover([g.grant.grant_id]);
    const b2 = backup("b2");
    issued(); // advance past the backup
    restoreFrom(b2.db);
    lifecycle.reestablishHistory({
      dispositions: Object.fromEntries(
        lifecycle.reestablishAffected().map((x) => [x.grant_id, "keep"]),
      ),
      actionId: "re",
    });
    expect(call({ grant_id: g.grant.grant_id, token: rt }).status).toBe(401);
    void db;
  });

  it("S3 (F1, F3): after a failed anchor write and a restart, the evidence is written at open and a DB-only restore is detected", () => {
    const g = issued();
    const { db } = backup("b");
    failAllAnchorWrites = true;
    const first = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(first.ok && first.result.grants[0]!.state).toBe("pending");
    failAllAnchorWrites = false;
    store.close();
    open();
    expect(store.history.isCurrent()).toBe(true);
    expect(store.history.evidenceOwed()).toBe(false);
    expect(Object.keys(anchorDoc().erasures)).toEqual([g.grant.grant_id]);
    const retry = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(retry.ok && retry.result.complete).toBe(true);
    restoreFrom(db);
    expect(store.history.current()).toEqual({
      current: false,
      reason: "history_behind_anchor",
    });
    expect(answer(g.access_token, g.grant.grant_id)).toMatchObject({
      read_state: "revoked",
      held_data: "erase",
    });
    expect(tokens.resolveToken(g.access_token).active).toBe(false);
  });

  it("F1: when the anchor still cannot be written at open, the evidence stays owed and nothing is acknowledged", () => {
    const g = issued();
    failAllAnchorWrites = true;
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    store.close();
    open();
    expect(store.history.evidenceOwed()).toBe(true);
    const retry = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(retry.ok && retry.result.complete).toBe(false);
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }).status,
    ).toBe(503);
    failAllAnchorWrites = false;
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
    expect(store.history.evidenceOwed()).toBe(false);
  });

  it("S3b (F3): an erase delivered after a restart is in the anchor; a later restore keeps it erase", () => {
    const g = issued();
    const other = issued();
    const { db } = backup("b");
    failAllAnchorWrites = true;
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    failAllAnchorWrites = false;
    store.close();
    open();
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
    expect(Object.keys(anchorDoc().erasures)).toEqual([g.grant.grant_id]);
    restoreFrom(db);
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }).status,
    ).toBe(200);
    lifecycle.reestablishHistory({
      dispositions: {
        [g.grant.grant_id]: "keep",
        [other.grant.grant_id]: "keep",
      },
      actionId: "re",
    });
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
  });

  it("F3: the anchored erasure set matches every effective instruction in the database", () => {
    const a = issued();
    const b = issued("continuous", {
      expires_at: new Date(clockMs + H).toISOString(),
    });
    ownerEnd(
      "revoke",
      { [a.grant.grant_id]: "delete" },
      { grantIds: [a.grant.grant_id] },
    );
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: b.grant.grant_id,
      advance: true,
      actionId: "e",
      inScope: all,
    });
    advance(2 * H);
    answer(b.access_token, b.grant.grant_id); // settles the election at expiry
    const effective = store.lifecycle
      .listInstructions()
      .filter((i) => i.effectiveAt)
      .map((i) => i.grantId)
      .sort();
    expect(Object.keys(anchorDoc().erasures).sort()).toEqual(effective);
    expect(anchorDoc().erasures[a.grant.grant_id].token_digests).toContain(
      hashToken(a.access_token),
    );
  });

  it("S3c (F1): a same-process retry with the same action_id writes the evidence before it reports recorded", () => {
    const g = issued();
    const { db } = backup("b");
    failAllAnchorWrites = true;
    const first = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(first.ok && first.result.complete).toBe(false);
    failAllAnchorWrites = false;
    const retry = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(retry.ok && retry.result.complete).toBe(true);
    expect(Object.keys(anchorDoc().erasures)).toEqual([g.grant.grant_id]);
    restoreFrom(db);
    expect(store.history.isCurrent()).toBe(false);
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
  });

  it("S4 (F5): a grant issued after the backup: owner action accepted, instruction still delivered after re-establishment", () => {
    const old = issued();
    const { db } = backup("b");
    const g = issued();
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    const lost = issued(); // no instruction: only its pending action is kept
    restoreFrom(db);
    expect(answer(g.access_token, g.grant.grant_id)).toMatchObject({
      held_data: "erase",
    });
    const pending = lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: false,
      actionId: "Y",
      inScope: all,
    });
    expect(pending.ok && pending.result.grants[0]!.state).toBe("pending");
    const pendingLost = ownerEnd(
      "revoke",
      { [lost.grant.grant_id]: "delete" },
      { grantIds: [lost.grant.grant_id], actionId: "Z" },
    );
    expect(pendingLost.ok && pendingLost.result.grants[0]!.state).toBe(
      "pending",
    );
    const re = lifecycle.reestablishHistory({
      dispositions: { [old.grant.grant_id]: "keep" },
      actionId: "re",
    });
    expect(re).toMatchObject({
      ok: true,
      orphanedInstructions: [g.grant.grant_id],
      unappliedActions: 2,
    });
    expect(store.getGrant(g.grant.grant_id)).toBeNull();
    // Delivered from the orphan record, with the same identifier and clocks.
    const a = answer(g.access_token, g.grant.grant_id);
    expect(a).toMatchObject({ held_data: "erase", read_state: "revoked" });
    // A write with that token cannot authenticate.
    expect(
      answer(g.access_token, g.grant.grant_id, { pdpp_disposition: "delete" }),
    ).toEqual({
      grant_id: g.grant.grant_id,
      error: "current_authentication_required",
    });
    // The lost grant's token is unknown: refusal, as the statement says.
    expect(
      call({ grant_id: lost.grant.grant_id, token: lost.access_token }).status,
    ).toBe(401);
    expect(
      lifecycle
        .unappliedOwnerActions(OWNER)
        .map((u) => [u.grant_id, u.outcome]),
    ).toEqual([
      [
        g.grant.grant_id,
        "grant_not_in_restored_store_instruction_delivered_from_evidence",
      ],
      [lost.grant.grant_id, "grant_not_in_restored_store"],
    ]);
    // The orphan record survives into the new anchor.
    expect(anchorDoc().erasures[g.grant.grant_id].instruction_id).toBe(
      a.erasure!.instruction_id,
    );
  });

  it("F7: reestablishAffected filters by the caller's scope", () => {
    const g = issued();
    const { db } = backup("b");
    issued();
    restoreFrom(db);
    expect(lifecycle.reestablishAffected(undefined, () => false)).toEqual([]);
    expect(lifecycle.reestablishAffected().map((x) => x.grant_id)).toEqual([
      g.grant.grant_id,
    ]);
  });

  it("de-duplicates first_return journal lines while the history is not current", () => {
    const g = issued();
    const { db } = backup("b");
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    restoreFrom(db);
    for (let i = 0; i < 3; i++) answer(g.access_token, g.grant.grant_id);
    expect(
      store.pendingActions.list().filter((x) => x.kind === "first_return"),
    ).toHaveLength(1);
  });

  it("bounds the rate-limit map", async () => {
    const { MAX_RATE_WINDOWS } = await import("./lifecycle.js");
    const t = issued();
    for (let i = 0; i < MAX_RATE_WINDOWS + 50; i++)
      call({ grant_id: `grt_${i}`, token: t.access_token });
    const windows = (lifecycle as unknown as { windows: Map<string, unknown> })
      .windows;
    expect(windows.size).toBeLessThanOrEqual(MAX_RATE_WINDOWS);
  });
});

// ===========================================================================
// WP6 review round 3 (probe3.mjs R1-R3 and the non-blocking extras).
// ===========================================================================

describe("review round 3 — owner surface and evidence bounds", () => {
  const anchorDoc = () =>
    JSON.parse(readFileSync(`${dbPath}.history-anchor.json`, "utf8"));

  it("R1: while evidence is owed, the owner view shows pending; once written, recorded", () => {
    const g = issued();
    failAllAnchorWrites = true;
    const r = ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id], actionId: "X" },
    );
    expect(r.ok && r.result.grants[0]!.state).toBe("pending");
    expect(store.history.evidenceOwed()).toBe(true);
    expect(lifecycle.flushEvidence()).toBe(false);
    expect(view(g.grant.grant_id).evidence).toBe("pending");
    failAllAnchorWrites = false;
    expect(view(g.grant.grant_id).evidence).toBe("recorded");
    expect(store.history.evidenceOwed()).toBe(false);
    expect(Object.keys(anchorDoc().erasures)).toEqual([g.grant.grant_id]);
  });

  it("R2: an anchored advance election for a grant the restored store lacks is shown to the owner", () => {
    const old = issued();
    const { db } = backup("b");
    const g = issued("continuous", {
      expires_at: new Date(clockMs + 10 * H).toISOString(),
    });
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: true,
      actionId: "adv",
      inScope: all,
    });
    expect(anchorDoc().elections[g.grant.grant_id].subject_id).toBe(OWNER);
    restoreFrom(db);
    advance(20 * H);
    const re = lifecycle.reestablishHistory({
      dispositions: { [old.grant.grant_id]: "keep" },
      actionId: "re",
    });
    expect(re).toMatchObject({ ok: true, unappliedActions: 1 });
    expect(lifecycle.unappliedOwnerActions(OWNER)).toEqual([
      expect.objectContaining({
        grant_id: g.grant.grant_id,
        kind: "advance_election",
        disposition: "delete",
        outcome: "advance_election_grant_not_in_restored_store",
      }),
    ]);
    // Never promoted from stale state: the client is refused, not told erase.
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }).status,
    ).toBe(401);
  });

  it("bounds anchored token digests per erased grant, and drops them once completion is reported", async () => {
    const { MAX_ANCHORED_TOKEN_DIGESTS } = await import("./store.js");
    const g = issued();
    let rt = g.refresh_token!;
    for (let i = 0; i < MAX_ANCHORED_TOKEN_DIGESTS + 10; i++) {
      advance(1000);
      const r = tokens.refresh({ refreshToken: rt });
      if (!r.ok) throw new Error(r.failure.message);
      rt = r.issued.refresh_token!;
    }
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    const digests: string[] =
      anchorDoc().erasures[g.grant.grant_id].token_digests;
    expect(digests).toHaveLength(MAX_ANCHORED_TOKEN_DIGESTS);
    expect(digests).toContain(hashToken(rt)); // the newest token is kept
    const recovery = recover([g.grant.grant_id]);
    const id = answer(recovery, g.grant.grant_id).erasure!.instruction_id;
    answer(recovery, g.grant.grant_id, {
      report: "completed",
      instruction_id: id,
      reported_at: clock().toISOString(),
    });
    expect(anchorDoc().erasures[g.grant.grant_id].token_digests).toEqual([]);
  });

  it("records the first return of an orphan answer after re-establishment", () => {
    const old = issued();
    const { db } = backup("b");
    const g = issued();
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    restoreFrom(db);
    lifecycle.reestablishHistory({
      dispositions: { [old.grant.grant_id]: "keep" },
      actionId: "re",
    });
    expect(store.lifecycle.getOrphanFirstReturn(g.grant.grant_id)).toBeNull();
    advance(H);
    expect(answer(g.access_token, g.grant.grant_id).held_data).toBe("erase");
    const first = store.lifecycle.getOrphanFirstReturn(g.grant.grant_id);
    expect(first).toBe(clock().toISOString());
    advance(H);
    answer(g.access_token, g.grant.grant_id);
    expect(store.lifecycle.getOrphanFirstReturn(g.grant.grant_id)).toBe(first);
  });

  it("derives evidence with the injected clock", () => {
    const g = issued("continuous", {
      expires_at: new Date(clockMs + H).toISOString(),
    });
    lifecycle.requestErasureForOwner({
      subjectId: OWNER,
      grantId: g.grant.grant_id,
      advance: true,
      actionId: "a",
      inScope: all,
    });
    advance(2 * H);
    answer(g.access_token, g.grant.grant_id);
    expect(
      store.anchorEvidence(clock()).erasures[g.grant.grant_id],
    ).toMatchObject({ read_state: "expired", ended_at: g.grant.expires_at });
  });
});

describe("review round 4 — newest-64 digests across token kinds (T2)", () => {
  it("keeps a recovery token issued after more than 64 data tokens, and a lost grant still answers erase to it", async () => {
    const { MAX_ANCHORED_TOKEN_DIGESTS } = await import("./store.js");
    const old = issued();
    const { db } = backup("b");
    const g = issued();
    let rt = g.refresh_token!;
    let at = g.access_token;
    for (let i = 0; i < 100; i++) {
      advance(1000);
      const r = tokens.refresh({ refreshToken: rt });
      if (!r.ok) throw new Error(r.failure.message);
      rt = r.issued.refresh_token!;
      at = r.issued.access_token;
    }
    ownerEnd(
      "revoke",
      { [g.grant.grant_id]: "delete" },
      { grantIds: [g.grant.grant_id] },
    );
    advance(1000);
    const rec = recover([g.grant.grant_id]);
    const digests: string[] = JSON.parse(
      readFileSync(`${dbPath}.history-anchor.json`, "utf8"),
    ).erasures[g.grant.grant_id].token_digests;
    expect(digests).toHaveLength(MAX_ANCHORED_TOKEN_DIGESTS);
    expect(digests).toContain(hashToken(rec));
    expect(digests).toContain(hashToken(rt));
    expect(digests).toContain(hashToken(at));
    expect(digests).not.toContain(hashToken(g.access_token));
    restoreFrom(db);
    expect(answer(rec, g.grant.grant_id).held_data).toBe("erase");
    lifecycle.reestablishHistory({
      dispositions: { [old.grant.grant_id]: "keep" },
      actionId: "re",
    });
    // Recovery tokens are disabled at re-establishment; the newest data
    // token still receives the orphan answer.
    expect(answer(at, g.grant.grant_id).held_data).toBe("erase");
    expect(
      call({ grant_id: g.grant.grant_id, token: g.access_token }).status,
    ).toBe(401);
  });
});

/**
 * Authorization privacy boundary evidence (spec-core §6 L1212-L1241; §9 AS
 * items 52, 54, 55, 57). The entry points, protected-state variants, timing
 * method and limits are recorded in `pdpp-auth-privacy.md` next to this file
 * (AS item 55).
 *
 * One fixed request R is sent under five protected-owner-state variants:
 *
 *   S0  matched owner refusal: everything eligible; the owner declines.
 *   S1  private declaration acceptance: no declaration accepted for the source.
 *   S2  temporal capability: the stream declares no consent_time_field, but R
 *       carries a time_range.
 *   S3  view availability: the view R names is not defined.
 *   S4  instance eligibility: R's required stream has no eligible instance.
 *
 * Observables compared across variants: status, header set and values,
 * response JSON shape and byte length, the client callback (redirect URI),
 * session (transaction) behaviour, and processing-time distribution.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const OWNER = "user_abc123";
const CLIENT = "music_recommendations";
const REDIRECT = "https://app.example.com/callback";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const CHALLENGE = computeS256Challenge(
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
);

type Variant = "S0" | "S1" | "S2" | "S3" | "S4";
const VARIANTS: Variant[] = ["S0", "S1", "S2", "S3", "S4"];

function declarationFor(variant: Variant): DeclarationSnapshot | null {
  if (variant === "S1") return null;
  return {
    source_id: SOURCE_ID,
    source_kind: "connector",
    version: "v1",
    digest: "d".repeat(64),
    streams: [
      {
        name: "plays",
        fields: ["id", "track", "played_at"],
        required_fields: ["id"],
        primary_key: ["id"],
        ...(variant !== "S2" && {
          consent_time_field: "played_at",
          schema: {
            properties: { played_at: { type: "string", format: "date-time" } },
          },
        }),
      },
    ],
    ...(variant !== "S3" && {
      views: [{ name: "summary", fields: ["track"] }],
    }),
  };
}

/** The one request R, identical in every variant. */
const REQUEST = {
  client_id: CLIENT,
  redirect_uri: REDIRECT,
  state: "st-1",
  code_challenge: CHALLENGE,
  code_challenge_method: "S256",
  client_display: { name: "Concert Finder" },
  authorization_details: [
    {
      type: PDPP_DATA_ACCESS_TYPE,
      source: { id: SOURCE_ID },
      purpose_code: "https://pdpp.dev/purpose/personalization",
      access_mode: "single_use",
      streams: [
        {
          name: "plays",
          necessity: "required",
          view: "summary",
          time_range: { since: "2026-01-01T00:00:00Z" },
        },
      ],
    },
  ],
};

interface Harness {
  app: Hono;
  store: PdppAuthStore;
  tokens: PdppTokenService;
  sessions: AuthorizationSessionStore;
  ownerToken: string;
  close(): void;
}

function harness(variant: Variant): Harness {
  const dir = mkdtempSync(join(tmpdir(), `pdpp-privacy-${variant}-`));
  const store = openPdppAuthStore(join(dir, "auth.db"));
  const tokens = new PdppTokenService(store);
  const sessions = new AuthorizationSessionStore();
  const declaration = declarationFor(variant);
  const app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger: pino({ level: "silent" }),
      store,
      tokens,
      sessions,
      resolveDeclaration: (id) => (id === SOURCE_ID ? declaration : null),
      inventoryFor: () => ({
        eligibleFor: () => (variant === "S4" ? [] : ["inst-1"]),
      }),
      currentSubjectId: (c: Context) => {
        const h = c.req.header("authorization");
        if (!h) return null;
        const ctx = tokens.resolveToken(h.slice(7));
        return ctx.active && ctx.tokenKind === "owner" ? OWNER : null;
      },
      registeredClient: (id) =>
        id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
    }),
  );
  const ownerToken = tokens.issueOwnerToken({
    subjectId: OWNER,
    sourceId: SOURCE_ID,
  }).access_token;
  return {
    app,
    store,
    tokens,
    sessions,
    ownerToken,
    close() {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Everything a client-side observer could see of one response. */
async function observe(response: Response) {
  const text = await response.text();
  const headers = [...response.headers.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  );
  let shape: unknown = null;
  try {
    shape = shapeOf(JSON.parse(text));
  } catch {
    shape = "non-json";
  }
  return { status: response.status, headers, bytes: text.length, shape, text };
}

/** Keys and value types, with unpredictable values reduced to their type. */
function shapeOf(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(shapeOf);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, shapeOf(v)]),
    );
  return typeof value;
}

function post(h: Harness, path: string, body: unknown, token?: string) {
  return h.app.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token && { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });
}

let harnesses: Partial<Record<Variant, Harness>>;
beforeEach(() => {
  harnesses = Object.fromEntries(VARIANTS.map((v) => [v, harness(v)]));
});
afterEach(() => {
  for (const h of Object.values(harnesses)) h?.close();
});

describe("AS item 54 — pre-authentication observables", () => {
  it("are identical across protected-state variants at /authorize", async () => {
    const seen = await Promise.all(
      VARIANTS.map(async (v) =>
        observe(await post(harnesses[v]!, "/pdpp/v1/authorize", REQUEST)),
      ),
    );
    for (const o of seen) {
      expect(o.status).toBe(401);
      expect(o).toEqual(seen[0]);
    }
    for (const v of VARIANTS)
      expect(harnesses[v]!.store.listGrantsForSubject(OWNER)).toEqual([]);
  });

  it("are identical for a client-token caller (a client cannot authenticate the owner)", async () => {
    const seen = await Promise.all(
      VARIANTS.map(async (v) =>
        observe(
          await post(
            harnesses[v]!,
            "/pdpp/v1/authorize",
            REQUEST,
            "pdpp_at_client",
          ),
        ),
      ),
    );
    for (const o of seen) expect(o).toEqual(seen[0]);
  });
});

describe("AS items 52, 57 — differential case at the authenticated entry point", () => {
  it("opens an indistinguishable session for every variant", async () => {
    const seen = await Promise.all(
      VARIANTS.map(async (v) =>
        observe(
          await post(
            harnesses[v]!,
            "/pdpp/v1/authorize",
            REQUEST,
            harnesses[v]!.ownerToken,
          ),
        ),
      ),
    );
    for (const o of seen) {
      expect(o.status).toBe(201);
      // session_id and expires_at are unpredictable transaction values
      // (L1238 permits them to differ); shape, size and headers may not.
      expect({ ...o, text: undefined }).toEqual({
        ...seen[0],
        text: undefined,
      });
    }
  });

  it("ends every variant with the same client-visible access_denied as the owner's refusal", async () => {
    const callbacks = [];
    for (const v of VARIANTS) {
      const h = harnesses[v]!;
      const created = await post(
        h,
        "/pdpp/v1/authorize",
        REQUEST,
        h.ownerToken,
      );
      const { session_id } = (await created.json()) as { session_id: string };
      // Authenticated review: the owner may be told why (L1228). S0 is
      // eligible and the owner reviews it normally; S1-S4 are refused here.
      const reviewed = await h.app.request(
        `/pdpp/v1/authorize/${session_id}/review`,
        { headers: { authorization: `Bearer ${h.ownerToken}` } },
      );
      expect(reviewed.status).toBe(v === "S0" ? 200 : 403);
      // Every variant concludes with the owner declining (S0) or the
      // consent surface declining for the owner (S1-S4).
      const denied = await post(
        h,
        `/pdpp/v1/authorize/${session_id}/deny`,
        {},
        h.ownerToken,
      );
      callbacks.push(await observe(denied));
      // Transaction behaviour: the session is decided, nothing is issued.
      expect(h.sessions.get(session_id)?.status).toBe("denied");
      expect(h.store.listGrantsForSubject(OWNER)).toEqual([]);
    }
    for (const o of callbacks) {
      expect(o.status).toBe(200);
      // The client callback, byte for byte: no diagnostic, no parameter
      // beyond error and state (L1230).
      expect(o.text).toBe(callbacks[0].text);
      expect(o.headers).toEqual(callbacks[0].headers);
    }
    expect(JSON.parse(callbacks[0].text)).toEqual({
      redirect_uri: `${REDIRECT}?error=access_denied&state=st-1`,
    });
  });

  it("never lets an ineligible variant approve", async () => {
    for (const v of VARIANTS.filter((x) => x !== "S0")) {
      const h = harnesses[v]!;
      const created = await post(
        h,
        "/pdpp/v1/authorize",
        REQUEST,
        h.ownerToken,
      );
      const { session_id } = (await created.json()) as { session_id: string };
      const approved = await post(
        h,
        `/pdpp/v1/authorize/${session_id}/approve`,
        { review_digest: "0".repeat(64) },
        h.ownerToken,
      );
      expect(approved.status).toBe(403);
      expect(h.store.listGrantsForSubject(OWNER)).toEqual([]);
    }
  });
});

/**
 * AS item 54 timing. Method (recorded in pdpp-auth-privacy.md): N requests
 * per variant, interleaved round-robin after a warm-up, timed in-process
 * around `app.request`. Statistic: median per variant; spread: median
 * absolute deviation (MAD). The check passes when every variant's median is
 * within max(FLOOR_MS, RELATIVE × S0 median, 3 × pooled MAD) of S0's. When
 * the run is too noisy to resolve that (pooled MAD above RELATIVE × S0
 * median, i.e. the spread alone exceeds the bound we claim) the test is
 * skipped and reports UNVERIFIED rather than passing (AS item 55).
 */
const SAMPLES = 150;
const WARMUP = 30;
const FLOOR_MS = 0.02;
const RELATIVE = 0.15;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[mid]!
    : (sorted[mid - 1]! + sorted[mid]!) / 2;
}
function mad(values: number[]): number {
  const m = median(values);
  return median(values.map((v) => Math.abs(v - m)));
}

async function timeVariants(
  run: (v: Variant) => Promise<Response>,
): Promise<Record<Variant, number[]>> {
  const samples = Object.fromEntries(
    VARIANTS.map((v) => [v, [] as number[]]),
  ) as Record<Variant, number[]>;
  for (let i = 0; i < WARMUP + SAMPLES; i++) {
    for (const v of VARIANTS) {
      const started = performance.now();
      const res = await run(v);
      await res.arrayBuffer();
      const elapsed = performance.now() - started;
      if (i >= WARMUP) samples[v].push(elapsed);
    }
  }
  return samples;
}

function judge(
  label: string,
  samples: Record<Variant, number[]>,
  skip: (note: string) => void,
) {
  const medians = Object.fromEntries(
    VARIANTS.map((v) => [v, median(samples[v])]),
  ) as Record<Variant, number>;
  const pooled = median(VARIANTS.map((v) => mad(samples[v])));
  const relative = RELATIVE * medians.S0;
  const bound = Math.max(FLOOR_MS, relative, 3 * pooled);
  const summary = VARIANTS.map((v) => `${v}=${medians[v].toFixed(3)}ms`).join(
    " ",
  );
  // Printed so a run's figures can be copied into the evidence record.
  console.info(
    `[AS-54 timing] ${label}: ${summary} pooledMAD=${pooled.toFixed(3)}ms bound=${bound.toFixed(3)}ms`,
  );
  if (pooled > Math.max(FLOOR_MS, relative)) {
    skip(`UNVERIFIED: ${label} too noisy (pooled MAD ${pooled.toFixed(3)} ms)`);
    return;
  }
  for (const v of VARIANTS)
    expect(
      Math.abs(medians[v] - medians.S0),
      `${label} ${v}`,
    ).toBeLessThanOrEqual(bound);
}

describe("AS item 54 — processing time does not reveal protected state", () => {
  it("at /authorize (authenticated entry point)", async (ctx) => {
    const samples = await timeVariants((v) =>
      post(
        harnesses[v]!,
        "/pdpp/v1/authorize",
        REQUEST,
        harnesses[v]!.ownerToken,
      ),
    );
    judge("authorize", samples, (note) => ctx.skip(note));
  }, 60_000);

  it("at /authorize before owner authentication", async (ctx) => {
    const samples = await timeVariants((v) =>
      post(harnesses[v]!, "/pdpp/v1/authorize", REQUEST),
    );
    judge("authorize-unauthenticated", samples, (note) => ctx.skip(note));
  }, 60_000);

  it("at /deny (client-visible eligibility denial after review)", async (ctx) => {
    const samples = await timeVariants(async (v) => {
      const h = harnesses[v]!;
      const created = await post(
        h,
        "/pdpp/v1/authorize",
        REQUEST,
        h.ownerToken,
      );
      const { session_id } = (await created.json()) as { session_id: string };
      return post(h, `/pdpp/v1/authorize/${session_id}/deny`, {}, h.ownerToken);
    });
    judge("authorize+deny", samples, (note) => ctx.skip(note));
  }, 120_000);
});

/**
 * Stream and field names are data, not property names.
 *
 * The PDPP spec gives no character grammar for stream or field names, only
 * that stream names are unique and that no wildcard survives resolution. A
 * source may therefore declare a stream called `__proto__`, `constructor` or
 * `hasOwnProperty`, or one holding a line break or an astral character. The
 * owner's narrowing reaches the server twice: as `field[...]`, `since[...]`
 * and `until[...]` query keys on review, and as JSON objects on approval.
 * These tests run both routes with those names and check three things: the
 * narrowing the owner chose is the narrowing issued, `Object.prototype` is
 * untouched, and nothing throws.
 *
 * A name that is not well-formed Unicode cannot be carried faithfully: the URL
 * parser and a UTF-8 store both replace a lone surrogate with U+FFFD, so the
 * name the owner chose and the name the server reads would differ. That input
 * is refused with a typed 400 instead.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE_V02,
  PdppTokenService,
  type DeclarationSnapshot,
  type InstanceInventory,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_names";
const REDIRECT = "https://app.example.com/callback";
const CHALLENGE = computeS256Challenge(
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
);
const INSTANCE = "account_example";
const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const SINCE = "2025-06-01T00:00:00Z";

const NAMES = [
  "__proto__",
  "constructor",
  "toString",
  "hasOwnProperty",
  "line\nbreak",
  "carriage\rreturn",
  "line\u2028separator",
  "paragraph\u2029separator",
  "astral \u{1F600} \u{1D4B3}",
  "bracket]name[x]",
];

function snapshotDeclaring(name: string): DeclarationSnapshot {
  return {
    source_id: "https://data.example.com/names",
    source_kind: "provider_native",
    version: "2026-09-01",
    digest: "e".repeat(64),
    streams: [
      {
        name,
        fields: ["date", "amount"],
        required_fields: [],
        consent_time_field: "date",
        schema: {
          type: "object",
          properties: { date: { type: "string", format: "date-time" } },
        },
        primary_key: ["date"],
      },
      {
        name: "profile",
        fields: ["id", "display_name"],
        required_fields: [],
        primary_key: ["id"],
      },
    ],
  };
}

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let sessions: AuthorizationSessionStore;
let app: Hono;
let declared: DeclarationSnapshot;

const inventory: InstanceInventory = { eligibleFor: () => [INSTANCE] };

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-names-routes-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
  declared = snapshotDeclaring("transactions");
  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      protocolProfile: "candidate-0.1.0",
      logger,
      store,
      tokens,
      sessions,
      resolveDeclaration: (sourceId) =>
        sourceId === declared.source_id ? declared : null,
      inventoryFor: () => inventory,
      currentSubjectId: (_c: Context) => OWNER,
      registeredClient: (clientId) =>
        clientId === "budget_example"
          ? { client_id: clientId, redirect_uris: [REDIRECT] }
          : null,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function ownerToken(): string {
  return tokens.issueOwnerToken({ subjectId: OWNER, instanceIds: [INSTANCE] })
    .access_token;
}

function authorizeBody(name: string) {
  return {
    client_id: "budget_example",
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_display: { name: "Budget Example" },
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE_V02,
        source: { id: declared.source_id },
        purpose_code: "https://apps.example.com/purposes/budget",
        access_mode: "continuous",
        streams: [
          {
            name,
            necessity: "optional",
            fields: ["date", "amount"],
            time_range: YEAR,
          },
          { name: "profile", necessity: "optional", fields: ["id"] },
        ],
      },
    ],
  };
}

async function open(name: string) {
  declared = snapshotDeclaring(name);
  const token = ownerToken();
  const created = await app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(authorizeBody(name)),
  });
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };
  return { sessionId: session_id, token };
}

function reviewOf(sessionId: string, token: string, query: string) {
  return app.request(`/pdpp/v1/authorize/${sessionId}/review${query}`, {
    headers: { authorization: `Bearer ${token}` },
  });
}

function approveOf(sessionId: string, token: string, body: unknown) {
  return app.request(`/pdpp/v1/authorize/${sessionId}/approve`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
}

type ReviewJson = {
  review: {
    review_digest: string;
    data: {
      streams: Array<{
        name: string;
        fields: string[];
        time_constraint?: { since?: string; until?: string };
      }>;
    };
  };
};

/** `{ [name]: value }` makes an own property even for `__proto__`, as JSON.parse does. */
function own<T>(name: string, value: T): Record<string, T> {
  return { [name]: value };
}

describe.each(NAMES)("a stream named %j", (name) => {
  it("keeps the ceiling through review and approval when only another stream was narrowed", async () => {
    const { sessionId, token } = await open(name);
    const query = new URLSearchParams([
      ["field[profile]", "id"],
      ["instance[profile]", INSTANCE],
    ]).toString();
    const reviewed = await reviewOf(sessionId, token, `?${query}`);
    expect(reviewed.status).toBe(200);
    const body = (await reviewed.json()) as ReviewJson;
    const stream = body.review.data.streams.find((s) => s.name === name);
    expect(stream?.fields).toEqual(["date", "amount"]);

    const approved = await approveOf(sessionId, token, {
      review_digest: body.review.review_digest,
      owner_choices: { fields: { profile: ["id"] } },
      instance_choices: { profile: [INSTANCE] },
    });
    expect(approved.status).toBe(200);
    const { grant_id } = (await approved.json()) as { grant_id: string };
    const issued = store
      .getGrant(grant_id)
      ?.grant.streams.find((s) => s.name === name);
    expect(issued?.fields).toEqual(["date", "amount"]);
  });

  it("issues exactly the narrowing the owner chose for that name", async () => {
    const { sessionId, token } = await open(name);
    const query = new URLSearchParams([
      [`field[${name}]`, "date"],
      [`since[${name}]`, SINCE],
    ]).toString();
    const reviewed = await reviewOf(sessionId, token, `?${query}`);
    expect(reviewed.status).toBe(200);
    const body = (await reviewed.json()) as ReviewJson;
    const shown = body.review.data.streams.find((s) => s.name === name);
    expect(shown?.fields).toEqual(["date"]);
    expect(shown?.time_constraint?.since).toBe(SINCE);

    const approved = await approveOf(sessionId, token, {
      review_digest: body.review.review_digest,
      owner_choices: {
        fields: own(name, ["date"]),
        time_ranges: own(name, { since: SINCE }),
      },
    });
    expect(approved.status).toBe(200);
    const { grant_id } = (await approved.json()) as { grant_id: string };
    const issued = store
      .getGrant(grant_id)
      ?.grant.streams.find((s) => s.name === name);
    expect(issued?.fields).toEqual(["date"]);
    expect(issued?.time_constraint?.since).toBe(SINCE);
  });

  it("leaves Object.prototype unchanged", async () => {
    const before = Object.getOwnPropertyNames(Object.prototype).sort();
    const { sessionId, token } = await open(name);
    const query = new URLSearchParams([
      [`field[${name}]`, "date"],
      [`since[${name}]`, SINCE],
      [`until[${name}]`, YEAR.until],
      [`instance[${name}]`, INSTANCE],
      [`decline[${name}]`, "1"],
    ]).toString();
    await reviewOf(sessionId, token, `?${query}`);
    expect(Object.getOwnPropertyNames(Object.prototype).sort()).toEqual(before);
    for (const key of ["date", "since", "until", "fields"]) {
      expect(Reflect.get({}, key)).toBeUndefined();
    }
  });
});

describe("a name that is not well-formed Unicode is refused", () => {
  // A lone surrogate cannot be written in UTF-8, so on the wire it is an
  // invalid percent-encoded sequence. The URL parser turns that into U+FFFD
  // without any error, which would change the name the owner chose.
  it.each(["approve", "decline", "field", "instance", "since", "until"])(
    "in a %s query key",
    async (axis) => {
      const { sessionId, token } = await open("transactions");
      const response = await reviewOf(
        sessionId,
        token,
        `?${axis}[%ED%A0%80]=2025-06-01T00:00:00Z`,
      );
      expect(response.status).toBe(400);
      expect(((await response.json()) as { error: string }).error).toBe(
        "invalid_owner_choices",
      );
    },
  );

  it("in a query value", async () => {
    const { sessionId, token } = await open("transactions");
    const response = await reviewOf(
      sessionId,
      token,
      "?field[transactions]=%ED%A0%80",
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toBe(
      "invalid_owner_choices",
    );
  });

  it("but a real U+FFFD, validly encoded, is an ordinary name", async () => {
    const { sessionId, token } = await open("transactions");
    const response = await reviewOf(
      sessionId,
      token,
      "?field[a%EF%BF%BDb]=date",
    );
    expect(response.status).toBe(200);
  });

  it.each([
    [
      "owner_choices fields key",
      { owner_choices: { fields: { "\ud800": ["date"] } } },
    ],
    [
      "owner_choices fields value",
      { owner_choices: { fields: { profile: ["\udc00"] } } },
    ],
    [
      "owner_choices time_ranges key",
      { owner_choices: { time_ranges: { "a\ud800": { since: SINCE } } } },
    ],
    [
      "owner_choices declined_streams",
      { owner_choices: { declined_streams: ["x\ud83d"] } },
    ],
    ["instance_choices key", { instance_choices: { "\ud800": [INSTANCE] } }],
    ["instance_choices value", { instance_choices: { profile: ["\udc00"] } }],
  ])("in an approval body: %s", async (_label, extra) => {
    const { sessionId, token } = await open("transactions");
    const reviewed = (await (
      await reviewOf(sessionId, token, "")
    ).json()) as ReviewJson;
    const approved = await approveOf(sessionId, token, {
      review_digest: reviewed.review.review_digest,
      ...extra,
    });
    expect(approved.status).toBe(400);
    expect(((await approved.json()) as { error: string }).error).toBe(
      "invalid_owner_choices",
    );
  });

  it("but a valid surrogate pair in an approval body is data", async () => {
    const name = "pair \u{1F600}";
    const { sessionId, token } = await open(name);
    const reviewed = (await (
      await reviewOf(sessionId, token, "")
    ).json()) as ReviewJson;
    const approved = await approveOf(sessionId, token, {
      review_digest: reviewed.review.review_digest,
    });
    expect(approved.status).toBe(200);
  });

  it("when a request names a stream with one", async () => {
    declared = snapshotDeclaring("transactions");
    const response = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ownerToken()}`,
      },
      body: JSON.stringify(authorizeBody("lone \ud800 surrogate")),
    });
    expect(response.status).toBe(400);
  });
});

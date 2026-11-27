/**
 * Vana Account's "Apps with access to your data" screen:
 *
 * 1. GET /pdpp/v1/owner/sources, authenticated by the Web3Signed owner proof
 *    (the mechanism /pdpp/v1/owner/token takes; uri /pdpp/v1/owner/sources,
 *    aud = PS origin), lists [{ source_id, display_name? }] for sources that
 *    hold this owner's data or grants, and nothing of another subject.
 * 2. Each GET /pdpp/v1/grants entry carries client.client_display.name, the
 *    AS-resolved display name, omitted when the AS resolved none.
 */

import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
  type DeclarationSnapshot,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const ORIGIN = "https://ps.example";
const owner = createTestWallet(0);
const other = createTestWallet(1);
const SUBJECT = owner.address.toLowerCase();
const SPOTIFY = "https://registry.pdpp.dev/connectors/spotify";
const OURA = "https://registry.pdpp.dev/connectors/oura";
const GITHUB = "https://registry.pdpp.dev/connectors/github";
const FOREIGN = "https://registry.pdpp.dev/connectors/foreign";

function declaration(id: string, name?: string): DeclarationSnapshot {
  return {
    source_id: id,
    source_kind: "connector",
    version: "v1",
    digest: "d".repeat(64),
    ...(name && { display: { name } }),
    streams: [
      { name: "s", fields: ["id"], required_fields: ["id"], primary_key: ["id"] },
    ],
  };
}
const declarations: Record<string, DeclarationSnapshot> = {
  [SPOTIFY]: declaration(SPOTIFY, "Spotify"),
  [OURA]: declaration(OURA, "Oura"),
  [GITHUB]: declaration(GITHUB),
};

function grant(
  id: string,
  sourceId: string,
  clientId: string,
  clientDisplay?: { name: string },
): Grant {
  return {
    version: "0.1.0",
    grant_id: id,
    issued_at: new Date().toISOString(),
    subject: { id: "pws_x" },
    client: {
      client_id: clientId,
      ...(clientDisplay && { client_display: clientDisplay }),
    },
    source: { kind: "connector", id: sourceId },
    source_declaration: { version: "v1" },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    streams: [
      { name: "s", instance_ids: ["i"], fields: ["id"], required_fields: ["id"] },
    ],
  } as Grant;
}

let store: PdppAuthStore;
let tokens: PdppTokenService;
let app: Hono;

beforeEach(() => {
  store = openPdppAuthStore(":memory:");
  tokens = new PdppTokenService(store);
  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger: pino({ level: "silent" }),
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      issuer: ORIGIN,
      resolveDeclaration: (id) => declarations[id] ?? null,
      inventoryFor: () => ({ eligibleFor: () => ["i"] }),
      currentSubjectId: () => SUBJECT,
      ownerSubjectId: () => SUBJECT,
      ownerDataSources: (subject) => (subject === SUBJECT ? [OURA] : [FOREIGN]),
      ownerAuth: { serverOrigin: ORIGIN, serverOwner: owner.address },
    }),
  );
  store.insertGrant({
    grant: grant("g1", SPOTIFY, "concert_finder", { name: "Concert Finder" }),
    subjectId: SUBJECT,
    reviewDigest: "r",
  });
  store.insertGrant({
    grant: grant("g2", GITHUB, "plain_app"),
    subjectId: SUBJECT,
    reviewDigest: "r",
    consentEvidence: {
      displayed: { client: { client_id: "plain_app", display_name: "plain_app" } },
    },
  });
  store.insertGrant({
    grant: grant("g3", FOREIGN, "x", { name: "X" }),
    subjectId: "0xsomeoneelse",
    reviewDigest: "r",
  });
});

afterEach(() => store.close());

async function signed(wallet = owner, uri = "/pdpp/v1/owner/sources") {
  return buildWeb3SignedHeader({ wallet, aud: ORIGIN, method: "GET", uri });
}

describe("GET /pdpp/v1/owner/sources", () => {
  it("lists the owner's data and grant sources with display names, nothing of others", async () => {
    const res = await app.request("/pdpp/v1/owner/sources", {
      headers: { authorization: await signed() },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      sources: [
        { source_id: GITHUB },
        { source_id: OURA, display_name: "Oura" },
        { source_id: SPOTIFY, display_name: "Spotify" },
      ],
    });
  });

  it("answers 401 without a proof, with another wallet's proof, or a proof for another uri", async () => {
    expect((await app.request("/pdpp/v1/owner/sources")).status).toBe(401);
    for (const header of [
      await signed(other),
      await signed(owner, "/pdpp/v1/owner/token"),
    ]) {
      const res = await app.request("/pdpp/v1/owner/sources", {
        headers: { authorization: header },
      });
      expect(res.status).toBe(401);
      expect(await res.text()).not.toContain(FOREIGN);
    }
  });

  it("does not accept a PDPP owner token in place of the wallet proof", async () => {
    const token = tokens.issueOwnerToken({ subjectId: SUBJECT, sourceId: SPOTIFY })
      .access_token;
    const res = await app.request("/pdpp/v1/owner/sources", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(401);
  });
});

describe("GET /pdpp/v1/grants client display name", () => {
  it("carries client.client_display.name when the AS resolved one, and omits it otherwise", async () => {
    const token = tokens.issueOwnerToken({ subjectId: SUBJECT }).access_token;
    const res = await app.request("/pdpp/v1/grants", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const { grants } = (await res.json()) as {
      grants: Array<{ grant_id: string; client: Record<string, unknown> }>;
    };
    const byId = Object.fromEntries(grants.map((g) => [g.grant_id, g.client]));
    expect(byId.g1).toEqual({
      client_id: "concert_finder",
      client_display: { name: "Concert Finder" },
    });
    // The review's client_id fallback is not a display name.
    expect(byId.g2).toEqual({ client_id: "plain_app" });
    expect(byId.g3).toBeUndefined();
  });
});

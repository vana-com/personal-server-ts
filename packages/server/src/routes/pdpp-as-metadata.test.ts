/**
 * Oracle for the PDPP AS metadata document.
 *
 * Anchor: PR vana-com/pdpp#1 spec-core.md §8 — "An AS supporting this revision
 * MUST advertise `https://pdpp.dev/data-access/0.2` in
 * `authorization_details_types_supported` in its OAuth authorization-server
 * metadata. A client MUST establish support for this type before requesting
 * it."
 *
 * Without this document a conformant v0.2 client cannot establish support, so
 * it must not request the type — meaning the whole v0.2 implementation is
 * unreachable to a client that follows the spec. That is why this is in scope
 * rather than deferred.
 *
 * It lives under `/pdpp/v1/` rather than at the origin root on purpose. The
 * root `/.well-known/oauth-authorization-server` already describes the MCP
 * OAuth authorization server, which is a different authority over different
 * tokens; §8 warns against a second grant authority and merging the two
 * documents would present them as one.
 */

import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import pino from "pino";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_API_VERSION,
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pdppAsMetadataHandler, pdppAuthRoutes } from "./pdpp-auth.js";

function harness() {
  const dir = mkdtempSync(join(tmpdir(), "pdpp-md-"));
  const store = openPdppAuthStore(join(dir, "auth.db"));
  const app = new Hono();
  // Mirrors how src/app.ts mounts these: the router under /pdpp/v1, and the
  // RFC 8414 location at the root, which lies outside that prefix.
  app.get(
    "/.well-known/oauth-authorization-server/pdpp/v1",
    pdppAsMetadataHandler("https://ps.example.com"),
  );
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger: pino({ level: "silent" }),
      store,
      tokens: new PdppTokenService(store),
      sessions: new AuthorizationSessionStore(),
      resolveDeclaration: () => null,
      inventoryFor: () => ({ eligibleFor: () => [] }),
      currentSubjectId: () => null,
      issuer: "https://ps.example.com",
    }),
  );
  return {
    app,
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

describe("PDPP AS metadata", () => {
  it("advertises both PDPP authorization-details types", async () => {
    const { app, cleanup } = harness();
    try {
      const response = await app.request(
        "/pdpp/v1/.well-known/oauth-authorization-server",
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        authorization_details_types_supported: string[];
      };
      // Both, because both are implemented and each resolves under its own
      // revision. Advertising only v0.2 would strand existing v0.1 clients.
      expect(body.authorization_details_types_supported).toEqual([
        PDPP_DATA_ACCESS_TYPE,
        PDPP_DATA_ACCESS_TYPE_V02,
      ]);
    } finally {
      cleanup();
    }
  });

  it("names the endpoints a client needs to reach the flow", async () => {
    const { app, cleanup } = harness();
    try {
      const response = await app.request(
        "/pdpp/v1/.well-known/oauth-authorization-server",
      );
      const body = (await response.json()) as Record<string, unknown>;
      expect(body.issuer).toBe("https://ps.example.com");
      expect(body.token_endpoint).toBe("https://ps.example.com/pdpp/v1/token");
      expect(body.introspection_endpoint).toBe(
        "https://ps.example.com/pdpp/v1/introspect",
      );
      expect(body.revocation_endpoint).toBe(
        "https://ps.example.com/pdpp/v1/revoke",
      );
      expect(body.pdpp_api_version).toBe(PDPP_API_VERSION);
    } finally {
      cleanup();
    }
  });

  it("advertises PKCE S256, which the flow requires", async () => {
    const { app, cleanup } = harness();
    try {
      const response = await app.request(
        "/pdpp/v1/.well-known/oauth-authorization-server",
      );
      const body = (await response.json()) as Record<string, unknown>;
      expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    } finally {
      cleanup();
    }
  });

  it("is reachable without a credential", async () => {
    // Authorization-server metadata is public by definition: a client has to
    // read it *before* it can obtain any credential.
    const { app, cleanup } = harness();
    try {
      const response = await app.request(
        "/pdpp/v1/.well-known/oauth-authorization-server",
      );
      expect(response.status).toBe(200);
    } finally {
      cleanup();
    }
  });
});

/**
 * RFC 8414 §3: for an issuer with a path component, the metadata document is
 * published at `/.well-known/oauth-authorization-server` with the issuer's path
 * APPENDED — host-first, not path-first. This AS mounts under `/pdpp/v1` and
 * published only the path-first (OIDC-style) form, so no client following RFC
 * 8414 could discover it: the two locations are different URLs and only one is
 * the registered well-known.
 *
 * Serving the RFC 8414 location does not reintroduce the collision the
 * path-first placement was chosen to avoid. The MCP authorization server owns
 * the BARE `/.well-known/oauth-authorization-server`; this one carries the
 * `/pdpp/v1` suffix, so the two documents stay distinct and no reader can
 * mistake one authority for the other.
 */
describe("PDPP AS metadata: RFC 8414 discovery location", () => {
  it("publishes the document at the RFC 8414 path-aware well-known URL", async () => {
    const { app, cleanup } = harness();
    try {
      const res = await app.request(
        "/.well-known/oauth-authorization-server/pdpp/v1",
      );
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.issuer).toBe("https://ps.example.com");
      expect(body.introspection_endpoint).toBe(
        "https://ps.example.com/pdpp/v1/introspect",
      );
    } finally {
      cleanup();
    }
  });

  it("keeps serving the existing path-first location", async () => {
    const { app, cleanup } = harness();
    try {
      const res = await app.request(
        "/pdpp/v1/.well-known/oauth-authorization-server",
      );
      expect(res.status).toBe(200);
      expect((await res.json()).issuer).toBe("https://ps.example.com");
    } finally {
      cleanup();
    }
  });

  it("does not claim the bare well-known URL the MCP AS owns", async () => {
    const { app, cleanup } = harness();
    try {
      const res = await app.request("/.well-known/oauth-authorization-server");
      expect(res.status).toBe(404);
    } finally {
      cleanup();
    }
  });
});

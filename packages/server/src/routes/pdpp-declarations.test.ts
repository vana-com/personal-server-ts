/**
 * Oracles for the declaration submission surface (§5 declaration acceptance).
 *
 * The AS has always had a real validator, but it ran only at construction:
 * `buildDeclarationRegistry` parsed `config.pdpp.declarationPaths` once at
 * boot and pinned the survivors. Offering a candidate therefore required a
 * server restart, which is a different measurement from "what does the AS
 * refuse at an acceptance surface" — and it is the reason the conformance
 * suite's declaration-validity cases could not run against this target.
 *
 * These tests drive the acceptance surface directly: accept, refuse with the
 * spec error shape, update the live registry in place, and survive a restart.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  openDeclarationRegistry,
  type MutableDeclarationRegistry,
} from "../pdpp/declaration-registry.js";
import { pdppDeclarationRoutes } from "./pdpp-declarations.js";

const logger = pino({ level: "silent" });
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const OPERATOR_TOKEN = "operator-secret";

/** A minimal normative SourceDeclaration this deployment would accept. */
function declarationDocument(overrides: Record<string, unknown> = {}) {
  return {
    protocol_version: "0.1.0",
    source: { kind: "connector", id: SOURCE_ID },
    declaration_version: "1.0.0",
    publisher: { id: "https://registry.pdpp.dev/publishers/pdp-connect" },
    display: { name: "Spotify" },
    streams: [
      {
        name: "top_artists",
        semantics: "mutable_state",
        schema: {
          $schema: "https://json-schema.org/draft/2020-12/schema",
          type: "object",
          properties: { id: { type: "string" }, name: { type: "string" } },
          required: ["id"],
        },
        primary_key: ["id"],
        cursor_field: "id",
      },
    ],
    extensions: {},
    ...overrides,
  };
}

let dir: string;
let registry: MutableDeclarationRegistry;
let app: Hono;

function buildApp(reg: MutableDeclarationRegistry) {
  const next = new Hono();
  next.route(
    "/pdpp",
    pdppDeclarationRoutes({
      logger,
      registry: reg,
      // The connector gate this PS applies: it serves Spotify, not Netflix.
      supportedConnectors: ["spotify"],
      operatorToken: OPERATOR_TOKEN,
    }),
  );
  return next;
}

function submit(
  document: unknown,
  { token = OPERATOR_TOKEN }: { token?: string | null } = {},
) {
  return app.request("/pdpp/declarations", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token === null ? {} : { authorization: `Bearer ${token}` }),
    },
    body: typeof document === "string" ? document : JSON.stringify(document),
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-decl-"));
  registry = openDeclarationRegistry({
    path: join(dir, "declarations.db"),
    supportedConnectors: ["spotify"],
    logger,
  });
  app = buildApp(registry);
});

afterEach(() => {
  registry.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("POST /pdpp/declarations — acceptance", () => {
  it("accepts a valid declaration and reports what it retained", async () => {
    const res = await submit(declarationDocument());

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.source_id).toBe(SOURCE_ID);
    expect(body.version).toBe("1.0.0");
    // Clause 5.8-4's retention half: the caller can see what is now held.
    expect(body.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(body.streams).toEqual(["top_artists"]);
  });

  it("makes the accepted declaration resolvable without a restart", async () => {
    expect(registry.resolve(SOURCE_ID)).toBeNull();

    await submit(declarationDocument());

    // The live lookup the AS consumes, updated in place — this is the whole
    // point: the suite's positive control and its negative case must land in
    // the SAME server lifetime to be comparing anything.
    expect(registry.resolve(SOURCE_ID)?.source_id).toBe(SOURCE_ID);
  });

  it("is idempotent for an identical resubmission", async () => {
    const first = await submit(declarationDocument());
    const second = await submit(declarationDocument());

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect((await second.json()).digest).toBe((await first.json()).digest);
  });

  it("refuses different content under an accepted source and version", async () => {
    await submit(declarationDocument());
    const res = await submit(
      declarationDocument({
        streams: [
          {
            ...declarationDocument().streams[0],
            name: "different_stream",
          },
        ],
      }),
    );

    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("declaration_equivocation");
    expect(registry.resolve(SOURCE_ID)?.streams[0]?.name).toBe("top_artists");
    expect(registry.documentFor(SOURCE_ID)).toBe(
      JSON.stringify(declarationDocument()),
    );
  });

  it("replaces the retained declaration when a newer version is submitted", async () => {
    await submit(declarationDocument());
    const res = await submit(
      declarationDocument({ declaration_version: "2.0.0" }),
    );

    expect(res.status).toBe(200);
    expect((await res.json()).version).toBe("2.0.0");
    expect(registry.resolve(SOURCE_ID)?.version).toBe("2.0.0");

    const equivocation = await submit(
      declarationDocument({
        streams: [
          {
            ...declarationDocument().streams[0],
            name: "different_stream",
          },
        ],
      }),
    );
    expect(equivocation.status).toBe(400);
    expect((await equivocation.json()).error).toBe("declaration_equivocation");
    expect(registry.resolve(SOURCE_ID)?.version).toBe("2.0.0");
  });
});

describe("POST /pdpp/declarations — refusal carries the spec error shape", () => {
  it("refuses a malformed document as invalid_document", async () => {
    const res = await submit("{not json");

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_document");
    expect(typeof body.error_description).toBe("string");
  });

  it("refuses a declaration whose streams are empty as invalid_document", async () => {
    const res = await submit(declarationDocument({ streams: [] }));

    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_document");
  });

  it("refuses a source this deployment does not serve as untrusted_source", async () => {
    const res = await submit(
      declarationDocument({
        source: {
          kind: "connector",
          id: "https://registry.pdpp.dev/connectors/netflix",
        },
      }),
    );

    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("untrusted_source");
  });

  it("leaves nothing retained when it refuses", async () => {
    await submit(declarationDocument({ streams: [] }));

    expect(registry.resolve(SOURCE_ID)).toBeNull();
  });

  it("does not let a refusal displace an already-retained declaration", async () => {
    await submit(declarationDocument());
    await submit(declarationDocument({ streams: [] }));

    // The good one must survive a bad resubmission under the same key, or a
    // single malformed POST would silently disarm a working grant surface.
    expect(registry.resolve(SOURCE_ID)?.version).toBe("1.0.0");
  });
});

describe("POST /pdpp/declarations — this must not be client-reachable", () => {
  // Clause 5.8-1: a client that can submit its own declaration can declare
  // itself authority over any source, which defeats the trust policy the
  // whole §5 acceptance model rests on.
  it("refuses a request with no operator credential", async () => {
    const res = await submit(declarationDocument(), { token: null });

    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("unauthorized");
    expect(registry.resolve(SOURCE_ID)).toBeNull();
  });

  it("refuses a request bearing the wrong credential", async () => {
    const res = await submit(declarationDocument(), { token: "not-it" });

    expect(res.status).toBe(401);
    expect(registry.resolve(SOURCE_ID)).toBeNull();
  });
});

describe("retention survives a restart", () => {
  it("resolves a previously accepted declaration from a fresh registry", async () => {
    await submit(declarationDocument());
    const path = join(dir, "declarations.db");
    registry.close();

    const reopened = openDeclarationRegistry({
      path,
      supportedConnectors: ["spotify"],
      logger,
    });
    try {
      expect(reopened.resolve(SOURCE_ID)?.version).toBe("1.0.0");
      // And the exact retained bytes, not a re-serialization: the digest a
      // producer's envelope is checked against must be over what we stored.
      expect(reopened.documentFor(SOURCE_ID)).toBe(
        JSON.stringify(declarationDocument()),
      );
    } finally {
      reopened.close();
    }
    // Reassigned so afterEach closes something valid.
    registry = openDeclarationRegistry({
      path,
      supportedConnectors: ["spotify"],
      logger,
    });
  });
});

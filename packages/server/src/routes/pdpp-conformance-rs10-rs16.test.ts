/**
 * Conformance regressions for two suite failures against this Resource Server.
 *
 * RS-10 — "Unknown parameters return 400" (spec-core.md §8). An unrecognized
 * query parameter was silently ignored and the request served 200. That is not
 * a cosmetic laxness: a client that misspells `limit` as `limt`, or sends a
 * parameter this version does not implement, gets a successful response that
 * quietly does something other than what it asked. Silent acceptance of an
 * unknown constraint is indistinguishable from applying it.
 *
 * RS-16 — "Answer 401 with a WWW-Authenticate challenge naming the metadata
 * URL" (spec-core.md §8, RFC 9728 §5.1). The 401 and challenge existed, but
 * `resource_metadata` was the hardcoded relative string
 * `/.well-known/oauth-protected-resource`. RFC 9728 §5.1 requires a URI the
 * client can dereference; a relative path is only resolvable if the client
 * already knows the origin, which is precisely what an unauthenticated client
 * bootstrapping discovery does not reliably have (proxies, path prefixes, a
 * `pdpp_core_query_base` that is not `/v1`). It must be absolute.
 */

import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

const ORIGIN = "http://ps.example.test";
const AUTH = { Authorization: "Bearer t" };

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

const ownerAuth: PdppAuthorizationService = {
  async resolveToken() {
    return {
      active: true,
      tokenKind: "owner" as const,
      subjectId: "sub",
      instanceIds: ["i1"],
    };
  },
};

function app() {
  const a = new Hono();
  const store = createMemoryRecordStore();
  a.route(
    "/v1",
    pdppRecordsRoutes({
      store,
      auth: ownerAuth,
      declarations,
      instancesForSubject: () => ["i1"],
    }),
  );
  a.route(
    "/v1/blobs",
    pdppBlobsRoutes({
      store,
      auth: ownerAuth,
      declarations,
      instancesForSubject: () => ["i1"],
    }),
  );
  return a;
}

/** Hono needs an absolute URL to populate a real origin on the request. */
function url(path: string): string {
  return `${ORIGIN}${path}`;
}

describe("RS-10: unknown query parameters are rejected", () => {
  it("rejects an unknown parameter on list records", async () => {
    const res = await app().request(url("/v1/streams/s/records?bogus=1"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_request");
    // The offending parameter is named, so a client can correct it rather
    // than bisecting its own query string.
    expect(body.error.param).toBe("bogus");
  });

  it("names a plausible typo rather than silently ignoring it", async () => {
    // The case that motivates the requirement: `limt` looks like `limit`.
    // Silently serving a default page size would look like success.
    const res = await app().request(url("/v1/streams/s/records?limt=5"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.param).toBe("limt");
  });

  it("still accepts every parameter this version implements", async () => {
    const res = await app().request(
      url("/v1/streams/s/records?limit=5&order=asc&fields=id"),
      { headers: AUTH },
    );
    expect(res.status).toBe(200);
  });

  it("rejects an unknown parameter on get record", async () => {
    const res = await app().request(url("/v1/streams/s/records/k1?bogus=1"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error.param).toBe("bogus");
  });

  it("rejects an unknown parameter on stream metadata", async () => {
    const res = await app().request(url("/v1/streams/s?bogus=1"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
  });

  it("rejects an unknown parameter on list streams", async () => {
    const res = await app().request(url("/v1/streams?bogus=1"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
  });
});

describe("RS-16: the 401 challenge names a dereferenceable metadata URL", () => {
  /**
   * An absolute URL, because an unauthenticated client bootstrapping
   * discovery from a failed read cannot be assumed to know the origin.
   */
  const EXPECTED = `${ORIGIN}/.well-known/oauth-protected-resource`;

  it("challenges an unauthenticated record read with an absolute URL", async () => {
    const res = await app().request(url("/v1/streams/s/records"));
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate") ?? "";
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain(`resource_metadata="${EXPECTED}"`);
  });

  it("challenges an unauthenticated stream listing with an absolute URL", async () => {
    const res = await app().request(url("/v1/streams"));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${EXPECTED}"`,
    );
  });

  it("challenges an unauthenticated blob fetch with an absolute URL", async () => {
    const res = await app().request(url("/v1/blobs/b1"));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${EXPECTED}"`,
    );
  });

  it("derives the origin from the request rather than hardcoding one", async () => {
    // A server reachable on a second origin (tunnel, proxy, alternate host)
    // must point the client at the origin it actually used, or discovery
    // sends it somewhere it cannot reach.
    const other = "https://other.example.test";
    const res = await app().request(`${other}/v1/streams/s/records`);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${other}/.well-known/oauth-protected-resource"`,
    );
  });
});

/**
 * RS-16, the part the first fix missed.
 *
 * The challenge was built ONLY on the missing-token branch of `authenticate`.
 * A token that was PRESENT and rejected by `resolveToken` -- expired, revoked,
 * unknown -- returned a bare 401 with no `WWW-Authenticate` at all. That is
 * precisely the client §8's challenge exists to help: one holding a stale
 * token, which needs the pointer back to the metadata document in order to
 * re-authorize. A client with no token at all was already the easy case.
 *
 * Reported against 8ba3265 with two curls to the same endpoint: no header at
 * all returned the challenge, `Authorization: Bearer <invalid>` did not.
 *
 * The challenge is now attached wherever a 401 is emitted rather than at each
 * call site, so a future 401 path cannot forget it.
 */
describe("RS-16: a REJECTED token is challenged, not just a missing one", () => {
  const EXPECTED = `${ORIGIN}/.well-known/oauth-protected-resource`;

  /** Resolves every token as inactive — the stale-token client. */
  const rejectingAuth: PdppAuthorizationService = {
    async resolveToken() {
      return {
        active: false,
        tokenKind: "client" as const,
        subjectId: "",
        inactiveReason: "expired" as const,
      };
    },
  };

  function rejectingApp() {
    const a = new Hono();
    const store = createMemoryRecordStore();
    a.route(
      "/v1",
      pdppRecordsRoutes({
        store,
        auth: rejectingAuth,
        declarations,
        instancesForSubject: () => ["i1"],
      }),
    );
    a.route(
      "/v1/blobs",
      pdppBlobsRoutes({
        store,
        auth: rejectingAuth,
        declarations,
        instancesForSubject: () => ["i1"],
      }),
    );
    return a;
  }

  it("challenges a rejected token on a record read", async () => {
    const res = await rejectingApp().request(url("/v1/streams/s/records"), {
      headers: { Authorization: "Bearer stale-token" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${EXPECTED}"`,
    );
  });

  it("challenges a rejected token on a stream listing", async () => {
    const res = await rejectingApp().request(url("/v1/streams"), {
      headers: { Authorization: "Bearer stale-token" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${EXPECTED}"`,
    );
  });

  it("challenges a rejected token on a blob fetch", async () => {
    const res = await rejectingApp().request(url("/v1/blobs/b1"), {
      headers: { Authorization: "Bearer stale-token" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain(
      `resource_metadata="${EXPECTED}"`,
    );
  });

  it("does not attach a challenge to a non-401 error", async () => {
    // A 400 is not an authentication failure; adding a challenge there would
    // tell a client to re-authorize when its credentials were never the
    // problem.
    const res = await app().request(url("/v1/streams/s/records?bogus=1"), {
      headers: AUTH,
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("www-authenticate")).toBeNull();
  });
});

/**
 * PDPP reads must appear in the owner's access feed.
 *
 * Scope 6 requires Vana product preservation: PDPP reads map into the EXISTING
 * owner access-feed contract. An independent ledger-path review found the
 * bearer RS route had no `accessLogWriter` dependency at all, so a client
 * reading under a PDPP grant left no trace — adopting PDPP would have made an
 * owner's access history strictly less complete than the legacy
 * `/v1/data/{scope}` path it replaces. That is the one regression a data
 * portability product cannot ship.
 *
 * These cases pin four properties:
 *   - a served client read is recorded, with the grant and client identified;
 *   - a DENIED read is recorded too (the legacy middleware only fires on 2xx,
 *     so an owner could not otherwise see that an app tried something it was
 *     not granted);
 *   - an OWNER read is not recorded, because reading your own store is not a
 *     third-party access event and the legacy feed does not record it either;
 *   - a failing feed write never breaks the read it is describing.
 */

import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes, type PdppAccessLogPort } from "./pdpp-records.js";

const INSTANCE = "i1";
const AUTH = { Authorization: "Bearer t" };

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
  {
    name: "ungranted",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

const GRANT = {
  version: "0.1.0",
  grant_id: "grt_abc",
  issued_at: "2026-01-01T00:00:00.000Z",
  subject: { id: "sub" },
  client: { client_id: "app_public_id" },
  source: { kind: "connector" as const, id: "src" },
  source_declaration: { version: "v1" },
  purpose_code: "p",
  access_mode: "continuous" as const,
  streams: [{ name: "s", instance_ids: [INSTANCE], fields: ["id", "name"] }],
};

function auth(kind: "client" | "owner"): PdppAuthorizationService {
  return {
    async resolveToken() {
      return kind === "client"
        ? {
            active: true,
            tokenKind: "client" as const,
            subjectId: "sub",
            grant: GRANT as never,
            clientId: "app_public_id",
          }
        : {
            active: true,
            tokenKind: "owner" as const,
            subjectId: "sub",
            instanceIds: [INSTANCE],
          };
    },
  };
}

function app(kind: "client" | "owner", accessLog?: PdppAccessLogPort) {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    [
      {
        instance: INSTANCE,
        stream: "s",
        key: "r1",
        data: { id: "r1", name: "n1" },
        emitted_at: "2026-05-01T00:00:00.000Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );

  const a = new Hono();
  a.route(
    "/v1",
    pdppRecordsRoutes({
      store,
      auth: auth(kind),
      declarations,
      instancesForSubject: () => [INSTANCE],
      ...(accessLog ? { accessLog } : {}),
    }),
  );
  return a;
}

function recorder() {
  const entries: Parameters<PdppAccessLogPort["record"]>[0][] = [];
  const port: PdppAccessLogPort = {
    record: async (entry) => {
      entries.push(entry);
    },
  };
  return { entries, port };
}

describe("PDPP reads populate the owner access feed", () => {
  it("records a served client read with the grant and client", async () => {
    const { entries, port } = recorder();
    const res = await app("client", port).request("/v1/streams/s/records", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);

    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      clientId: "app_public_id",
      grantId: "grt_abc",
      operation: "read",
      outcome: "completed",
      stream: "s",
    });
    // The Request-Id correlates the feed entry to the response.
    expect(entries[0].requestId).toBe(res.headers.get("request-id"));
  });

  it("records a DENIED read, which the legacy 2xx-only middleware cannot", async () => {
    const { entries, port } = recorder();
    const res = await app("client", port).request(
      "/v1/streams/ungranted/records",
      { headers: AUTH },
    );
    expect(res.status).toBe(403);

    // An owner must be able to see that an app tried to read something it was
    // never granted.
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      grantId: "grt_abc",
      outcome: "denied",
      stream: "ungranted",
    });
  });

  it("records a single-record read", async () => {
    const { entries, port } = recorder();
    const res = await app("client", port).request("/v1/streams/s/records/r1", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    expect(entries).toHaveLength(1);
    expect(entries[0].outcome).toBe("completed");
  });

  it("does NOT record an owner read", async () => {
    const { entries, port } = recorder();
    const res = await app("owner", port).request("/v1/streams/s/records", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    // Reading your own store is not a third-party access event, and the
    // legacy feed does not record it either.
    expect(entries).toHaveLength(0);
  });

  it("serves the read even when the feed write fails", async () => {
    const failing: PdppAccessLogPort = {
      record: vi.fn().mockRejectedValue(new Error("feed unavailable")),
    };
    const res = await app("client", failing).request("/v1/streams/s/records", {
      headers: AUTH,
    });
    // A logging outage must not turn a legitimate read into an error, nor a
    // denial into a 500.
    expect(res.status).toBe(200);
    expect(failing.record).toHaveBeenCalled();
  });

  it("still serves reads when no feed is configured", async () => {
    const res = await app("client").request("/v1/streams/s/records", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
  });
});

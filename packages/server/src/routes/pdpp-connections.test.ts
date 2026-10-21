import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { pdppConnectionRoutes } from "./pdpp-connections.js";

const OWNER = "0xowner";
const SOURCE = "https://registry.pdpp.dev/connectors/spotify";
const A = "spotify:0xowner";
const B = "conn_123e4567-e89b-42d3-a456-426614174000";

describe("PDPP connection routes", () => {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  const routeDeps: Parameters<typeof pdppConnectionRoutes>[0] = {
    store,
    auth: {
      async resolveToken(token) {
        if (token !== "owner-token") return { active: false as const };
        return {
          active: true as const,
          tokenKind: "owner" as const,
          subjectId: OWNER,
          sourceId: SOURCE,
          instanceIds: [A],
        };
      },
    } satisfies PdppAuthorizationService,
    ownerSubjectId: OWNER,
    connectionMethods: new Map([[SOURCE, ["spotify"]]]),
    configuredMethods: new Map(),
    canonicalSourceIds: new Set([SOURCE]),
    sourceIds: new Set([SOURCE]),
  };
  const app = pdppConnectionRoutes(routeDeps);
  const candidateApp = pdppConnectionRoutes({
    ...routeDeps,
    protocolProfile: "candidate-0.1.0",
  });

  afterEach(() => {
    db.exec(
      "DELETE FROM pdpp_records; DELETE FROM pdpp_record_changes; DELETE FROM pdpp_instance_binding;",
    );
  });

  it("registers, lists, and updates a same-method account without changing its id", async () => {
    for (const id of [A, B]) {
      const response = await app.request(
        `/pdpp/connections/${encodeURIComponent(id)}`,
        {
          method: "PUT",
          headers: {
            authorization: "Bearer owner-token",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            source_id: SOURCE,
            method_id: "spotify",
            label: id === A ? "Personal" : "Work",
          }),
        },
      );
      expect(response.status).toBe(200);
    }
    const listed = await app.request(
      `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}`,
      {
        headers: { authorization: "Bearer owner-token" },
      },
    );
    expect((await listed.json()).connections).toHaveLength(2);

    const changed = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "PUT",
        headers: {
          authorization: "Bearer owner-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: SOURCE,
          method_id: "spotify",
          label: "Work account",
        }),
      },
    );
    expect((await changed.json()).label).toBe("Work account");
    expect(
      store
        .listConnections(SOURCE)
        .map((item) => item.instance)
        .sort(),
    ).toEqual([A, B].sort());
  });

  it("advertises the versioned connection capability", async () => {
    const response = await app.request("/pdpp/capabilities");
    expect((await response.json()).capabilities).toContain("connections_v1");
  });

  it("refuses a foreign owner, an unknown method, and a reused deleted id", async () => {
    const unauthenticated = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "PUT",
        headers: {
          authorization: "Bearer wrong",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: SOURCE,
          method_id: "spotify",
          label: "Work",
        }),
      },
    );
    expect(unauthenticated.status).toBe(401);

    const wrongMethod = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "PUT",
        headers: {
          authorization: "Bearer owner-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: SOURCE,
          method_id: "other",
          label: "Work",
        }),
      },
    );
    expect(wrongMethod.status).toBe(409);

    await app.request(`/pdpp/connections/${encodeURIComponent(B)}`, {
      method: "PUT",
      headers: {
        authorization: "Bearer owner-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: SOURCE,
        method_id: "spotify",
        label: "Work",
      }),
    });
    const deleted = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "DELETE",
        headers: { authorization: "Bearer owner-token" },
      },
    );
    expect(deleted.status).toBe(200);
    const replay = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "PUT",
        headers: {
          authorization: "Bearer owner-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: SOURCE,
          method_id: "spotify",
          label: "Work",
        }),
      },
    );
    expect(replay.status).toBe(409);
    expect((await replay.json()).error.code).toBe("connection_deleted");
  });
  it.each([undefined, "Bearer stale"])(
    "challenges rejected connection bearer %s under the candidate profile only",
    async (authorization) => {
      const path = `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}`;
      const headers = authorization ? { authorization } : undefined;
      const current = await app.request(path, { headers });
      expect(current.status).toBe(401);
      expect(current.headers.get("WWW-Authenticate")).toBeNull();

      const candidate = await candidateApp.request(path, { headers });
      expect(candidate.status).toBe(401);
      expect(await candidate.json()).toEqual(await current.json());
      expect(candidate.headers.get("WWW-Authenticate")).toBe(
        'Bearer error="invalid_token", resource_metadata="http://localhost/.well-known/oauth-protected-resource"',
      );
    },
  );
});

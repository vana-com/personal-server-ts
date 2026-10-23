import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { pdppConnectionRoutes } from "./pdpp-connections.js";

const OWNER = "0xowner";
const SOURCE = "https://registry.pdpp.dev/connectors/spotify";
const A = "spotify:0xowner";
const B = "conn_123e4567-e89b-42d3-a456-426614174000";
const C = "conn_223e4567-e89b-42d3-a456-426614174001";

describe("PDPP connection routes", () => {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  const app = pdppConnectionRoutes({
    store,
    auth: {
      async resolveToken(token) {
        // Source-wide owner: no instance ceiling.
        if (token === "source-owner-token") {
          return {
            active: true as const,
            tokenKind: "owner" as const,
            subjectId: OWNER,
            sourceId: SOURCE,
          };
        }
        // Owner whose instance list is empty: covers no instances.
        if (token === "empty-owner-token") {
          return {
            active: true as const,
            tokenKind: "owner" as const,
            subjectId: OWNER,
            sourceId: SOURCE,
            instanceIds: [],
          };
        }
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
  });

  afterEach(() => {
    db.exec(
      "DELETE FROM pdpp_records; DELETE FROM pdpp_record_changes; DELETE FROM pdpp_instance_binding;",
    );
  });

  function put(id: string, token: string, label = "Work") {
    return app.request(`/pdpp/connections/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        source_id: SOURCE,
        method_id: "spotify",
        label,
      }),
    });
  }

  function remove(id: string, token: string) {
    return app.request(`/pdpp/connections/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
  }

  function listed(token: string) {
    return app.request(
      `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}`,
      {
        headers: { authorization: `Bearer ${token}` },
      },
    );
  }

  function ingestPrivateRecord(instance: string) {
    const result = store.ingestBatch(
      [
        {
          instance,
          stream: "playlists",
          key: "p1",
          data: { id: "p1", private: instance },
          emitted_at: "2026-10-23T00:00:00Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "spotify", generation: 1 },
    );
    expect(result.accepted).toBe(1);
  }

  it("registers, lists, and updates a same-method account without changing its id", async () => {
    for (const id of [A, B]) {
      const response = await app.request(
        `/pdpp/connections/${encodeURIComponent(id)}`,
        {
          method: "PUT",
          headers: {
            authorization: "Bearer source-owner-token",
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
    const listedAll = await app.request(
      `/pdpp/connections?source_id=${encodeURIComponent(SOURCE)}`,
      {
        headers: { authorization: "Bearer source-owner-token" },
      },
    );
    expect((await listedAll.json()).connections).toHaveLength(2);

    const changed = await app.request(
      `/pdpp/connections/${encodeURIComponent(B)}`,
      {
        method: "PUT",
        headers: {
          authorization: "Bearer source-owner-token",
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
          authorization: "Bearer source-owner-token",
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

    await put(B, "source-owner-token");
    const deleted = await remove(B, "source-owner-token");
    expect(deleted.status).toBe(200);
    const replay = await put(B, "source-owner-token");
    expect(replay.status).toBe(409);
    expect((await replay.json()).error.code).toBe("connection_deleted");
  });

  it("lists only the connections an instance-scoped owner covers", async () => {
    expect((await put(A, "source-owner-token", "Personal")).status).toBe(200);
    expect((await put(B, "source-owner-token")).status).toBe(200);

    const response = await listed("owner-token");
    expect(response.status).toBe(200);
    expect(
      (await response.json()).connections.map(
        (connection: { connection_id: string }) => connection.connection_id,
      ),
    ).toEqual([A]);
  });

  it("refuses to relabel or create a connection outside the owner token's instances", async () => {
    expect((await put(B, "source-owner-token", "Work")).status).toBe(200);

    const relabel = await put(B, "owner-token", "Hijacked");
    expect(relabel.status).toBe(403);
    const created = await put(C, "owner-token", "New");
    expect(created.status).toBe(403);

    expect(store.getInstanceBinding(B).label).toBe("Work");
    expect(
      store.listConnections(SOURCE).map((item) => item.instance),
    ).not.toContain(C);
  });

  it("refuses to delete another connection, leaving its records and binding intact", async () => {
    expect((await put(B, "source-owner-token")).status).toBe(200);
    ingestPrivateRecord(B);
    expect(store.getRecord(B, "playlists", "p1")).toBeDefined();

    const response = await remove(B, "owner-token");
    expect(response.status).toBe(403);

    expect(store.getRecord(B, "playlists", "p1")).toBeDefined();
    expect(store.getInstanceBinding(B).deletedAt).toBeNull();
  });

  it("still lets an instance-scoped owner relabel and delete its own connection", async () => {
    expect((await put(A, "source-owner-token", "Personal")).status).toBe(200);

    const relabel = await put(A, "owner-token", "Still mine");
    expect(relabel.status).toBe(200);
    expect(store.getInstanceBinding(A).label).toBe("Still mine");

    const deleted = await remove(A, "owner-token");
    expect(deleted.status).toBe(200);
    expect(store.getInstanceBinding(A).deletedAt).not.toBeNull();
  });

  it("treats an empty instance list as covering no connections, never the whole source", async () => {
    expect((await put(B, "source-owner-token")).status).toBe(200);
    ingestPrivateRecord(B);

    const response = await listed("empty-owner-token");
    expect((await response.json()).connections).toEqual([]);
    expect((await put(C, "empty-owner-token")).status).toBe(403);
    expect((await remove(B, "empty-owner-token")).status).toBe(403);

    expect(store.getRecord(B, "playlists", "p1")).toBeDefined();
    expect(store.getInstanceBinding(B).deletedAt).toBeNull();
  });
});

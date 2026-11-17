/**
 * `GET /v1/streams/:stream/records` on a device that only synced.
 *
 * The streams a connector has on this Personal Server are what the device's
 * synced local state holds, not what the host names at boot. A device that
 * synced a connection from another device, and wrote nothing itself, serves
 * that connection's streams.
 *
 * Real: the Lite runtime and its owner auth, the database composition and
 * its apply of a remote registry's heads and tombstones.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  closeStores,
  CONNECTOR,
  liteGet,
  liteRuntime,
  syncedStore,
} from "./test-support/records-route.js";

afterEach(closeStores);

const POSTS = ["p1", "p2", "p3"].map((id) => ({ id, caption: `c ${id}` }));
const path = (stream: string) =>
  `/v1/streams/${stream}/records?source=${CONNECTOR}`;

async function recordsOf(
  local: Awaited<ReturnType<typeof syncedStore>>["local"],
  stream: string,
) {
  const response = await liteGet(await liteRuntime(local), path(stream));
  const body = await response.json();
  return { status: response.status, body };
}

describe("the records route on a device that synced a connection", () => {
  it("serves a stream no manifest of this boot declared", async () => {
    const { local } = await syncedStore(async (remote) => {
      await remote.head("posts", POSTS);
    });
    const { status, body } = await recordsOf(local, "posts");
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.data.map((row: { id: string }) => row.id)).toEqual([
      "p1",
      "p2",
      "p3",
    ]);
  });

  it("serves a synced stream that holds no records as an empty list", async () => {
    const { local } = await syncedStore(async (remote) => {
      await remote.head("posts", POSTS);
      await remote.head("drafts", []);
    });
    const { status, body } = await recordsOf(local, "drafts");
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body).toMatchObject({ data: [], has_more: false });
  });

  it("answers 404 for a stream the connection never synced", async () => {
    const { local } = await syncedStore(async (remote) => {
      await remote.head("posts", POSTS);
    });
    const { status } = await recordsOf(local, "never_synced");
    expect(status).toBe(404);
  });

  it("stops serving a stream once its delete is applied", async () => {
    const { local, remote } = await syncedStore(async (r) => {
      await r.head("posts", POSTS);
      await r.head("drafts", [{ id: "d1" }]);
    });
    expect((await recordsOf(local, "drafts")).status).toBe(200);
    const scope = (await remote.registry.listStreamRows(CONNECTOR)).find((e) =>
      e.scope.endsWith("drafts"),
    )!.scope;
    remote.reads.set(scope, {
      found: true,
      version: 2,
      dataHash: remote.hashes.tombstoneData,
      metadataHash: remote.hashes.tombstoneMetadata,
      deleted: true,
    });
    await local.apply();
    expect((await recordsOf(local, "drafts")).status).toBe(404);
    expect((await recordsOf(local, "posts")).status).toBe(200);
  });

  it("stops serving every stream once its connection is deleted", async () => {
    const { local, remote } = await syncedStore(async (r) => {
      await r.head("posts", POSTS);
    });
    expect(await local.declarations.streamsOf(CONNECTOR)).toEqual(["posts"]);
    remote.setControl(1, true);
    await local.apply();
    expect(await local.declarations.streamsOf(CONNECTOR)).toEqual([]);
    expect((await recordsOf(local, "posts")).status).toBe(404);
  });

  // Applying a delete floors the connection's streams too, so these two
  // states reach the read only from a connection whose streams are not yet
  // floored (a delete in flight, a legacy import): its streams are not served.
  // A load of a newer head after a delete keeps the delete floor until it
  // completes; its applied parts are what a reader may show meanwhile.
  describe("a stream reloading after its delete", () => {
    const reloading = async (partial: {
      version: number;
      generation: number;
    }) => {
      const { local, remote, db } = await syncedStore(async (r) => {
        await r.head("posts", POSTS);
      });
      const scope = (await remote.registry.listStreamRows(CONNECTOR))[0]!.scope;
      remote.reads.set(scope, {
        found: true,
        version: 2,
        dataHash: remote.hashes.tombstoneData,
        metadataHash: remote.hashes.tombstoneMetadata,
        deleted: true,
      });
      await local.apply();
      expect(await local.declarations.streamsOf(CONNECTOR)).toEqual([]);
      await db.batch([
        {
          sql: `INSERT INTO stream_partial (connection_id, stream, version,
                  generation, data_hash, head_blob, observed_at, parts_applied,
                  parts_total, records_total)
                VALUES ('pdpp.${CONNECTOR}~', 'posts', ?, ?, '0x00', 'blob', 1, 1, 3, 3)`,
          params: [partial.version, partial.generation],
        },
      ]);
      return local;
    };

    it("is named once parts of a newer head of the connection's generation are applied", async () => {
      const local = await reloading({ version: 3, generation: 1 });
      expect(await local.declarations.streamsOf(CONNECTOR)).toEqual(["posts"]);
    });

    it.each([
      ["a head no newer than the delete", { version: 2, generation: 1 }],
      ["another generation of the connection", { version: 3, generation: 2 }],
    ])("is not named for parts of %s", async (_name, partial) => {
      const local = await reloading(partial);
      expect(await local.declarations.streamsOf(CONNECTOR)).toEqual([]);
    });
  });

  it.each([
    ["control state is not active", "control_state = 'deleted'"],
    ["row is marked deleted", "deleted_at = 1"],
  ])("names no stream of a connection whose %s", async (_name, set) => {
    const { local, db } = await syncedStore(async (r) => {
      await r.head("posts", POSTS);
    });
    await db.batch([{ sql: `UPDATE connections SET ${set}`, params: [] }]);
    expect(await local.declarations.streamsOf(CONNECTOR)).toEqual([]);
  });
});

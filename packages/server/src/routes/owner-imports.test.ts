import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { readDataFile } from "../storage/hierarchy.js";
import { dataRoutes } from "./data.js";
import { DATA_INGEST_MAX_SIZE } from "../middleware/body-limit.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";

const owner = "0x1111111111111111111111111111111111111111";
const operation = "a".repeat(64);
const scope = "github.events";

describe("owner import acceptance across restart", () => {
  let root: string;
  let index: ReturnType<typeof createIndexManager>;
  let app: ReturnType<typeof dataRoutes>;
  const dataWritten = vi.fn();

  function openServer() {
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
    app = dataRoutes({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "owner-import-test",
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      onDataWritten: dataWritten,
    });
  }

  function write(method: "PUT" | "POST", body: unknown) {
    return app.request(
      method === "PUT" ? `/${scope}/imports/${operation}` : `/${scope}`,
      {
        method,
        headers: {
          Authorization: "Bearer owner-import-test",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
    );
  }

  beforeEach(async () => {
    dataWritten.mockClear();
    root = await mkdtemp(join(tmpdir(), "owner-import-replay-"));
    openServer();
  });

  afterEach(async () => {
    index?.close();
    await rm(root, { recursive: true, force: true });
  });

  it("keeps separate ordinary POST writes even when their bodies match", async () => {
    expect((await write("POST", { value: "A" })).status).toBe(201);
    expect((await write("POST", { value: "A" })).status).toBe(201);
    expect(index.countByScope(scope)).toBe(2);
  });

  it("replays an accepted import without appending it after a newer write", async () => {
    const first = await write("PUT", { value: "A" });
    expect(first.status).toBe(201);
    const accepted = await first.json();
    expect(accepted.importReceipt).toMatchObject({ operation, scope });
    expect(index.countByScope(scope)).toBe(1);

    const newer = await write("POST", { value: "B" });
    expect(newer.status).toBe(201);
    const newerReceipt = await newer.json();
    index.close();
    openServer();

    const retry = await write("PUT", { value: "A" });
    expect(retry.status).toBe(200);
    const replay = await retry.json();
    expect(replay.importReceipt).toEqual(accepted.importReceipt);
    expect(replay.collectedAt).toBe(accepted.collectedAt);
    expect(dataWritten).toHaveBeenCalledTimes(2);
    expect(index.countByScope(scope)).toBe(2);
    expect(index.findLatestByScope(scope)?.collectedAt).toBe(
      newerReceipt.collectedAt,
    );
    const latest = await readDataFile(
      { dataDir: join(root, "data") },
      scope,
      newerReceipt.collectedAt,
    );
    expect(latest.data).toEqual({ value: "B" });
  });

  it("binds the operation to semantic JSON and refuses changed data", async () => {
    const first = await write("PUT", { value: "A", nested: { z: 1, a: 2 } });
    expect(first.status).toBe(201);
    const receipt = (await first.json()).importReceipt;
    const reordered = await write("PUT", {
      nested: { a: 2, z: 1 },
      value: "A",
    });
    expect(reordered.status).toBe(200);
    expect((await reordered.json()).importReceipt).toEqual(receipt);
    const changed = await write("PUT", { value: "B", nested: { z: 1, a: 2 } });
    expect(changed.status).toBe(409);
    expect((await changed.json()).error.errorCode).toBe("IMPORT_CONFLICT");
    expect(index.countByScope(scope)).toBe(1);
    expect(dataWritten).toHaveBeenCalledTimes(1);
  });

  it("keeps deleted operation identities across restart and permits an intentional new operation", async () => {
    const first = await write("PUT", { value: "A" });
    expect(first.status).toBe(201);
    const receipt = (await first.json()).importReceipt;
    const deletion = await app.request(`/${scope}`, {
      method: "DELETE",
      headers: { Authorization: "Bearer owner-import-test" },
    });
    expect(deletion.status).toBe(200);
    index.close();
    openServer();
    const replay = await write("PUT", { value: "A" });
    expect(replay.status).toBe(410);
    expect((await replay.json()).error.details.importReceipt).toEqual(receipt);
    expect((await write("PUT", { value: "B" })).status).toBe(409);
    expect(index.countByScope(scope)).toBe(0);
    const readd = await app.request(`/${scope}/imports/${"b".repeat(64)}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer owner-import-test",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ value: "A" }),
    });
    expect(readd.status).toBe(201);
    expect(index.countByScope(scope)).toBe(1);
  });

  it("refuses unsupported storage and invalid import combinations before creating data", async () => {
    const raw = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
    });
    const unsupported = dataRoutes({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
      dataStorage: { ...raw, kind: "custom", commitVersion: undefined },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "owner-import-test",
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
    });
    const refused = await unsupported.request(
      `/${scope}/imports/${operation}`,
      {
        method: "PUT",
        headers: {
          Authorization: "Bearer owner-import-test",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ value: "A" }),
      },
    );
    expect(refused.status).toBe(501);
    for (const body of [
      { $writtenBy: {} },
      { $lineage: {} },
      { lineage: {} },
      { $binary: true },
      [],
    ]) {
      expect((await write("PUT", body)).status).toBe(400);
    }
    for (const suffix of ["?supersede=legacy", "?lineage=true"]) {
      expect(
        (
          await app.request(`/${scope}/imports/${operation}${suffix}`, {
            method: "PUT",
            headers: {
              Authorization: "Bearer owner-import-test",
              "Content-Type": "application/json",
            },
            body: "{}",
          })
        ).status,
      ).toBe(400);
    }
    expect(
      (
        await app.request(`/${scope}/imports/${operation}`, {
          method: "PUT",
          headers: {
            Authorization: "Bearer owner-import-test",
            "Content-Type": "application/octet-stream",
          },
          body: "binary",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await app.request(`/${scope}`, {
          method: "PUT",
          headers: {
            Authorization: "Bearer owner-import-test",
            "Content-Type": "application/json",
          },
          body: "{}",
        })
      ).status,
    ).toBe(405);
    expect(index.countByScope(scope)).toBe(0);
  });

  it("authorizes the owner before returning operation binding details", async () => {
    expect((await write("PUT", { value: "A" })).status).toBe(201);
    const refused = await app.request(`/${scope}/imports/${operation}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer invalid-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ value: "B" }),
    });
    expect(refused.status).toBe(401);
    expect(index.countByScope(scope)).toBe(1);
  });

  it("applies the ingest body limit to the nested import route before publication", async () => {
    const response = await app.request(`/${scope}/imports/${operation}`, {
      method: "PUT",
      headers: {
        Authorization: "Bearer owner-import-test",
        "Content-Type": "application/json",
        // The declared length alone must be refused; no 512 MiB body is built.
        "Content-Length": String(DATA_INGEST_MAX_SIZE + 1),
      },
      body: JSON.stringify({ value: "x" }),
    });
    expect(response.status).toBe(413);
    expect(index.countByScope(scope)).toBe(0);
    expect(dataWritten).not.toHaveBeenCalled();
  });
});

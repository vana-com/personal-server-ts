import { describe, expect, it, vi } from "vitest";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

const headers = { Authorization: "Bearer owner" };
const auth = createFixtureAuthorizationService({
  owner: {
    active: true,
    tokenKind: "owner",
    subjectId: "fixture",
    instanceIds: ["fixture"],
  },
});
const declarations = createStreamDeclarationRegistry([]);
describe("storage mode refusals preserve HTTP errors", () => {
  it.each(["unknown", "switched"] as const)(
    "maps %s metadata refusals to 503 without reading legacy",
    async (mode) => {
      const store = createMemoryRecordStore();
      const list = vi.spyOn(store, "listStreams");
      const app = pdppRecordsRoutes({
        store,
        auth,
        declarations,
        accountStorageMode: { owner: "fixture", read: () => mode },
        instancesForSubject: () => ["fixture"],
      });
      const response = await app.request("/streams", { headers });
      expect(response.status).toBe(503);
      expect(list).not.toHaveBeenCalled();
    },
  );
  it("rejects an inactive token before consulting Account mode on record reads", async () => {
    const read = vi.fn(() => "unknown" as const);
    const app = pdppRecordsRoutes({
      store: createMemoryRecordStore(),
      auth,
      declarations,
      accountStorageMode: { owner: "fixture", read },
    });
    for (const path of [
      "/streams/items/records",
      "/streams/items/records/id",
    ]) {
      const response = await app.request(path, {
        headers: { Authorization: "Bearer invalid" },
      });
      expect(response.status).toBe(401);
    }
    expect(read).not.toHaveBeenCalled();
  });
  it("preserves a blob reader's account-mode refusal rather than answering 500", async () => {
    const app = pdppBlobsRoutes({
      store: createMemoryRecordStore(),
      auth,
      declarations,
      reads: () => {
        throw new PdppError("ACCOUNT_MODE_UNKNOWN", "Waiting for the account");
      },
    });
    expect((await app.request("/fixture", { headers })).status).toBe(503);
  });
});

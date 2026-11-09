/**
 * The refusal lives in the core write operations, not only in the server's
 * route layer: these requests go straight to the core dispatcher, with no
 * middleware in front, and the switch on.
 */
import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  STREAM_SYNC_CLIENT_HEADER,
  type PersonalServerDataApiDeps,
} from "./index.js";
import type { ScopeUploadRegistry } from "./scope-uploads.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const scope = "notes.entries";
const operation = "b".repeat(64);

function fixture(switchedOn: { value: boolean }) {
  const storage = createMemoryDataStorage();
  const commitVersion = vi.fn(async () => {
    throw new Error("a refused write must not reach storage");
  });
  const uploads = {
    maxBatchBytes: 1024,
    begin: vi.fn(async () => ({ uploadId: "u1", collectedAt: "t" })),
    append: vi.fn(async () => ({ seq: 0, items: 0, replay: false })),
    commit: vi.fn(async () => {
      throw new Error("a refused write must not commit");
    }),
    abort: vi.fn(async () => undefined),
  } as unknown as ScopeUploadRegistry;
  const deps: PersonalServerDataApiDeps = {
    storage: Object.assign(storage, { commitVersion }),
    scopeUploads: uploads,
    serverOwner: "0x1111111111111111111111111111111111111111",
    legacyWritesRefused: () => switchedOn.value,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
  };
  return { storage, commitVersion, uploads, deps };
}

const request = (
  method: string,
  path: string,
  headers: Record<string, string> = {},
) =>
  new Request(`https://ps.example${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: method === "GET" || method === "DELETE" ? undefined : "{}",
  });

const forged = { "x-vana-write-signature": "forged" };

describe("the core refuses legacy writes after owner authorization", () => {
  const importPath = `/${scope}/imports/${operation}`;
  const cases = [
    ["durable import", "PUT", importPath],
    ["durable import, trailing slash", "PUT", `${importPath}/`],
    ["durable import, doubled slash", "PUT", `${importPath}//`],
    ["upload begin", "POST", `/${scope}/uploads`],
    ["upload batch", "PUT", `/${scope}/uploads/u1/batches/0`],
    ["upload commit", "POST", `/${scope}/uploads/u1/commit`],
  ] as const;

  describe.each(cases)("%s", (_name, method, path) => {
    it.each([
      ["no header", {}],
      ["a forged write signature", forged],
    ])("answers 426 and touches nothing with %s", async (_label, headers) => {
      const f = fixture({ value: true });
      const response = await handlePersonalServerDataRequest(
        request(method, path, headers),
        f.deps,
      );
      expect(response.status).toBe(426);
      expect((await response.json()).errorCode).toBe("update_required");
      expect(f.commitVersion).not.toHaveBeenCalled();
      expect(f.storage.entries).toHaveLength(0);
      for (const call of Object.values(f.uploads)) {
        if (typeof call === "function" && "mock" in call) {
          expect((call as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
        }
      }
    });

    it("is not refused with the switch off", async () => {
      const f = fixture({ value: false });
      const response = await handlePersonalServerDataRequest(
        request(method, path),
        f.deps,
      );
      expect(response.status).not.toBe(426);
    });

    it("is not refused for a declaring client", async () => {
      const f = fixture({ value: true });
      const response = await handlePersonalServerDataRequest(
        request(method, path, { [STREAM_SYNC_CLIENT_HEADER]: "1" }),
        f.deps,
      );
      expect(response.status).not.toBe(426);
    });
  });

  it("lets an old client abort an upload it opened before the switch", async () => {
    const f = fixture({ value: true });
    const response = await handlePersonalServerDataRequest(
      request("DELETE", `/${scope}/uploads/u1`),
      f.deps,
    );
    expect(response.status).toBe(204);
    expect(f.uploads.abort).toHaveBeenCalledOnce();
  });
});

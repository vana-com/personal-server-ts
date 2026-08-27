import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type {
  PersonalServerApiAuthPort,
  PersonalServerDataApiDeps,
  PersonalServerReadAuthResult,
} from "./index.js";

const OWNER = "0x000000000000000000000000000000000000dEaD" as const;
const BUILDER = "0x000000000000000000000000000000000000bEEF";

function depsWithAuth(
  readResult: PersonalServerReadAuthResult | void,
): PersonalServerDataApiDeps {
  const auth: PersonalServerApiAuthPort = {
    authorizeOwner: vi.fn(async () => undefined),
    authorizeBuilderList: vi.fn(async () => undefined),
    authorizeBuilderRead: vi.fn(async () => readResult),
  };
  return {
    // The lineage route never touches local storage before the gate.
    storage: {} as PersonalServerDataApiDeps["storage"],
    auth,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    serverOwner: OWNER,
    lineageGateway: {
      getDataPoint: vi.fn(),
      getLineage: vi.fn(async () => ({
        ok: false as const,
        status: 404,
        body: { error: "not found" },
      })),
      registerDataPoint: vi.fn(),
    },
  };
}

async function lineageRead(deps: PersonalServerDataApiDeps) {
  return handlePersonalServerDataRequest(
    new Request("https://ps.example.com/spine.health.summary/lineage"),
    deps,
  );
}

describe("lineage read: which view the auth result entitles the caller to", () => {
  it("owner signals get the full view (no grantId sent to the gateway)", async () => {
    for (const result of [
      undefined,
      { builder: OWNER, grantId: "owner" },
      { builder: BUILDER, grantId: "policy-bypass" },
    ] as const) {
      const deps = depsWithAuth(result);
      await lineageRead(deps);
      expect(deps.lineageGateway?.getLineage).toHaveBeenCalledWith(
        expect.objectContaining({ grantId: undefined }),
      );
    }
  });

  it("a builder with a resolved grant gets that grant's view", async () => {
    const deps = depsWithAuth({ builder: BUILDER, grantId: "grant-r-1" });
    await lineageRead(deps);
    expect(deps.lineageGateway?.getLineage).toHaveBeenCalledWith(
      expect.objectContaining({ grantId: "grant-r-1" }),
    );
  });

  it("a builder result without a resolved grant is refused, never widened to the owner view", async () => {
    for (const result of [
      { builder: BUILDER },
      { builder: BUILDER, grantId: undefined },
      { builder: BUILDER, grantId: "" },
      { builder: BUILDER, grantId: "unknown" },
    ]) {
      const deps = depsWithAuth(result);
      const res = await lineageRead(deps);
      expect(res.status).toBe(403);
      expect((await res.json()).error.errorCode).toBe("GRANT_REQUIRED");
      expect(deps.lineageGateway?.getLineage).not.toHaveBeenCalled();
    }
  });
});

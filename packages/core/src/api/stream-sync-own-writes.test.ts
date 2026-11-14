import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";

function fixture(mode: "switched" | "unknown") {
  const storageCalls = vi.fn(() => {
    throw new Error("Legacy storage must not be used");
  });
  const abort = vi.fn(async () => undefined);
  const authorizeOwner = vi.fn(async () => undefined);
  const modeRead = vi.fn(() => mode);
  const deps = {
    accountMode: { read: modeRead },
    storage: new Proxy({}, { get: () => storageCalls }),
    scopeUploads: { abort },
    auth: { authorizeOwner },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    logger: { error: vi.fn() },
  } as unknown as PersonalServerDataApiDeps;
  return { deps, storageCalls, abort, authorizeOwner, modeRead };
}

async function remove(path: string, deps: PersonalServerDataApiDeps) {
  const response = await handlePersonalServerDataRequest(
    new Request(`https://server.example/${path}`, { method: "DELETE" }),
    deps,
  );
  return { response, code: (await response.json()).error.errorCode };
}

describe("#598 switched legacy mutation refusals", () => {
  it("refuses data-set DELETE and lineage cascade with USE_CONNECTOR_DELETE", async () => {
    for (const query of ["", "?cascade=lineage"]) {
      const f = fixture("switched");
      const { response, code } = await remove(
        `pdpp.example.items${query}`,
        f.deps,
      );
      expect(response.status).toBe(409);
      expect(code).toBe("USE_CONNECTOR_DELETE");
      expect(f.authorizeOwner).toHaveBeenCalledTimes(1);
      expect(f.modeRead).toHaveBeenCalledTimes(1);
      expect(f.storageCalls).not.toHaveBeenCalled();
    }
  });

  it("refuses control-scope DELETE with STREAM_SYNC_CONTROL_SCOPE", async () => {
    const f = fixture("switched");
    const { response, code } = await remove(
      "pdpp.example~0123456789abcdef",
      f.deps,
    );
    expect(response.status).toBe(409);
    expect(code).toBe("STREAM_SYNC_CONTROL_SCOPE");
    expect(f.authorizeOwner).toHaveBeenCalledTimes(1);
    expect(f.storageCalls).not.toHaveBeenCalled();
  });

  it("refuses import-upload abort with 426, or authenticated 503 while mode is unknown", async () => {
    for (const mode of ["switched", "unknown"] as const) {
      const f = fixture(mode);
      const { response, code } = await remove(
        "pdpp.example.items/uploads/upload-1",
        f.deps,
      );
      expect(response.status).toBe(mode === "switched" ? 426 : 503);
      if (mode === "unknown") expect(code).toBe("ACCOUNT_MODE_UNKNOWN");
      expect(f.authorizeOwner).toHaveBeenCalledTimes(1);
      expect(f.modeRead).toHaveBeenCalledTimes(1);
      expect(f.abort).not.toHaveBeenCalled();
      expect(f.storageCalls).not.toHaveBeenCalled();
    }
  });
});

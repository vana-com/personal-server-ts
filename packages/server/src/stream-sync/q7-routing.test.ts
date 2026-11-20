import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PhysicalScopeError } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { enclaveFleetRoutes } from "../routes/enclave-fleet.js";
import {
  deleteFirstSeenLedger,
  readFirstSeenLedger,
  writeFirstSeenLedger,
} from "../storage/hierarchy.js";

// Ruling Q7: physical stream-sync names never reach the vana-sdk ScopeSchema
// or scopeToPathSegments in the full server.
const PHYSICAL = "pdpp.chatgpt~0123456789abcdef.conversations";

describe("full server routes physical stream-sync names away (ruling Q7)", () => {
  let dataDir: string;
  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "q7-routing-"));
  });
  afterEach(async () => {
    await rm(dataDir, { recursive: true, force: true });
  });

  it("the first-seen ledger has nothing for a physical name and does not throw on read", async () => {
    await expect(
      readFirstSeenLedger({ dataDir }, PHYSICAL),
    ).resolves.toBeNull();
  });

  it("the first-seen ledger refuses writes of a physical name before the SDK", async () => {
    await expect(
      writeFirstSeenLedger({ dataDir }, PHYSICAL, {}),
    ).rejects.toBeInstanceOf(PhysicalScopeError);
    await expect(
      deleteFirstSeenLedger({ dataDir }, PHYSICAL),
    ).rejects.toBeInstanceOf(PhysicalScopeError);
  });

  it("the enclave fleet readiness route answers 400 for a physical name", async () => {
    const hydrate = vi.fn();
    const observe = vi.fn();
    const app = enclaveFleetRoutes({
      accessToken: "local-secret",
      hydrate,
      observe,
    });
    const response = await app.request("/readiness", {
      method: "POST",
      headers: { authorization: "Bearer local-secret" },
      body: JSON.stringify({ hydrate: true, scopes: [{ scope: PHYSICAL }] }),
    });
    expect(response.status).toBe(400);
    expect(hydrate).not.toHaveBeenCalled();
    expect(observe).not.toHaveBeenCalled();
  });
});

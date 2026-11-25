import { describe, expect, it, vi } from "vitest";
import {
  LegacyRetireNotAdmitted,
  LegacyRetireUnavailable,
  type LegacyRetireStatus,
} from "../localdb/legacy-retire-intent.js";
import type { OwnerConnectorDeleteDeps } from "./owner-connector-delete.js";
import {
  handleOwnerLegacyRetire,
  handleOwnerLegacyRetireStatus,
} from "./owner-legacy-retire.js";

const STATUS: LegacyRetireStatus = {
  retireId: "retire-1",
  legacy: { state: "pending" },
};

function setup(
  mode: "switched" | "unswitched" | "unknown" = "switched",
  status: LegacyRetireStatus | null = STATUS,
) {
  const requestLegacyRetire = vi.fn(async () => ({ retireId: "retire-1" }));
  const requestConnectionDelete = vi.fn();
  const deps: OwnerConnectorDeleteDeps = {
    authorizeOwner: vi.fn(async () => {}),
    mode: { read: () => mode },
    connectionDelete: {
      requestConnectionDelete,
      requestLegacyRetire,
      legacyRetireStatus: vi.fn(async () => status),
    },
  };
  return { deps, requestLegacyRetire, requestConnectionDelete };
}

const request = (method: string) =>
  new Request("https://example.test/v1/owner/connectors/github/legacy", {
    method,
  });

describe("DELETE /v1/owner/connectors/:id/legacy", () => {
  it("answers 202 with the intent and its status, and never asks for a connection delete", async () => {
    const { deps, requestLegacyRetire, requestConnectionDelete } = setup();
    const reply = await handleOwnerLegacyRetire(
      request("DELETE"),
      "github",
      deps,
    );
    expect(reply.status).toBe(202);
    expect(await reply.json()).toEqual({
      retireId: "retire-1",
      legacy: { state: "pending" },
    });
    expect(requestLegacyRetire).toHaveBeenCalledWith("github");
    expect(requestConnectionDelete).not.toHaveBeenCalled();
  });

  it("checks the owner first, then the id, then the mode", async () => {
    const { deps } = setup();
    vi.mocked(deps.authorizeOwner).mockRejectedValueOnce(new Error("no"));
    await expect(
      handleOwnerLegacyRetire(request("DELETE"), "github", deps),
    ).rejects.toThrow("no");
    const bad = await handleOwnerLegacyRetire(request("DELETE"), "a~b", deps);
    expect(bad.status).toBe(400);
  });

  it.each([
    ["unswitched", 409, "NOT_SWITCHED"],
    ["unknown", 503, "ACCOUNT_MODE_UNKNOWN"],
  ] as const)("refuses a %s account with %i", async (mode, status, code) => {
    const { deps, requestLegacyRetire } = setup(mode);
    const reply = await handleOwnerLegacyRetire(
      request("DELETE"),
      "github",
      deps,
    );
    expect(reply.status).toBe(status);
    expect((await reply.json()).error.errorCode).toBe(code);
    expect(requestLegacyRetire).not.toHaveBeenCalled();
  });

  it("maps the writer's own refusals", async () => {
    const { deps, requestLegacyRetire } = setup();
    requestLegacyRetire.mockRejectedValueOnce(
      new LegacyRetireNotAdmitted("unswitched"),
    );
    expect(
      (await handleOwnerLegacyRetire(request("DELETE"), "github", deps)).status,
    ).toBe(409);
    requestLegacyRetire.mockRejectedValueOnce(new LegacyRetireUnavailable());
    const reply = await handleOwnerLegacyRetire(
      request("DELETE"),
      "github",
      deps,
    );
    expect(reply.status).toBe(503);
    expect((await reply.json()).error.errorCode).toBe(
      "LEGACY_RETIRE_UNAVAILABLE",
    );
  });

  it("answers 503 where no writer is wired", async () => {
    const { deps } = setup();
    const reply = await handleOwnerLegacyRetire(request("DELETE"), "github", {
      ...deps,
      connectionDelete: null,
    });
    expect(reply.status).toBe(503);
  });
});

describe("GET /v1/owner/connectors/:id/legacy", () => {
  it("answers the intent and its status", async () => {
    const { deps } = setup("switched", {
      retireId: "retire-1",
      legacy: { state: "blocked", reason: "legacy_head_changed" },
    });
    const reply = await handleOwnerLegacyRetireStatus(
      request("GET"),
      "github",
      deps,
    );
    expect(reply.status).toBe(200);
    expect(await reply.json()).toEqual({
      retireId: "retire-1",
      legacy: { state: "blocked", reason: "legacy_head_changed" },
    });
  });

  it("answers 404 when nothing was requested, and the same mode refusals", async () => {
    expect(
      (
        await handleOwnerLegacyRetireStatus(
          request("GET"),
          "github",
          setup("switched", null).deps,
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await handleOwnerLegacyRetireStatus(
          request("GET"),
          "github",
          setup("unswitched").deps,
        )
      ).status,
    ).toBe(409);
  });
});

import { describe, expect, it, vi } from "vitest";
import { pdppInstanceBindingRoutes } from "./pdpp-instance-bindings.js";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { PdppInstanceBinding } from "../storage/pdpp-records-sqlite-store.js";

const OWNER = "0xowner";

function binding(instance: string): PdppInstanceBinding {
  return { instance, method: "m1", generation: 1, resetClock: 0 };
}

function buildApp() {
  const resetInstanceBinding = vi.fn((input: { instance: string }) => ({
    binding: { ...binding(input.instance), method: "m2", generation: 2 },
    alreadyReset: false,
  }));
  const getInstanceBinding = vi.fn((instance: string) => binding(instance));
  const app = pdppInstanceBindingRoutes({
    store: { getInstanceBinding, resetInstanceBinding },
    auth: {
      async resolveToken(token: string) {
        if (token !== "owner-token") return { active: false as const };
        return {
          active: true as const,
          tokenKind: "owner" as const,
          subjectId: OWNER,
          instanceIds: ["inst_1"],
        };
      },
    } satisfies PdppAuthorizationService,
    ownerSubjectId: OWNER,
    instancesForSubject: () => ["inst_1", "inst_2"],
    configuredMethods: new Map([
      ["inst_1", ["m1"]],
      ["inst_2", ["m1"]],
    ]),
  });
  return { app, getInstanceBinding, resetInstanceBinding };
}

describe("pdpp instance binding routes", () => {
  it("denies binding reads outside the owner token's persisted instance scope", async () => {
    const { app, getInstanceBinding } = buildApp();

    const response = await app.request("/pdpp/instances/inst_2/binding", {
      headers: { authorization: "Bearer owner-token" },
    });

    expect(response.status).toBe(401);
    expect((await response.json()).error.code).toBe("authentication_error");
    expect(getInstanceBinding).not.toHaveBeenCalled();
  });

  it("denies resets outside the owner token's persisted instance scope without mutating", async () => {
    const { app, resetInstanceBinding } = buildApp();

    const response = await app.request("/pdpp/instances/inst_2/reset", {
      method: "POST",
      headers: {
        authorization: "Bearer owner-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        expected_method: "m1",
        expected_generation: 1,
        next_method: "m2",
      }),
    });

    expect(response.status).toBe(401);
    expect((await response.json()).error.code).toBe("authentication_error");
    expect(resetInstanceBinding).not.toHaveBeenCalled();
  });

  it("allows resets inside the owner token's persisted instance scope", async () => {
    const { app, resetInstanceBinding } = buildApp();

    const response = await app.request("/pdpp/instances/inst_1/reset", {
      method: "POST",
      headers: {
        authorization: "Bearer owner-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        expected_method: "m1",
        expected_generation: 1,
        next_method: "m2",
      }),
    });

    expect(response.status).toBe(200);
    expect(resetInstanceBinding).toHaveBeenCalledWith({
      instance: "inst_1",
      expectedMethod: "m1",
      expectedGeneration: 1,
      nextMethod: "m2",
    });
  });
});

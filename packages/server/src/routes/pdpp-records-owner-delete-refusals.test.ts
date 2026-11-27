/**
 * Owner DELETE on a switched (stream-sync) account: a refusal with no retry
 * path carries a machine-readable reason (`PDPP-Refusal-Reason` header; the
 * §8 error body stays closed, RS item 6) and a message that names the remedy
 * (trade-off sweep NEW-1).
 */
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { OwnerRecordDeleteResult } from "@opendatalabs/personal-server-ts-core/localdb";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const owner = "0x1111111111111111111111111111111111111111";

function app(switchedDelete?: () => Promise<OwnerRecordDeleteResult>): Hono {
  const a = new Hono();
  a.route(
    "/v1",
    pdppRecordsRoutes({
      accountStorageMode: { owner, read: () => "switched" },
      store: createMemoryRecordStore(),
      ...(switchedDelete && { switchedDelete }),
      auth: createFixtureAuthorizationService({
        owner: {
          active: true,
          tokenKind: "owner",
          subjectId: owner,
          instanceIds: ["h"],
        },
      }),
      declarations: createStreamDeclarationRegistry([
        {
          name: "items",
          semantics: "mutable_state",
          primaryKey: ["id"],
          requiredFields: ["id"],
        },
      ]),
      instancesForSubject: () => ["h"],
    }),
  );
  return a;
}

const del = (a: Hono) =>
  a.request("/v1/streams/items/records/r1", {
    method: "DELETE",
    headers: { Authorization: "Bearer owner" },
  });

describe("owner DELETE refusals on a switched account (NEW-1)", () => {
  it.each([
    ["namespaced_connection", "device that collects this connection"],
    ["no_verified_artifact", "Update the server"],
    ["delete_not_applied", "disconnect the connection"],
  ])("returns 409 with reason %s and the remedy", async (code, remedy) => {
    const res = await del(
      app(async () => ({
        kind: "refused",
        code,
        reason: `… ${remedy} …`,
        retryable: false,
      })),
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as {
      error: { code: string; message: string };
    };
    expect(body.error.code).toBe("conflict");
    expect(res.headers.get("PDPP-Refusal-Reason")).toBe(code);
    expect(body.error.message).toContain(remedy);
  });

  it("returns 503 with reason registry_unreachable when the refusal is retryable", async () => {
    const res = await del(
      app(async () => ({
        kind: "refused",
        code: "registry_unreachable",
        reason: "Try again later.",
        retryable: true,
      })),
    );
    expect(res.status).toBe(503);
    expect(res.headers.get("PDPP-Refusal-Reason")).toBe("registry_unreachable");
  });

  it("returns 426 with reason delete_port_missing and the remedy when the host has no delete port", async () => {
    const res = await del(app());
    expect(res.status).toBe(426);
    const body = (await res.json()) as { error: { message: string } };
    expect(res.headers.get("PDPP-Refusal-Reason")).toBe("delete_port_missing");
    expect(body.error.message).toContain("Update the Personal Server app");
  });
});

import { afterEach, expect, it, vi } from "vitest";
import { createServerApiAuth } from "./api-auth.js";
import { handlePersonalServerDataRequest } from "@opendatalabs/personal-server-ts-core/api";
import { createMemoryDataStorage } from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createScopeDeletionTracker,
  type ScopeDeletionTracker,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
const OWNER = "0x1111111111111111111111111111111111111111" as const;
const SCOPE = "test.records";
afterEach(() => vi.useRealTimers());
for (const scopeKind of ["instance", "source"] as const) {
  for (const ending of [
    "token revocation",
    "family revocation",
    "expiry",
    "connection removal",
    "unchanged",
  ] as const) {
    it(`F4: real owner versions bridge retains authority through visibility await: ${scopeKind} ${ending}`, async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      const now = Date.now();
      let active = true;
      let available = true;
      const context: PdppTokenContext = {
        active: true,
        tokenKind: "owner",
        subjectId: OWNER,
        ...(scopeKind === "instance"
          ? { instanceIds: ["test:i"] }
          : { sourceId: "https://registry.example/source/test" }),
        expiresAt: new Date(now + 5_000).toISOString(),
      };
      const auth: PdppAuthorizationService = {
        locality: "local",
        resolveToken: async () => context,
        resolveTokenNow: () =>
          active ? context : { active: false, inactiveReason: "revoked" },
      };
      const storage = createMemoryDataStorage();
      const envelope = {
        version: "1.0",
        scope: SCOPE,
        collectedAt: new Date(now).toISOString(),
        data: { private: "body" },
      };
      const written = await storage.writeEnvelope(envelope as never);
      storage.insertEntry({
        scope: SCOPE,
        collectedAt: envelope.collectedAt,
        path: written.path!,
        sizeBytes: written.sizeBytes,
        fileId: "private-file-id",
        producerProvenance: JSON.stringify({ private: "owner-provenance" }),
      });
      const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
      const resolving = new Proxy(tracker, {
        get(target, key) {
          if (key === "resolve")
            return async (
              ...args: Parameters<ScopeDeletionTracker["resolve"]>
            ) => {
              const verdict = await target.resolve(...args);
              if (ending === "expiry") vi.setSystemTime(now + 6_000);
              if (ending === "connection removal") available = false;
              if (ending.includes("revocation")) active = false;
              return verdict;
            };
          return Reflect.get(target, key, target);
        },
      });
      const apiAuth = createServerApiAuth({
        serverOrigin: "http://ps",
        serverOwner: OWNER,
        gateway: {} as never,
        pdppOwnerBearer: {
          auth,
          ownerSubjectId: OWNER,
          configuredMethods: new Map([
            ["test:i", ["test"]],
            ["https://registry.example/source/test", ["test"]],
          ]),
          instancesForSubject: () => (available ? ["test:i"] : []),
          instancesForSource: () => (available ? ["test:i"] : []),
        },
      });
      const response = await handlePersonalServerDataRequest(
        new Request(`http://ps/v1/data/${SCOPE}/versions`, {
          headers: { Authorization: "Bearer t" },
        }),
        {
          auth: apiAuth,
          storage,
          scopeDeletions: resolving,
          serverOwner: OWNER,
        },
        { basePath: "/v1/data" },
      );
      const text = await response.text();
      if (ending === "unchanged") {
        expect(response.status, text).toBe(200);
        expect(text).toContain("private-file-id");
        expect(text).toContain("owner-provenance");
      } else {
        expect(response.status, text).toBeGreaterThanOrEqual(400);
        expect(text).not.toContain("private-file-id");
        expect(text).not.toContain("owner-provenance");
      }
    });
  }
}

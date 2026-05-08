import { PsUnavailableError } from "@opendatalabs/personal-server-ts-core/errors";
import type { RuntimeAvailabilityPort } from "@opendatalabs/personal-server-ts-core/ports";

export interface PsLiteStorageAdapter {
  kind: "indexeddb" | "opfs" | "custom";
}

export interface PsLiteRuntimeOptions {
  storage: PsLiteStorageAdapter;
  active?: boolean;
  now?: () => Date;
}

export interface PsLiteRuntime extends RuntimeAvailabilityPort {
  readonly kind: "ps-lite";
  readonly storage: PsLiteStorageAdapter;
  activate(): void;
  deactivate(): void;
  fetch(request: Request): Promise<Response>;
}

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

function unavailableResponse(): Response {
  const err = new PsUnavailableError({
    runtime: "ps-lite",
    reason: "Browser runtime is inactive",
  });
  return jsonResponse(err.toJSON(), { status: err.code });
}

export function createPsLiteRuntime(
  options: PsLiteRuntimeOptions,
): PsLiteRuntime {
  let active = options.active ?? false;
  const now = options.now ?? (() => new Date());

  return {
    kind: "ps-lite",
    storage: options.storage,
    activate() {
      active = true;
    },
    deactivate() {
      active = false;
    },
    isAvailable() {
      return active;
    },
    async fetch(request: Request) {
      const url = new URL(request.url);

      if (url.pathname === "/health") {
        return jsonResponse({
          status: active ? "healthy" : "unavailable",
          runtime: "ps-lite",
          storage: options.storage.kind,
          active,
          checkedAt: now().toISOString(),
        });
      }

      if (!active) {
        return unavailableResponse();
      }

      return jsonResponse(
        {
          error: {
            code: 501,
            errorCode: "NOT_IMPLEMENTED",
            message: "PS Lite contract handler not implemented",
          },
        },
        { status: 501 },
      );
    },
  };
}

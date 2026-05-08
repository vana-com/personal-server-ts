import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import {
  createBearerTokenPsLiteAuth,
  createMemoryPsLiteStorage,
  createPsLiteRuntime,
  handlePsLiteBridgeRequest,
  type PsLiteRuntime,
} from "@opendatalabs/personal-server-ts-lite";

export interface PsLiteDebugRouteDeps {
  devToken: string;
  now?: () => Date;
}

const PS_LITE_ORIGIN = "https://ps-lite.local";
const OWNER_TOKEN = "ps-lite-owner-token";
const BUILDER_TOKEN = "ps-lite-builder-token";
const SAMPLE_SCOPE = "debug.local.profile";
const SAMPLE_GRANT_ID = "debug-grant";
const SAMPLE_BODY = {
  source: "debug-ui",
  mode: "local",
};

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

async function responseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function toBridgeBody(body: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  return Buffer.from(bytes).toString("base64");
}

function createRuntime(now?: () => Date): PsLiteRuntime {
  return createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: OWNER_TOKEN,
      builderToken: BUILDER_TOKEN,
    }),
    active: false,
    now,
  });
}

export function psLiteDebugRoutes(deps: PsLiteDebugRouteDeps): Hono {
  const app = new Hono();
  let runtime = createRuntime(deps.now);

  const requireDevToken: MiddlewareHandler = async (c, next) => {
    if (c.req.header("authorization") !== `Bearer ${deps.devToken}`) {
      return c.json(
        {
          error: {
            code: 401,
            errorCode: "UNAUTHORIZED",
            message: "Invalid dev token",
          },
        },
        401,
      );
    }
    await next();
  };

  app.use("*", requireDevToken);

  app.post("/reset", (c) => {
    runtime = createRuntime(deps.now);
    return c.json({ status: "reset", active: false });
  });

  app.post("/activate", (c) => {
    runtime.activate();
    return c.json({ status: "activated", active: true });
  });

  app.post("/deactivate", (c) => {
    runtime.deactivate();
    return c.json({ status: "deactivated", active: false });
  });

  app.get("/health", async () => {
    const response = await runtime.fetch(
      new Request(`${PS_LITE_ORIGIN}/health`),
    );
    return jsonResponse(await responseBody(response), {
      status: response.status,
    });
  });

  app.post("/ingest", async (c) => {
    const payload = (await c.req.json().catch(() => SAMPLE_BODY)) as unknown;
    const body =
      payload && typeof payload === "object" && !Array.isArray(payload)
        ? payload
        : SAMPLE_BODY;
    const response = await runtime.fetch(
      new Request(`${PS_LITE_ORIGIN}/v1/data/${SAMPLE_SCOPE}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OWNER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }),
    );
    return jsonResponse(await responseBody(response), {
      status: response.status,
    });
  });

  app.get("/list", async () => {
    const response = await runtime.fetch(
      new Request(`${PS_LITE_ORIGIN}/v1/data`, {
        headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
      }),
    );
    return jsonResponse(await responseBody(response), {
      status: response.status,
    });
  });

  app.get("/read", async () => {
    const response = await runtime.fetch(
      new Request(
        `${PS_LITE_ORIGIN}/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
        {
          headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
        },
      ),
    );
    return jsonResponse(await responseBody(response), {
      status: response.status,
    });
  });

  app.post("/bridge-read", async (c) => {
    const response = await handlePsLiteBridgeRequest(
      runtime,
      {
        requestId: "debug-bridge-read",
        method: "GET",
        path: `/v1/data/${SAMPLE_SCOPE}`,
        query: `grantId=${SAMPLE_GRANT_ID}`,
        headers: { authorization: `Bearer ${BUILDER_TOKEN}` },
        body: "",
      },
      { origin: PS_LITE_ORIGIN },
    );
    return c.json(response, response.status as 200 | 401 | 403 | 404 | 503);
  });

  app.post("/local-smoke", async (c) => {
    runtime.activate();
    const write = await runtime.fetch(
      new Request(`${PS_LITE_ORIGIN}/v1/data/${SAMPLE_SCOPE}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OWNER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(SAMPLE_BODY),
      }),
    );
    const list = await runtime.fetch(
      new Request(`${PS_LITE_ORIGIN}/v1/data`, {
        headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
      }),
    );
    const read = await runtime.fetch(
      new Request(
        `${PS_LITE_ORIGIN}/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
        {
          headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
        },
      ),
    );
    const bridge = await handlePsLiteBridgeRequest(
      runtime,
      {
        requestId: "debug-bridge-post",
        method: "POST",
        path: `/v1/data/${SAMPLE_SCOPE}`,
        query: "",
        headers: {
          authorization: `Bearer ${OWNER_TOKEN}`,
          "content-type": "application/json",
        },
        body: toBridgeBody({ ...SAMPLE_BODY, bridge: true }),
      },
      { origin: PS_LITE_ORIGIN },
    );

    return c.json({
      status:
        write.ok && list.ok && read.ok && bridge.status === 201
          ? "ok"
          : "failed",
      runtime: "ps-lite",
      mode: "local",
      write: {
        status: write.status,
        body: await responseBody(write),
      },
      list: {
        status: list.status,
        body: await responseBody(list),
      },
      read: {
        status: read.status,
        body: await responseBody(read),
      },
      bridge,
    });
  });

  return app;
}

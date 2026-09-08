import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";

export interface UiRouteDeps {
  devToken: string;
  /**
   * PS Lite debug bootstrap (owner master-key signature + config). NEVER
   * rendered into the HTML — served only by `GET /api/bootstrap` to a caller
   * presenting the dev token. The owner signature recovers the owner identity
   * and derives the storage encryption key, so it must not sit in a page that
   * any GET can fetch.
   */
  psLiteBootstrap?: unknown;
}

// Read the HTML file once at module load time
let cachedHtml: string | null = null;

function getHtmlPath(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  return join(currentDir, "..", "ui", "index.html");
}

function getUiAssetPath(fileName: string): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const distPath = join(currentDir, "..", "ui", fileName);
  if (!currentDir.endsWith(`${sep}dist${sep}routes`)) {
    return join(currentDir, "..", "..", "dist", "ui", fileName);
  }
  return distPath;
}

function loadHtml(devToken: string): string {
  if (!cachedHtml) {
    cachedHtml = readFileSync(getHtmlPath(), "utf-8");
  }
  // The bootstrap placeholder is always rendered as `null`; the page fetches
  // the real value from /api/bootstrap with the dev token at runtime.
  return cachedHtml
    .replace("__DEV_TOKEN__", devToken)
    .replace('"__PS_LITE_BOOTSTRAP_JSON__"', "null");
}

function contentTypeFor(fileName: string): string {
  if (fileName.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (fileName.endsWith(".wasm")) return "application/wasm";
  return "application/octet-stream";
}

function hasDevToken(
  authHeader: string | undefined,
  devToken: string,
): boolean {
  if (!authHeader) return false;
  const expected = Buffer.from(`Bearer ${devToken}`);
  const presented = Buffer.from(authHeader);
  return (
    expected.length === presented.length && timingSafeEqual(expected, presented)
  );
}

export function uiRoute(deps: UiRouteDeps): Hono {
  const app = new Hono();

  app.get("/", (c) => {
    try {
      const html = loadHtml(deps.devToken);
      return c.html(html);
    } catch {
      return c.json(
        {
          error: {
            code: 500,
            errorCode: "UI_ERROR",
            message: "Failed to load UI",
          },
        },
        500,
      );
    }
  });

  // Dev-token-gated bootstrap for the browser PS Lite debug runtime. Keeps the
  // owner signature out of the HTML: it is only returned to a caller that can
  // present the dev token in an Authorization header (which a cross-origin
  // page cannot attach without a CORS preflight).
  app.get("/api/bootstrap", (c) => {
    if (!hasDevToken(c.req.header("authorization"), deps.devToken)) {
      return c.json(
        {
          error: {
            code: 401,
            errorCode: "MISSING_AUTH",
            message: "Dev token required",
          },
        },
        401,
      );
    }
    if (!deps.psLiteBootstrap) {
      return c.notFound();
    }
    return c.json(deps.psLiteBootstrap, 200, { "cache-control": "no-store" });
  });

  app.get("/:file", (c) => {
    const fileName = c.req.param("file");
    if (
      fileName !== "ps-lite-debug.js" &&
      fileName !== "browser_tls_rustls_bg.wasm"
    ) {
      return c.notFound();
    }
    try {
      const asset = readFileSync(getUiAssetPath(fileName));
      return new Response(asset, {
        headers: {
          "content-type": contentTypeFor(fileName),
          "cache-control": "no-store",
        },
      });
    } catch {
      return c.json(
        {
          error: {
            code: 404,
            errorCode: "UI_ASSET_NOT_FOUND",
            message: "UI asset not found. Run npm run build.",
          },
        },
        404,
      );
    }
  });

  return app;
}

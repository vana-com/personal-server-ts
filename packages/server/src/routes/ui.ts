import { readFileSync } from "node:fs";
import { join, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Hono } from "hono";

export interface UiRouteDeps {
  devToken: string;
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
  return cachedHtml.replace("__DEV_TOKEN__", devToken);
}

function contentTypeFor(fileName: string): string {
  if (fileName.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (fileName.endsWith(".wasm")) return "application/wasm";
  return "application/octet-stream";
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

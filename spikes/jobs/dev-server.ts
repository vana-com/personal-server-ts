/**
 * Minimal stand-in for `vercel dev`: routes requests through vercel.json
 * rewrites to the api/ handlers, emulating the @vercel/node request shape
 * (parsed JSON body, path params merged into req.query, replayable body
 * stream) and response helpers (status/json/send). Local measurement only.
 *
 *   REPO=/path/to/data-gateway PORT=3000 tsx dev-server.ts
 */
import http from "node:http";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const REPO = process.env["REPO"]!;
const PORT = Number(process.env["PORT"] ?? 3000);
const HTTP_NOT_FOUND = 404;

interface Route {
  regex: RegExp;
  keys: string[];
  file: string;
}

const vercel = JSON.parse(readFileSync(`${REPO}/vercel.json`, "utf8")) as {
  rewrites: { source: string; destination: string }[];
};

const routes: Route[] = vercel.rewrites.map(({ source, destination }) => {
  const keys: string[] = [];
  const pattern = source.replace(/:([A-Za-z0-9_]+)/g, (_, k: string) => {
    keys.push(k);
    return "([^/]+)";
  });
  const file = destination.replace(/:([A-Za-z0-9_]+)/g, "[$1]");
  return { regex: new RegExp(`^${pattern}$`), keys, file: `${REPO}${file}.ts` };
});

const modules = new Map<
  string,
  Promise<{ default: (req: unknown, res: unknown) => unknown }>
>();
function load(file: string) {
  let mod = modules.get(file);
  if (!mod) {
    mod = import(pathToFileURL(file).href);
    modules.set(file, mod);
  }
  return mod;
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => parts.push(c));
    req.on("end", () => resolve(Buffer.concat(parts)));
    req.on("error", reject);
  });
}

function parseBody(raw: Buffer, contentType: string | undefined): unknown {
  if (raw.length === 0) return undefined;
  if (/^application\/json/i.test(contentType ?? "")) {
    try {
      return JSON.parse(raw.toString("utf8"));
    } catch {
      return undefined;
    }
  }
  return raw.toString("utf8");
}

http
  .createServer(async (req, res) => {
    const url = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "localhost"}`,
    );
    const route = routes.find((r) => r.regex.test(url.pathname));
    if (!route) {
      res.statusCode = HTTP_NOT_FOUND;
      res.end(JSON.stringify({ error: "Not found", path: url.pathname }));
      return;
    }

    const query: Record<string, string> = Object.fromEntries(
      url.searchParams.entries(),
    );
    const match = url.pathname.match(route.regex)!;
    route.keys.forEach(
      (k, i) => (query[k] = decodeURIComponent(match[i + 1]!)),
    );

    const raw = await readBody(req);
    // Vercel buffers the body and replays it through on('data'|'end') for
    // handlers that need the exact bytes; emulate that after consuming it.
    const on = (event: string, cb: (arg?: unknown) => void) => {
      if (event === "data" && raw.length > 0) setImmediate(() => cb(raw));
      if (event === "end") setImmediate(() => cb());
      return req;
    };
    const vreq = Object.assign(req, {
      query,
      body: parseBody(raw, req.headers["content-type"]),
      on,
      cookies: {},
    });

    const vres = Object.assign(res, {
      status(code: number) {
        res.statusCode = code;
        return vres;
      },
      json(payload: unknown) {
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify(payload));
        return vres;
      },
      send(payload: unknown) {
        res.end(
          typeof payload === "string" || Buffer.isBuffer(payload)
            ? payload
            : JSON.stringify(payload),
        );
        return vres;
      },
    });

    try {
      const mod = await load(route.file);
      await mod.default(vreq, vres);
    } catch (error) {
      console.error("[dev-server]", route.file, error);
      if (!res.headersSent) res.statusCode = 500;
      res.end(JSON.stringify({ error: "handler crashed" }));
    }
  })
  .listen(PORT, () =>
    console.log(
      `[dev-server] listening on http://localhost:${PORT} for ${REPO}`,
    ),
  );

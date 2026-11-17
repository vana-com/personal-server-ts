import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  collectRoutes,
  routesContractFromRepo,
  type RoutesContract,
  type SourceFile,
} from "./routes-contract.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const file = JSON.parse(
  readFileSync(
    new URL("../packages/core/contracts/routes.json", import.meta.url),
    "utf8",
  ),
) as RoutesContract;

const names = (contract: RoutesContract): string[] =>
  contract.routes.map((route) => route.path);
const serverNames = (contract: RoutesContract): string[] =>
  contract.routes
    .filter((route) => route.hosts.includes("server"))
    .map((route) => route.path);

// A small server: `files` are relative to /s, and /s/app.ts exports createApp.
const collect = (
  files: Record<string, string>,
  lite: Record<string, string> = {},
) =>
  collectRoutes({
    server: Object.entries(files).map(([name, text]) => ({
      name: `/s/${name}`,
      text,
    })),
    serverEntry: "/s/app.ts",
    lite: Object.entries(lite).map(([name, text]) => ({
      name: `/l/${name}`,
      text,
    })),
  }).routes;

const app = (body: string, header = "") =>
  `import { Hono } from "hono";\n${header}\nexport function createApp() {\n  const app = new Hono();\n${body}\n  return app;\n}\n`;

describe("the routes contract file", () => {
  // A host reads this file, not the source. If this fails, run
  // `npm run contracts:write` and commit the file with the route change.
  it("is what the route registrations produce", () => {
    expect(file).toEqual(routesContractFromRepo(root));
  });

  it("names the routes the client factory calls", () => {
    expect(names(file)).toEqual(
      expect.arrayContaining(["/v1/data", "/v1/access-logs", "/v1/sync"]),
    );
  });

  it("names routes registered only inside a mounted router", () => {
    expect(names(file)).toEqual(
      expect.arrayContaining(["/v1/sync/trigger", "/v1/sync/events"]),
    );
  });

  it("does not claim the roots other services share", () => {
    expect(names(file)).not.toContain("/v1");
    expect(names(file)).not.toContain("/.well-known");
  });
});

/**
 * The staleness check is only as good as the generator. Each case changes the
 * real source in memory the way a developer would, then asks the generator for
 * the contract; the committed file must no longer match.
 */
describe("the generator sees a changed route table", () => {
  const readTree = (directory: string, recursive: boolean): SourceFile[] =>
    readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        return recursive ? readTree(full, true) : [];
      }
      return entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")
        ? [{ name: full, text: readFileSync(full, "utf8") }]
        : [];
    });
  const serverDir = path.join(root, "packages/server/src");
  const generate = (change: (source: SourceFile) => string): RoutesContract =>
    collectRoutes({
      server: readTree(serverDir, true).map((source) => ({
        ...source,
        text: change(source),
      })),
      serverEntry: path.join(serverDir, "app.ts"),
      lite: readTree(path.join(root, "packages/lite/src"), false),
    });
  const insertBeforeReturn =
    (target: string, code: string) => (source: SourceFile) =>
      source.name.endsWith(target)
        ? source.text.replace(
            /\n {2}return app;\n/u,
            `\n${code}\n  return app;\n`,
          )
        : source.text;

  it("unchanged source matches the committed file", () => {
    expect(generate((source) => source.text)).toEqual(file);
  });

  it("adds a route to a mounted child router", () => {
    const changed = generate(
      insertBeforeReturn(
        "routes/sync.ts",
        `  app.post("/zz-new-child", (c) => c.text("x"));`,
      ),
    );
    expect(names(changed)).toContain("/v1/sync/zz-new-child");
    expect(changed).not.toEqual(file);
  });

  it("renames a route in a mounted child router", () => {
    const changed = generate((source) =>
      source.name.endsWith("routes/sync.ts")
        ? source.text.replace('app.post("/trigger"', 'app.post("/zz-renamed"')
        : source.text,
    );
    expect(serverNames(changed)).toContain("/v1/sync/zz-renamed");
    expect(serverNames(changed)).not.toContain("/v1/sync/trigger");
    expect(changed).not.toEqual(file);
  });

  it("removes a route from a mounted child router", () => {
    const changed = generate((source) =>
      source.name.endsWith("routes/sync.ts")
        ? source.text.replace('app.post("/trigger"', 'app.use("*"')
        : source.text,
    );
    expect(serverNames(changed)).not.toContain("/v1/sync/trigger");
    expect(changed).not.toEqual(file);
  });

  it("adds a constant-backed route family", () => {
    const changed = generate(
      insertBeforeReturn(
        "app.ts",
        `  const ZZ_NEW_FAMILY = "/zz-family";\n  app.get(ZZ_NEW_FAMILY, (c) => c.text("x"));`,
      ),
    );
    expect(names(changed)).toContain("/zz-family");
    expect(changed).not.toEqual(file);
  });
});

describe("collectRoutes", () => {
  it("composes a mounted router's routes under its mount path", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.route("/v1/sync", syncRoutes());`,
          `import { syncRoutes } from "./routes/sync.js";`,
        ),
        "routes/sync.ts": `import { Hono } from "hono";
export function syncRoutes() {
  const r = new Hono();
  r.post("/trigger", h).get("/events/:id", h);
  r.get("/", h);
  return r;
}`,
      }),
    ).toEqual([
      { path: "/v1/sync", hosts: ["server"], methods: ["GET"] },
      { path: "/v1/sync/events", hosts: ["server"], methods: ["GET"] },
      { path: "/v1/sync/trigger", hosts: ["server"], methods: ["POST"] },
    ]);
  });

  it("follows a router mounted inside a mounted router", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.route("/a", outer());`,
          `import { outer } from "./outer.js";`,
        ),
        "outer.ts": `import { Hono } from "hono";
import { inner } from "./inner.js";
export const outer = () => {
  const r = new Hono();
  r.route("/b", inner());
  return r;
};`,
        "inner.ts": `import { Hono } from "hono";
export function inner() {
  const r = new Hono();
  r.put("/c", h);
  return r;
}`,
      }).map((route) => route.path),
    ).toEqual(["/a", "/a/b", "/a/b/c"]);
  });

  it("follows a factory that returns another factory's router", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.route("/w", wrapped());`,
          `import { wrapped } from "./w.js";`,
        ),
        "w.ts": `import { inner } from "./inner.js";
export function wrapped() {
  return inner();
}`,
        "inner.ts": `import { Hono } from "hono";
export function inner() {
  const r = new Hono();
  r.get("/x", h);
  return r;
}`,
      }).map((route) => route.path),
    ).toEqual(["/w", "/w/x"]);
  });

  it("follows a named router built in the same function", () => {
    expect(
      collect({
        "app.ts": `import { Hono } from "hono";
export function createApp() {
  const app = new Hono();
  const admin = new Hono();
  admin.delete("/zap", h);
  app.route("/admin", admin);
  return app;
}`,
      }).map((route) => route.path),
    ).toEqual(["/admin", "/admin/zap"]);
  });

  it("resolves constants: local, imported, templated, concatenated, in objects and loops", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.get(LOCAL, h);
  app.get(ROUTES.reports, h);
  app.get(\`\${BASE}/templated\`, h);
  app.get(BASE + "/joined", h);
  for (const each of ["/looped-a", "/looped-b"]) {
    app.all(each, h);
  }
  app.post(IMPORTED, h);`,
          `import { IMPORTED, BASE } from "./paths.js";
const LOCAL = "/local-family";
const ROUTES = { reports: "/reports" } as const;`,
        ),
        "paths.ts": `export const BASE = "/base";
export const IMPORTED = "/imported-family";`,
      }).map((route) => route.path),
    ).toEqual([
      "/base/joined",
      "/base/templated",
      "/imported-family",
      "/local-family",
      "/looped-a",
      "/looped-b",
      "/reports",
    ]);
  });

  it("records a parameterized handler as its static prefix", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.get("/things/:id/parts/*", h);\n  app.get("/:id", h);`,
        ),
      }),
    ).toEqual([{ path: "/things", hosts: ["server"], methods: ["GET"] }]);
  });

  it("drops only the roots other services share and middleware for every path", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.use("*", mw);\n  app.use(mw);\n  app.route("/v1", a());\n  app.use("/.well-known", mw, mw);`,
          `import { a } from "./a.js";`,
        ),
        "a.ts": `import { Hono } from "hono";
export function a() {
  const r = new Hono();
  r.get("/own", h);
  return r;
}`,
      }).map((route) => route.path),
    ).toEqual(["/v1/own"]);
  });

  it("reads the lite dispatcher's comparisons, prefixes and constants", () => {
    expect(
      collect(
        {
          "app.ts": app(
            `  app.route("/v1/data", d());`,
            `import { d } from "./d.js";`,
          ),
          "d.ts": `import { Hono } from "hono";
export function d() {
  const r = new Hono();
  return r;
}`,
        },
        {
          "dispatch.ts": `import { LITE_ONLY } from "./paths.js";
const NEW_ROUTE = "/v1/new-route";
const syncPrefix = "/v1/sync";
export function dispatch(url: URL) {
  if (url.pathname === "/v1/data") {}
  if (url.pathname.startsWith("/v1/grants/")) {}
  if (url.pathname === NEW_ROUTE) {}
  if (url.pathname === LITE_ONLY) {}
  return syncPrefix;
}`,
          "paths.ts": `export const LITE_ONLY = "/v1/lite-only";`,
        },
      ),
    ).toEqual([
      { path: "/v1/data", hosts: ["lite", "server"] },
      { path: "/v1/grants", hosts: ["lite"] },
      { path: "/v1/lite-only", hosts: ["lite"] },
      { path: "/v1/new-route", hosts: ["lite"] },
      { path: "/v1/sync", hosts: ["lite"] },
    ]);
  });

  it("ignores literals that are not registrations", () => {
    expect(
      collect(
        {
          "app.ts": app(
            `  log("/v1/not-a-route");\n  const note = "/v1/other";\n  cache.set("/v1/also", 1);`,
          ),
        },
        {
          "x.ts": `export const f = (m: Map<string, string>) => m.get("key");`,
        },
      ),
    ).toEqual([]);
  });

  it("sorts by path", () => {
    expect(
      collect({
        "app.ts": app(
          `  app.route("/b/x", r());\n  app.route("/a/x", r());`,
          `import { r } from "./r.js";`,
        ),
        "r.ts": `import { Hono } from "hono";
export function r() {
  const x = new Hono();
  return x;
}`,
      }).map((route) => route.path),
    ).toEqual(["/a/x", "/b/x"]);
  });

  describe("fails instead of dropping a route it cannot resolve", () => {
    it.each([
      ["a handler path from a call", `  app.get(pathFor("x"), h);`, ""],
      ["a mount prefix from a parameter", `  app.route(deps.prefix, a());`, ""],
      [
        "a mounted router that is not a factory call",
        `  app.route("/x", deps.router);`,
        "",
      ],
      [
        "an imported constant that is not a string",
        `  app.get(COUNT, h);`,
        `import { COUNT } from "./paths.js";`,
      ],
      ["a router passed to a function", `  register(app);`, ""],
      ["a router that is not named", `  new Hono().get("/hidden", h);`, ""],
      ["basePath", `  const scoped = app.basePath("/v9");`, ""],
    ])("%s", (_name, body, header) => {
      expect(() =>
        collect({
          "app.ts": app(body, header),
          "paths.ts": `export const COUNT = 3;`,
        }),
      ).toThrow(/routes-contract:/u);
    });

    it("a lite comparison against a constant that is not a string", () => {
      expect(() =>
        collect(
          { "app.ts": app("") },
          {
            "dispatch.ts": `const NEW_ROUTE = compute();
export function f(url: URL) { return url.pathname === NEW_ROUTE; }`,
          },
        ),
      ).toThrow(/NEW_ROUTE|path constant/u);
    });
  });
});

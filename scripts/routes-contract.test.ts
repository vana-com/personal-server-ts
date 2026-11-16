import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  collectRoutes,
  routesContractFromRepo,
  type SourceFile,
} from "./routes-contract.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const file = JSON.parse(
  readFileSync(
    new URL("../packages/core/contracts/routes.json", import.meta.url),
    "utf8",
  ),
) as unknown;

const source = (text: string, name = "x.ts"): SourceFile => ({ name, text });
const collect = (input: { app?: string; routes?: string[]; lite?: string[] }) =>
  collectRoutes({
    serverApp: source(input.app ?? ""),
    serverRoutes: (input.routes ?? []).map((text) => source(text)),
    lite: (input.lite ?? []).map((text) => source(text)),
  }).routes;

describe("the routes contract file", () => {
  // A host reads this file, not the source. If this fails, run
  // `npm run contracts:write` and commit the file with the route change.
  it("is what the route registrations produce", () => {
    expect(file).toEqual(routesContractFromRepo(root));
  });

  it("names the routes the client factory calls", () => {
    const paths = (
      file as ReturnType<typeof routesContractFromRepo>
    ).routes.map((route) => route.path);
    expect(paths).toEqual(
      expect.arrayContaining(["/v1/data", "/v1/access-logs", "/v1/sync"]),
    );
  });

  it("does not claim the roots other services share", () => {
    const paths = (
      file as ReturnType<typeof routesContractFromRepo>
    ).routes.map((route) => route.path);
    expect(paths).not.toContain("/v1");
    expect(paths).not.toContain("/.well-known");
  });
});

describe("collectRoutes", () => {
  it("reads mounts, handlers and lite comparisons, merging hosts", () => {
    expect(
      collect({
        app: `app.route("/v1/data", r); app.use("/v1/sync/*", m);`,
        lite: [
          `if (url.pathname === "/v1/data") {}
           if (url.pathname.startsWith("/v1/grants/")) {}
           const syncPrefix = "/v1/sync";`,
        ],
      }),
    ).toEqual([
      { path: "/v1/data", hosts: ["lite", "server"] },
      { path: "/v1/grants", hosts: ["lite"] },
      { path: "/v1/sync", hosts: ["lite", "server"] },
    ]);
  });

  it("ignores literals that are not registrations", () => {
    expect(
      collect({
        app: `log("/v1/not-a-route"); const note = "/v1/other"; x.set("/v1/also", 1);`,
      }),
    ).toEqual([]);
  });

  it("drops shared roots, wildcards and parameters", () => {
    expect(
      collect({
        app: `app.route("/v1", a); app.use("/.well-known", b);
               app.get("/:id", c); app.get("/v1/x/*", d); app.use("/", e);`,
      }),
    ).toEqual([{ path: "/v1/x", hosts: ["server"] }]);
  });

  it("admits a route file's path only when a mount already names its root", () => {
    expect(
      collect({
        app: `app.route("/health", h);`,
        routes: [`app.get("/health", a); app.get("/trigger", b);`],
      }),
    ).toEqual([{ path: "/health", hosts: ["server"] }]);
  });

  it("sorts by path", () => {
    const paths = collect({
      app: `app.route("/v1/b", a); app.route("/v1/a", b);`,
    }).map((route) => route.path);
    expect(paths).toEqual(["/v1/a", "/v1/b"]);
  });
});

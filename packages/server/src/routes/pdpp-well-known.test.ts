import { describe, it, expect } from "vitest";
import { pdppWellKnownRoutes } from "./pdpp-well-known.js";

describe("pdpp well-known protected-resource metadata", () => {
  it("publishes the RFC 9728 document with the 4 pdpp_ members", async () => {
    const app = pdppWellKnownRoutes({
      resource: "https://ps.example.com",
      coreQueryBase: "/v1",
      authorizationServers: ["https://as.example.com"],
    });
    const res = await app.request("/oauth-protected-resource");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resource).toBe("https://ps.example.com");
    expect(body.authorization_servers).toEqual(["https://as.example.com"]);
    expect(body.pdpp_core_query_base).toBe("/v1");
    expect(body.pdpp_token_kinds_supported).toEqual(["owner", "client"]);
    expect(body.pdpp_self_export_supported).toBe(true);
    expect(body.pdpp_provider_connect_version).toBe("2026-04-06");
  });

  it("omits authorization_servers when not enumerable, rather than publishing a partial list", async () => {
    const app = pdppWellKnownRoutes({
      resource: "https://ps.example.com",
      coreQueryBase: "/v1",
    });
    const res = await app.request("/oauth-protected-resource");
    const body = await res.json();
    expect(body).not.toHaveProperty("authorization_servers");
  });
});

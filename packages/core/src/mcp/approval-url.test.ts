import { describe, expect, it } from "vitest";
import {
  buildMcpScopeRequestApprovalUrl,
  vanaWebMcpScopeRequestApprovalUrl,
} from "./approval-url.js";

describe("buildMcpScopeRequestApprovalUrl", () => {
  it("links Vana Web to the request on this server by default", () => {
    expect(
      buildMcpScopeRequestApprovalUrl({
        connectionId: "conn-1",
        serverOrigin: "https://abc123.server.vana.org/",
      }),
    ).toBe(
      "https://app.vana.org/mcp/requests/conn-1?ps_origin=https%3A%2F%2Fabc123.server.vana.org",
    );
  });

  it("keeps only the server origin and escapes the connection id", () => {
    const url = new URL(
      buildMcpScopeRequestApprovalUrl({
        connectionId: "a/b c",
        serverOrigin: "https://ps.example.com:8443/some/path?x=1",
        webOrigin: "https://app-dev.vana.org/ignored",
      }) ?? "",
    );
    expect(url.origin).toBe("https://app-dev.vana.org");
    expect(url.pathname).toBe("/mcp/requests/a%2Fb%20c");
    expect(url.searchParams.get("ps_origin")).toBe(
      "https://ps.example.com:8443",
    );
  });

  it("carries the read token in the fragment, never the query", () => {
    const link =
      buildMcpScopeRequestApprovalUrl({
        connectionId: "conn-1",
        serverOrigin: "https://abc123.server.vana.org",
        readToken: "tok_abc-123",
      }) ?? "";
    expect(link).toBe(
      "https://app.vana.org/mcp/requests/conn-1?ps_origin=https%3A%2F%2Fabc123.server.vana.org#t=tok_abc-123",
    );
    const url = new URL(link);
    expect(new URLSearchParams(url.hash.slice(1)).get("t")).toBe("tok_abc-123");
    expect(url.search).not.toContain("tok_abc-123");
    expect(
      vanaWebMcpScopeRequestApprovalUrl()("conn-1", {
        serverOrigin: "https://abc123.server.vana.org",
        readToken: "tok_abc-123",
      }),
    ).toBe(link);
  });

  it("gives no link for a server the page cannot reach", () => {
    for (const serverOrigin of [
      undefined,
      "",
      "not a url",
      "ftp://ps.example.com",
      // Local-only server: app.vana.org (https) cannot fetch http, and a phone
      // cannot reach the laptop's loopback.
      "http://localhost:8080",
      "http://ps.example.com",
    ]) {
      expect(
        buildMcpScopeRequestApprovalUrl({ connectionId: "c", serverOrigin }),
      ).toBeUndefined();
    }
    expect(
      buildMcpScopeRequestApprovalUrl({
        connectionId: "",
        serverOrigin: "https://ps.example.com",
      }),
    ).toBeUndefined();
  });

  it("allows a loopback server only from a loopback web dev server", () => {
    expect(
      buildMcpScopeRequestApprovalUrl({
        connectionId: "c",
        serverOrigin: "http://127.0.0.1:8080",
        webOrigin: "http://localhost:3083",
      }),
    ).toBe(
      "http://localhost:3083/mcp/requests/c?ps_origin=http%3A%2F%2F127.0.0.1%3A8080",
    );
  });
});

describe("vanaWebMcpScopeRequestApprovalUrl", () => {
  it("builds the link from the origin the server reports at call time", () => {
    const hook = vanaWebMcpScopeRequestApprovalUrl({
      webOrigin: "https://app-dev.vana.org",
    });
    expect(hook("conn-9", { serverOrigin: "https://t.example.com" })).toBe(
      "https://app-dev.vana.org/mcp/requests/conn-9?ps_origin=https%3A%2F%2Ft.example.com",
    );
    expect(hook("conn-9", {})).toBeUndefined();
  });
});

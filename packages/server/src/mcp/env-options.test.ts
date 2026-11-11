import { describe, expect, it } from "vitest";
import { mcpOptionsFromEnv } from "./env-options.js";

describe("mcpOptionsFromEnv", () => {
  it("leaves every option unset when no variable is set", () => {
    expect(mcpOptionsFromEnv({})).toEqual({});
  });

  it("maps the flags only for the exact value 1", () => {
    expect(
      mcpOptionsFromEnv({
        VANA_MCP_EXPOSE_UNSHARED: "1",
        VANA_MCP_SCOPE_REQUEST_GUIDANCE: "1",
      }),
    ).toEqual({ mcpExposeUnsharedScopes: true, mcpScopeRequestGuidance: true });
    expect(
      mcpOptionsFromEnv({
        VANA_MCP_EXPOSE_UNSHARED: "true",
        VANA_MCP_SCOPE_REQUEST_GUIDANCE: "0",
      }),
    ).toEqual({});
  });

  it("builds the approval URL hook from the template", () => {
    const { mcpScopeRequestApprovalUrl } = mcpOptionsFromEnv({
      VANA_MCP_SCOPE_REQUEST_APPROVAL_URL_TEMPLATE:
        "vana://mcp-scope-request?connection={connectionId}#t={token}",
    });
    expect(mcpScopeRequestApprovalUrl?.("c 1", { readToken: "abc" })).toBe(
      "vana://mcp-scope-request?connection=c%201#t=abc",
    );
  });
});

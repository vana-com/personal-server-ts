import { describe, it, expect } from "vitest";
import { isAllowedOAuthRedirectUri } from "./oauth-redirect.js";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "./store.js";
import {
  createMcpOAuthAuthorization,
  McpOAuthAuthorizationError,
} from "./connection-api.js";

describe("isAllowedOAuthRedirectUri", () => {
  it.each([
    "https://claude.ai/api/mcp/auth_callback",
    "https://example.com/cb?x=1",
    "http://127.0.0.1:33418/callback",
    "http://127.1.2.3/cb",
    "http://localhost:6274/oauth/callback",
    "http://[::1]:8080/cb",
    "cursor://anysphere.cursor-retrieval/oauth/callback",
    "vscode://vscode.github-authentication/did-authenticate",
  ])("allows %s", (uri) => {
    expect(isAllowedOAuthRedirectUri(uri)).toBe(true);
  });

  it.each([
    "",
    "not a url",
    "/relative/callback",
    "http://example.com/cb",
    "http://localhost.example.com/cb",
    "http://127.0.0.1.example.com/cb",
    "https://claude.ai/cb#frag",
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    " javascript:alert(1)",
    "java\tscript:alert(1)",
    "data:text/html,hi",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
    "blob:https://example.com/uuid",
    "about:blank",
    "filesystem:https://example.com/temporary/x",
  ])("rejects %j", (uri) => {
    expect(isAllowedOAuthRedirectUri(uri)).toBe(false);
  });

  it("rejects non-string values", () => {
    expect(isAllowedOAuthRedirectUri(undefined)).toBe(false);
    expect(isAllowedOAuthRedirectUri(42)).toBe(false);
  });
});

describe("createMcpOAuthAuthorization redirect_uri validation", () => {
  it("rejects a disallowed redirect_uri before creating anything", async () => {
    const connectionStore = createInMemoryMcpConnectionStore();
    const authorizationStore = createInMemoryMcpOAuthAuthorizationStore();
    const attempt = createMcpOAuthAuthorization(
      {
        clientId: "client",
        redirectUri: "javascript:alert(1)",
        codeChallenge: "challenge",
        codeChallengeMethod: "S256",
      },
      { connectionStore, authorizationStore, publicOrigin: "https://ps.test" },
    );
    await expect(attempt).rejects.toBeInstanceOf(McpOAuthAuthorizationError);
    await expect(attempt).rejects.toMatchObject({ code: "invalid_request" });
    expect(await connectionStore.list()).toHaveLength(0);
  });
});

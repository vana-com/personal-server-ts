import {
  templateMcpScopeRequestApprovalUrl,
  type McpScopeRequestApprovalUrlHook,
} from "@opendatalabs/personal-server-ts-core/mcp";

export interface McpEnvOptions {
  mcpScopeRequestApprovalUrl?: McpScopeRequestApprovalUrlHook;
  mcpExposeUnsharedScopes?: boolean;
  mcpScopeRequestGuidance?: boolean;
  mcpOwnerAccessEdit?: boolean;
}

/**
 * MCP host options for the standalone entry. Every variable is optional and
 * unset leaves the option off:
 * - VANA_MCP_SCOPE_REQUEST_APPROVAL_URL_TEMPLATE, e.g.
 *   `vana://mcp-scope-request?connection={connectionId}#t={token}`
 * - VANA_MCP_EXPOSE_UNSHARED=1  (`notShared` on list_granted_scopes)
 * - VANA_MCP_SCOPE_REQUEST_GUIDANCE=1  (`nextAction` on scope_not_granted)
 * - VANA_MCP_OWNER_ACCESS_EDIT=1  (owner `PUT /v1/mcp/connections/:id/access`)
 */
export function mcpOptionsFromEnv(
  env: Record<string, string | undefined>,
): McpEnvOptions {
  const template = env.VANA_MCP_SCOPE_REQUEST_APPROVAL_URL_TEMPLATE?.trim();
  return {
    ...(template
      ? {
          mcpScopeRequestApprovalUrl:
            templateMcpScopeRequestApprovalUrl(template),
        }
      : {}),
    ...(env.VANA_MCP_EXPOSE_UNSHARED === "1"
      ? { mcpExposeUnsharedScopes: true }
      : {}),
    ...(env.VANA_MCP_SCOPE_REQUEST_GUIDANCE === "1"
      ? { mcpScopeRequestGuidance: true }
      : {}),
    ...(env.VANA_MCP_OWNER_ACCESS_EDIT === "1"
      ? { mcpOwnerAccessEdit: true }
      : {}),
  };
}

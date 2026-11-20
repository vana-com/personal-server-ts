import {
  templateMcpScopeRequestApprovalUrl,
  type McpScopeRequestApprovalUrlHook,
} from "@opendatalabs/personal-server-ts-core/mcp";

export interface McpEnvOptions {
  mcpScopeRequestApprovalUrl?: McpScopeRequestApprovalUrlHook;
  mcpExposeUnsharedScopes?: boolean;
  /** Allow the owner to narrow connection scopes; default off. */
  mcpOwnerAccessEdit?: boolean;
  mcpScopeRequestGuidance?: boolean;
}

/**
 * MCP host options for the standalone entry. Every variable is optional and
 * unset leaves the option off:
 * - VANA_MCP_SCOPE_REQUEST_APPROVAL_URL_TEMPLATE, e.g.
 *   `vana://mcp-scope-request?connection={connectionId}#t={token}`
 * - VANA_MCP_EXPOSE_UNSHARED=1  (`notShared` on list_granted_scopes)
 * - VANA_MCP_OWNER_ACCESS_EDIT=1 (owner can remove connection permissions)
 * - VANA_MCP_SCOPE_REQUEST_GUIDANCE=1  (`nextAction` on scope_not_granted)
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
    ...(env.VANA_MCP_OWNER_ACCESS_EDIT === "1"
      ? { mcpOwnerAccessEdit: true }
      : {}),
    ...(env.VANA_MCP_SCOPE_REQUEST_GUIDANCE === "1"
      ? { mcpScopeRequestGuidance: true }
      : {}),
  };
}

/**
 * Personal-Server-hosted MCP types.
 *
 * Phase 1 / 260604-PLAN-vana-mcp-personal-server.md §1–§3.
 *
 * An `McpConnectionRecord` represents one Claude (or other MCP client)
 * connection to a single user's Personal Server. Each connection has:
 *
 *  - a per-connection grantee keypair — the MCP route signs read requests
 *    as this grantee so the existing grant-gated `/v1/data` path treats MCP
 *    reads exactly like an external builder, and the access log records the
 *    grantee address (NOT the owner) for every MCP read.
 *
 *  - a high-entropy connection token — used as the OAuth access token Claude
 *    presents as `Authorization: Bearer ...` to the stable `/mcp` endpoint.
 *    The legacy `/mcp/<connectionToken>` URL path still resolves the same
 *    token for backward-compatible manual smokes. The store keeps only the
 *    SHA-256 hash so a leaked store dump can't be replayed.
 *
 *  - a set of grant ids minted during DCR-style consent. The MCP tools only
 *    expose scopes covered by these grants.
 */

export type McpConnectionStatus = "pending" | "approved" | "revoked";

export interface McpConnectionGrant {
  grantId: string;
  scopes: string[];
  sourceId?: string;
}

/**
 * Encrypted-at-rest grantee private key.
 *
 * For Web PS Lite this is wrapped with the same owner-derived master key
 * the runtime uses for its server identity. For server-side runtimes the
 * grantee key is stored in plaintext alongside the other keys on the
 * trusted host disk (same trust boundary as `loadOrCreateServerAccount`).
 */
export type McpEncryptedPrivateKey =
  | {
      kind: "plaintext";
      privateKey: `0x${string}`;
    }
  | {
      kind: "aes-gcm";
      iv: string;
      ciphertext: string;
    };

export interface McpConnectionRecord {
  id: string;
  displayName: string;
  granteeAddress: `0x${string}`;
  granteePublicKey: `0x${string}`;
  encryptedGranteePrivateKey: McpEncryptedPrivateKey;
  /** SHA-256 hex of the raw connection token. The raw token is only returned once on creation. */
  tokenHash: string;
  status: McpConnectionStatus;
  grants: McpConnectionGrant[];
  createdAt: string;
  approvedAt?: string;
  revokedAt?: string;
  lastUsedAt?: string;
}

export interface McpConnectionStore {
  create(record: McpConnectionRecord): Promise<void>;
  list(): Promise<McpConnectionRecord[]>;
  getById(id: string): Promise<McpConnectionRecord | null>;
  /**
   * Look up an *approved, non-revoked* connection by the SHA-256 hash of the
   * raw connection token presented in the URL. Returns null for unknown,
   * pending, or revoked tokens. Updates `lastUsedAt`.
   */
  getByTokenHash(tokenHash: string): Promise<McpConnectionRecord | null>;
  update(
    id: string,
    patch: Partial<
      Pick<
        McpConnectionRecord,
        | "status"
        | "grants"
        | "approvedAt"
        | "revokedAt"
        | "lastUsedAt"
        | "displayName"
        | "tokenHash"
      >
    >,
  ): Promise<McpConnectionRecord | null>;
}

export type McpOAuthAuthorizationStatus =
  | "pending"
  | "approved"
  | "redeemed"
  | "denied"
  | "expired";

export interface McpOAuthAuthorizationRecord {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  scope?: string;
  state?: string;
  connectionId: string;
  granteeAddress: `0x${string}`;
  status: McpOAuthAuthorizationStatus;
  createdAt: string;
  expiresAt: string;
  approvedAt?: string;
  authorizationCodeHash?: string;
  redeemedAt?: string;
}

export interface McpOAuthAuthorizationStore {
  create(record: McpOAuthAuthorizationRecord): Promise<void>;
  getById(id: string): Promise<McpOAuthAuthorizationRecord | null>;
  getByCodeHash(
    authorizationCodeHash: string,
  ): Promise<McpOAuthAuthorizationRecord | null>;
  update(
    id: string,
    patch: Partial<
      Pick<
        McpOAuthAuthorizationRecord,
        | "status"
        | "approvedAt"
        | "authorizationCodeHash"
        | "redeemedAt"
        | "expiresAt"
      >
    >,
  ): Promise<McpOAuthAuthorizationRecord | null>;
  delete(id: string): Promise<void>;
}

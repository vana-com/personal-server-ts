/**
 * MCP write client.
 *
 * The write twin of `read-client.ts`. An MCP tool that saves data (today only
 * `remember`) writes AS the per-connection grantee, through the exact path an
 * external builder's delegated write takes:
 *
 *  1. A short-lived write session for (grantee, grantId) is put into the SAME
 *     store `POST /v1/write/session` mints into, so the data route redeems it
 *     like any builder session. Its token never leaves this module.
 *  2. The grantee signs the per-write `X-Vana-Write-Signature` proof over the
 *     compact JSON body, exactly like a builder does.
 *  3. The request is dispatched to the mounted `POST /v1/data/:scope` route.
 *     Its auth port re-runs `verifyDataWritePolicy` against the LIVE grant
 *     (revocation, expiry, grantee and owner binding, `write:` scope
 *     coverage) and verifies the proof before anything is stored.
 *
 * So a `remember` write is policy-checked, `$writtenBy`-stamped,
 * access-logged and synced by the same code as a builder write. There is no
 * owner-mode shortcut: a request without a live write grant fails.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { DataStoragePort } from "../ports/index.js";
import { ProtocolError } from "../errors/catalog.js";
import {
  hashWriteSessionToken,
  type WriteSessionStore,
} from "../write/session.js";
import { WRITE_SIGNATURE_HEADER } from "../write/attribution.js";
import { signMcpGranteeRequest } from "./grantee.js";

/** The current stored record of a scope, as the write's starting point. */
export interface McpScopeWriteCurrent {
  /** The envelope `data` of the latest version; null when there is none. */
  data: Record<string, unknown> | null;
}

export interface McpScopeWriteResult {
  status: number;
  scope: string;
  collectedAt?: string;
  /** The record that was stored (what `update` returned). */
  data: Record<string, unknown>;
}

export interface McpDataWriteClient {
  /**
   * Read-modify-write one scope as the connection grantee. `update` receives
   * the latest stored record and returns the next one; the write is
   * conditional on that version, and a concurrent write makes the client
   * re-read and call `update` again (bounded retries). `update` may throw to
   * abort; its error propagates unchanged.
   */
  updateScope(params: {
    scope: string;
    grantId: string;
    update(current: McpScopeWriteCurrent): Record<string, unknown>;
  }): Promise<McpScopeWriteResult>;
}

export class McpDataWriteError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`MCP data write failed with status ${status}`);
    this.name = "McpDataWriteError";
  }
}

export interface CreateMcpDataWriteClientOptions {
  serverOrigin: string;
  granteeAccount: ServerAccount;
  /** Reads the latest stored record each read-modify-write starts from. */
  storage: Pick<DataStoragePort, "findEntry" | "readEnvelope">;
  /** The store the data route redeems write sessions from. */
  sessionStore: WriteSessionStore;
  /** Sends a request to the mounted data route (`POST {basePath}/:scope`). */
  dispatch(request: Request): Promise<Response>;
  /** Where the data route is mounted. Defaults to `/v1/data`. */
  basePath?: string;
  /**
   * Runs the live write policy for (grantee, grantId, scope) BEFORE the
   * current record is read, so a caller whose grant was revoked learns
   * nothing about the scope from `update`'s refusals. Throws a ProtocolError
   * to refuse. The data route runs the same policy again on the write.
   */
  authorize(params: { scope: string; grantId: string }): Promise<void>;
  /** Attempts before a write that keeps losing a version race gives up. */
  maxAttempts?: number;
}

const DEFAULT_MAX_ATTEMPTS = 3;
/** Long enough for one write; nothing outside this module holds the token. */
const SESSION_TTL_MS = 30_000;
/** Server-stamped keys that are never part of what the grantee signs. */
const STAMPED_KEYS = new Set(["$writtenBy", "$lineage"]);

function randomSessionToken(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return `vana_mcp_write_${Array.from(bytes, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function withoutStampedKeys(
  data: Record<string, unknown>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(data).filter(([key]) => !STAMPED_KEYS.has(key)),
  );
}

async function parseJsonOrText(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}

export function createMcpDataWriteClient(
  options: CreateMcpDataWriteClientOptions,
): McpDataWriteClient {
  const basePath = options.basePath ?? "/v1/data";
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const storage = options.storage;

  async function readCurrent(scope: string): Promise<{
    current: McpScopeWriteCurrent;
    version?: number;
  }> {
    const entry = storage.findEntry({ scope });
    if (!entry) return { current: { data: null } };
    const envelope = await storage.readEnvelope(scope, entry.collectedAt);
    return {
      current: { data: withoutStampedKeys(envelope.data) },
      version: entry.casRevision ?? entry.version,
    };
  }

  async function writeOnce(params: {
    scope: string;
    grantId: string;
    data: Record<string, unknown>;
    version?: number;
  }): Promise<Response> {
    const token = randomSessionToken();
    await options.sessionStore.create({
      tokenHash: await hashWriteSessionToken(token),
      builderAddress: options.granteeAccount.address,
      grantId: params.grantId,
      writeScopes: [params.scope],
      createdAt: new Date().toISOString(),
      expiresAtMs: Date.now() + SESSION_TTL_MS,
    });

    const uri = `${basePath}/${encodeURIComponent(params.scope)}`;
    const body = new TextEncoder().encode(JSON.stringify(params.data));
    const proof = await signMcpGranteeRequest({
      account: options.granteeAccount,
      aud: options.serverOrigin,
      method: "POST",
      uri,
      body,
      grantId: params.grantId,
    });
    return options.dispatch(
      new Request(new URL(uri, options.serverOrigin), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          [WRITE_SIGNATURE_HEADER]: proof,
          // Conditional on the version update() saw, so a concurrent write is
          // never silently overwritten.
          ...(params.version === undefined
            ? { "If-None-Match": "*" }
            : { "If-Match": `"${params.version}"` }),
        },
        body,
      }),
    );
  }

  return {
    async updateScope({ scope, grantId, update }) {
      try {
        await options.authorize({ scope, grantId });
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw new McpDataWriteError(err.code, err.toJSON());
        }
        throw err;
      }
      for (let attempt = 1; ; attempt += 1) {
        const { current, version } = await readCurrent(scope);
        const data = update(current);
        const response = await writeOnce({ scope, grantId, data, version });
        if (response.ok) {
          const body = (await parseJsonOrText(response)) as {
            collectedAt?: string;
          } | null;
          return {
            status: response.status,
            scope,
            ...(body?.collectedAt ? { collectedAt: body.collectedAt } : {}),
            data,
          };
        }
        // 412: another write landed between our read and our write. Re-read
        // and re-apply so nothing that write stored is lost.
        if (response.status === 412 && attempt < maxAttempts) continue;
        throw new McpDataWriteError(
          response.status,
          await parseJsonOrText(response),
        );
      }
    },
  };
}

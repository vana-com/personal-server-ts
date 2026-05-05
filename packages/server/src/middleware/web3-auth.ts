import { timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";
import {
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/personal-server-ts-core/auth";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { TokenStore } from "../token-store.js";

export type AuthMechanism =
  | "web3-signed"
  | "dev-token"
  | "control-plane-token"
  | "cli-session-token"
  | "vana-session";

export interface RequestAuth {
  signer: `0x${string}`;
  payload: Partial<Web3SignedPayload>;
}

export interface Web3AuthMiddlewareDeps {
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  serverOwner?: `0x${string}`;
  /**
   * URL of the account.vana.org-hosted OAuth introspection proxy used to
   * verify Vana session access tokens. Example:
   *   https://account-dev.vana.org/api/oauth/introspect
   *
   * The proxy returns RFC 7662 fields plus `linked_wallets[]` for the user.
   * PS validates the token's `aud` includes its own URL, then sets
   * auth.signer to the user's primary linked wallet address.
   *
   * If unset, the vana-session mechanism is disabled.
   */
  vanaIntrospectionUrl?: string;
  /**
   * Optional public URL of this PS, used to validate the access token's
   * `aud`. Defaults to deps.serverOrigin if it's a string. Required for
   * the vana-session mechanism to gate audience correctly.
   */
  serverPublicUrl?: string;
}

// In-process cache for vana-session introspection. Keyed by sha256(token);
// 30s TTL mirrors account.vana.org's getVanaSession cache. PS deployments
// are single-process per user, so an in-memory cache is fine.
type IntrospectionCacheEntry = {
  result: VanaIntrospectionResult;
  cachedAt: number;
};
const introspectionCache = new Map<string, IntrospectionCacheEntry>();
const INTROSPECTION_CACHE_TTL_MS = 30_000;
const INTROSPECTION_CACHE_MAX = 1_000;

interface VanaIntrospectionResult {
  active: boolean;
  sub?: string;
  aud?: string[] | string;
  exp?: number;
  scope?: string;
  client_id?: string;
  token_use?: string;
  linked_wallets?: Array<{
    vana_wallet_id: string;
    address: string;
    chain_type: string;
    is_primary: boolean;
  }>;
}

function pruneCache(): void {
  if (introspectionCache.size <= INTROSPECTION_CACHE_MAX) return;
  const target = Math.floor(INTROSPECTION_CACHE_MAX * 0.9);
  let toRemove = introspectionCache.size - target;
  for (const key of introspectionCache.keys()) {
    if (toRemove-- <= 0) break;
    introspectionCache.delete(key);
  }
}

/**
 * Constant-time comparison of two strings.
 * Returns false if either string is empty or they differ in length.
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length === 0 || b.length === 0) return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function createOwnerSessionAuth(serverOwner: `0x${string}`): RequestAuth {
  return {
    signer: serverOwner,
    // Bearer/session tokens authenticate the owner but do not carry Web3Signed claims.
    payload: {},
  };
}

/**
 * Parses + verifies Web3Signed Authorization header.
 * Sets c.set('auth', VerifiedAuth) for downstream handlers.
 *
 * When a devToken is configured and the request carries a matching
 * Bearer token, auth context is populated with the server owner
 * and c.set('devBypass', true) is set to skip downstream checks.
 *
 * When a control-plane token (PS_ACCESS_TOKEN) or tokenStore-issued CLI token is
 * configured and the request carries a matching Bearer token, auth context
 * is populated with the server owner. These are owner-authenticated requests,
 * not dev-bypass requests.
 */
export function createWeb3AuthMiddleware(
  depsOrOrigin: Web3AuthMiddlewareDeps | string,
): MiddlewareHandler {
  const deps: Web3AuthMiddlewareDeps =
    typeof depsOrOrigin === "string"
      ? { serverOrigin: depsOrOrigin }
      : depsOrOrigin;

  return async (c, next) => {
    const authHeader = c.req.header("authorization");

    // Dev token bypass: if configured and header matches, skip Web3Signed verification
    if (deps.devToken && authHeader === `Bearer ${deps.devToken}`) {
      if (!deps.serverOwner) {
        return c.json(
          {
            error: {
              code: 500,
              errorCode: "SERVER_NOT_CONFIGURED",
              message:
                "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
            },
          },
          500,
        );
      }
      c.set("auth", createOwnerSessionAuth(deps.serverOwner));
      c.set("authMechanism", "dev-token" satisfies AuthMechanism);
      c.set("isPolicyBypass", true);
      c.set("devBypass", true);
      await next();
      return;
    }

    // Control-plane token: long-lived hosted credential used for session brokerage.
    if (deps.accessToken && authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      if (safeCompare(token, deps.accessToken)) {
        if (!deps.serverOwner) {
          return c.json(
            {
              error: {
                code: 500,
                errorCode: "SERVER_NOT_CONFIGURED",
                message:
                  "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
              },
            },
            500,
          );
        }
        c.set("auth", createOwnerSessionAuth(deps.serverOwner));
        c.set("authMechanism", "control-plane-token" satisfies AuthMechanism);
        c.set("isPolicyBypass", false);
        c.set("devBypass", false);
        await next();
        return;
      }
    }

    // Vana session: opaque access token issued by Hydra (via
    // account.vana.org). Verified by calling the account.vana.org-hosted
    // /api/oauth/introspect proxy, which forwards to Hydra admin and
    // enriches the response with linked_wallets[]. PS validates the
    // token's `aud` includes its own URL, then resolves the user's
    // primary EVM wallet as auth.signer.
    //
    // See docs/auth-redesign/01-architecture.md §1.9 (vana-connect repo).
    if (deps.vanaIntrospectionUrl && authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      const result = await introspectVanaSession(
        token,
        deps.vanaIntrospectionUrl,
      );
      if (result?.active) {
        const expectedAudience =
          deps.serverPublicUrl ??
          (typeof deps.serverOrigin === "string"
            ? deps.serverOrigin
            : undefined);
        const audArr = Array.isArray(result.aud)
          ? result.aud
          : result.aud
            ? [result.aud]
            : [];
        if (!expectedAudience || audArr.includes(expectedAudience)) {
          const primary =
            result.linked_wallets?.find(
              (w: { is_primary: boolean }) => w.is_primary,
            ) ?? result.linked_wallets?.[0];
          if (primary?.address) {
            c.set(
              "auth",
              createOwnerSessionAuth(primary.address as `0x${string}`),
            );
            c.set("authMechanism", "vana-session" satisfies AuthMechanism);
            c.set("isPolicyBypass", false);
            c.set("devBypass", false);
            await next();
            return;
          }
        }
      }
    }

    // Token store: tokens generated via /auth/device flow
    if (deps.tokenStore && authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      if (await deps.tokenStore.isValid(token)) {
        if (!deps.serverOwner) {
          return c.json(
            {
              error: {
                code: 500,
                errorCode: "SERVER_NOT_CONFIGURED",
                message:
                  "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
              },
            },
            500,
          );
        }
        c.set("auth", createOwnerSessionAuth(deps.serverOwner));
        c.set("authMechanism", "cli-session-token" satisfies AuthMechanism);
        c.set("isPolicyBypass", false);
        c.set("devBypass", false);
        await next();
        return;
      }
    }

    try {
      const auth = await verifyWeb3Signed({
        headerValue: authHeader,
        expectedOrigin:
          typeof deps.serverOrigin === "function"
            ? deps.serverOrigin()
            : deps.serverOrigin,
        expectedMethod: c.req.method,
        expectedPath: new URL(c.req.url).pathname,
      });

      c.set("auth", auth);
      c.set("authMechanism", "web3-signed" satisfies AuthMechanism);
      c.set("isPolicyBypass", false);
      c.set("devBypass", false);
      await next();
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 403);
      }
      throw err;
    }
  };
}

/**
 * POST the access token to account.vana.org's introspection proxy.
 * Returns null on network failure or non-2xx (treated as inactive).
 * 30s in-process cache.
 */
async function introspectVanaSession(
  token: string,
  introspectUrl: string,
): Promise<VanaIntrospectionResult | null> {
  const { createHash } = await import("node:crypto");
  const key = createHash("sha256").update(token, "utf8").digest("hex");
  const now = Date.now();
  const cached = introspectionCache.get(key);
  if (cached && now - cached.cachedAt < INTROSPECTION_CACHE_TTL_MS) {
    return cached.result;
  }
  if (cached) introspectionCache.delete(key);

  let response: Response;
  try {
    response = await fetch(introspectUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ token }),
    });
  } catch {
    return null;
  }
  if (!response.ok) {
    // Cache negative result briefly to avoid hammering account.vana.org on
    // a known-bad token.
    const negative: VanaIntrospectionResult = { active: false };
    introspectionCache.set(key, { result: negative, cachedAt: now });
    pruneCache();
    return negative;
  }
  const result = (await response.json()) as VanaIntrospectionResult;
  introspectionCache.set(key, { result, cachedAt: now });
  pruneCache();
  return result;
}

/** Test-only: clear the cache between tests. */
export function __clearVanaIntrospectionCacheForTests(): void {
  introspectionCache.clear();
}

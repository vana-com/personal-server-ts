/**
 * Bounded SourceDeclaration retrieval (§5 declaration acceptance, §10
 * declaration retrieval hygiene).
 *
 * An AS that fetches a client-supplied URL is an SSRF engine unless it is
 * fenced. The rules here are the fence: HTTPS only, no private or loopback or
 * link-local address literals, a bounded redirect chain that is re-checked at
 * every hop, a response size cap, and a timeout. Each redirect is validated
 * again because a public hostname resolving to a public IP can redirect to
 * `http://169.254.169.254/` and a one-shot check at the start would miss it.
 *
 * What this module deliberately does NOT do is decide whether a declaration is
 * *trusted*. That is deployment policy (`DeclarationTrustPolicy`), applied
 * explicitly by the caller, because "we fetched it safely" and "we accept its
 * authority over this source" are different questions.
 */

import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { DeclarationSnapshot, SourceKind } from "./types.js";

export const MAX_DECLARATION_BYTES = 256 * 1024;
export const MAX_REDIRECTS = 3;
export const DECLARATION_FETCH_TIMEOUT_MS = 5_000;

export type DeclarationFailureCode =
  | "insecure_scheme"
  | "private_address"
  | "too_many_redirects"
  | "too_large"
  | "fetch_failed"
  | "invalid_document"
  | "digest_mismatch"
  | "source_id_mismatch"
  | "untrusted_source"
  | "unsupported_version";

export interface DeclarationFailure {
  code: DeclarationFailureCode;
  message: string;
}

export type DeclarationResult =
  | { ok: true; snapshot: DeclarationSnapshot }
  | { ok: false; failure: DeclarationFailure };

/**
 * Explicit deployment trust policy. §1 of the delivery scope requires the AS to
 * apply an *explicit* policy rather than trusting whatever it can reach.
 */
export interface DeclarationTrustPolicy {
  /**
   * Hosts whose declarations this deployment accepts. An empty list with
   * `allowAnyHttpsHost: false` accepts nothing, which is the safe default for
   * a deployment that has not configured trust yet.
   */
  trustedHosts?: string[];
  /** Opt in to accepting any HTTPS-reachable declaration host. */
  allowAnyHttpsHost?: boolean;
  /**
   * Permit plain HTTP and private addresses. Test and loopback-development
   * only — never in a deployment reachable from a network.
   */
  allowInsecureForTesting?: boolean;
}

/**
 * Private, loopback, link-local, and unique-local ranges. Checked against
 * address *literals* in the URL. A hostname that resolves into these ranges is
 * a DNS-rebinding concern the fetch layer must also handle; we reject the
 * literal form here and keep the redirect chain bounded so a rebind has a much
 * smaller window to work in.
 */
function isPrivateAddressLiteral(host: string): boolean {
  const bare =
    host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

  const version = isIP(bare);
  if (version === 4) {
    const parts = bare.split(".").map(Number);
    const [a, b] = parts;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 — link-local, and the cloud metadata endpoint.
    if (a === 169 && b === 254) return true;
    return false;
  }
  if (version === 6) {
    const lower = bare.toLowerCase();
    if (lower === "::1" || lower === "::") return true;
    // fc00::/7 unique-local, fe80::/10 link-local.
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    if (lower.startsWith("fe8") || lower.startsWith("fe9")) return true;
    if (lower.startsWith("fea") || lower.startsWith("feb")) return true;
    return false;
  }

  // Not a literal. Hostname forms that always mean "this machine".
  const lowerHost = bare.toLowerCase();
  return lowerHost === "localhost" || lowerHost.endsWith(".localhost");
}

/** Validate one URL in the chain. Applied to the origin URL and every hop. */
export function checkDeclarationUrl(
  raw: string,
  policy: DeclarationTrustPolicy,
): DeclarationFailure | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return {
      code: "fetch_failed",
      message: `malformed declaration URL: ${raw}`,
    };
  }

  if (url.protocol !== "https:" && !policy.allowInsecureForTesting) {
    return {
      code: "insecure_scheme",
      message: `declaration URL must use https, got ${url.protocol}`,
    };
  }

  if (
    isPrivateAddressLiteral(url.hostname) &&
    !policy.allowInsecureForTesting
  ) {
    return {
      code: "private_address",
      message: `declaration URL resolves to a private or loopback address: ${url.hostname}`,
    };
  }

  if (!policy.allowAnyHttpsHost) {
    const trusted = policy.trustedHosts ?? [];
    if (!trusted.includes(url.hostname)) {
      return {
        code: "untrusted_source",
        message: `declaration host '${url.hostname}' is not in this deployment's declaration trust policy`,
      };
    }
  }

  return null;
}

export function computeDeclarationDigest(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

interface RawDeclarationDocument {
  source_id?: unknown;
  source_kind?: unknown;
  version?: unknown;
  streams?: unknown;
  views?: unknown;
  selection_presets?: unknown;
}

/**
 * Parse and structurally validate a declaration document.
 *
 * Validates the embedded stream schemas enough that resolution can rely on
 * them: every stream needs a name, a field list, and a primary key, and its
 * `required_fields` must be a subset of its declared fields — otherwise the
 * per-stream consent floor would name fields the schema does not have.
 */
export function parseDeclaration(
  body: string,
  expectedSourceId: string,
  expectedDigest?: string,
): DeclarationResult {
  const digest = computeDeclarationDigest(body);
  if (expectedDigest !== undefined && digest !== expectedDigest) {
    return {
      ok: false,
      failure: {
        code: "digest_mismatch",
        message: "declaration digest does not match the expected value",
      },
    };
  }

  let doc: RawDeclarationDocument;
  try {
    doc = JSON.parse(body) as RawDeclarationDocument;
  } catch {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "declaration is not valid JSON",
      },
    };
  }

  if (typeof doc.source_id !== "string" || doc.source_id.length === 0) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "declaration is missing source_id",
      },
    };
  }

  // The declaration must claim the source we asked about. Without this check a
  // trusted host could serve an authority for a source it does not own.
  if (doc.source_id !== expectedSourceId) {
    return {
      ok: false,
      failure: {
        code: "source_id_mismatch",
        message: `declaration declares source_id '${doc.source_id}' but was retrieved for '${expectedSourceId}'`,
      },
    };
  }

  if (
    doc.source_kind !== "connector" &&
    doc.source_kind !== "provider_native"
  ) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "declaration source_kind must be connector or provider_native",
      },
    };
  }

  if (typeof doc.version !== "string" || doc.version.length === 0) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "declaration is missing version",
      },
    };
  }

  if (!Array.isArray(doc.streams) || doc.streams.length === 0) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "declaration declares no streams",
      },
    };
  }

  const streams = [];
  const seenStreams = new Set<string>();
  for (const raw of doc.streams) {
    const s = raw as Record<string, unknown>;
    if (typeof s.name !== "string" || s.name.length === 0) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: "a declared stream is missing name",
        },
      };
    }
    if (seenStreams.has(s.name)) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: `stream '${s.name}' is declared more than once`,
        },
      };
    }
    seenStreams.add(s.name);

    if (!Array.isArray(s.fields) || s.fields.length === 0) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: `stream '${s.name}' declares no fields`,
        },
      };
    }
    const fields = s.fields as string[];
    const requiredFields = Array.isArray(s.required_fields)
      ? (s.required_fields as string[])
      : [];
    const missing = requiredFields.filter((f) => !fields.includes(f));
    if (missing.length > 0) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: `stream '${s.name}' marks fields required that its schema does not declare: ${missing.join(", ")}`,
        },
      };
    }
    if (!Array.isArray(s.primary_key) || s.primary_key.length === 0) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: `stream '${s.name}' declares no primary_key`,
        },
      };
    }

    streams.push({
      name: s.name,
      fields,
      required_fields: requiredFields,
      ...(typeof s.consent_time_field === "string" && {
        consent_time_field: s.consent_time_field,
      }),
      primary_key: s.primary_key as string[],
    });
  }

  // §6: a preset naming the same stream twice makes the declaration invalid.
  // That is a declaration-acceptance failure, not deferred to issuance.
  const presets = Array.isArray(doc.selection_presets)
    ? (doc.selection_presets as Array<{
        name: string;
        streams: Array<{ name: string }>;
      }>)
    : undefined;
  if (presets) {
    for (const preset of presets) {
      const seen = new Set<string>();
      for (const stream of preset.streams ?? []) {
        if (seen.has(stream.name)) {
          return {
            ok: false,
            failure: {
              code: "invalid_document",
              message: `selection preset '${preset.name}' names stream '${stream.name}' more than once`,
            },
          };
        }
        seen.add(stream.name);
      }
    }
  }

  return {
    ok: true,
    snapshot: {
      source_id: doc.source_id,
      source_kind: doc.source_kind as SourceKind,
      version: doc.version,
      digest,
      streams,
      ...(Array.isArray(doc.views) && {
        views: doc.views as DeclarationSnapshot["views"],
      }),
      ...(presets && {
        selection_presets: presets as DeclarationSnapshot["selection_presets"],
      }),
    },
  };
}

/** Injected so tests exercise the bounds without real network access. */
export type DeclarationFetcher = (
  url: string,
  init: { redirect: "manual"; signal: AbortSignal },
) => Promise<Response>;

/**
 * Retrieve one declaration under the bounded rules, then parse and digest it.
 *
 * Redirects are followed manually so each hop can be re-validated. This is the
 * difference between a fence and a formality: `fetch`'s automatic redirect
 * following would validate only the URL we started with.
 */
export async function retrieveDeclaration(
  url: string,
  expectedSourceId: string,
  policy: DeclarationTrustPolicy,
  options: { fetcher?: DeclarationFetcher; expectedDigest?: string } = {},
): Promise<DeclarationResult> {
  const fetcher = options.fetcher ?? ((u, init) => fetch(u, init));

  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const problem = checkDeclarationUrl(current, policy);
    if (problem) return { ok: false, failure: problem };

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      DECLARATION_FETCH_TIMEOUT_MS,
    );

    let response: Response;
    try {
      response = await fetcher(current, {
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      return {
        ok: false,
        failure: {
          code: "fetch_failed",
          message: `declaration retrieval failed: ${(err as Error).message}`,
        },
      };
    } finally {
      clearTimeout(timer);
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        return {
          ok: false,
          failure: {
            code: "fetch_failed",
            message: "redirect response carried no Location header",
          },
        };
      }
      // Resolve relative redirects against the current URL, then re-check.
      current = new URL(location, current).toString();
      continue;
    }

    if (!response.ok) {
      return {
        ok: false,
        failure: {
          code: "fetch_failed",
          message: `declaration retrieval returned HTTP ${response.status}`,
        },
      };
    }

    const declaredLength = response.headers.get("content-length");
    if (declaredLength && Number(declaredLength) > MAX_DECLARATION_BYTES) {
      return {
        ok: false,
        failure: {
          code: "too_large",
          message: `declaration exceeds ${MAX_DECLARATION_BYTES} bytes`,
        },
      };
    }

    const body = await response.text();
    // Check the actual body too: Content-Length may be absent or lying.
    if (Buffer.byteLength(body, "utf8") > MAX_DECLARATION_BYTES) {
      return {
        ok: false,
        failure: {
          code: "too_large",
          message: `declaration exceeds ${MAX_DECLARATION_BYTES} bytes`,
        },
      };
    }

    return parseDeclaration(body, expectedSourceId, options.expectedDigest);
  }

  return {
    ok: false,
    failure: {
      code: "too_many_redirects",
      message: `declaration retrieval exceeded ${MAX_REDIRECTS} redirects`,
    },
  };
}

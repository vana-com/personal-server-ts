import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { PdppAuthorizationUnavailableError } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { resolveLocalInstance } from "@opendatalabs/personal-server-ts-core/replication/identity";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { z } from "zod";

export interface ReplicaGrantConnection {
  owner: string;
  sourceId: string;
  connectionId: string;
  issuerInstanceId: string;
  localInstanceId: string;
}

export type ReplicaAuthorizationReason =
  | "issuer_inactive"
  | "token_kind"
  | "owner_mismatch"
  | "grant_mismatch"
  | "expired"
  | "mapping_missing"
  | "mapping_ambiguous"
  | "mapping_invalid"
  | "mapping_collapsed"
  | "credential_unavailable"
  | "issuer_unavailable"
  | "invalid_response";

const nonempty = z.string().min(1);
const date = nonempty.refine((value) => Number.isFinite(Date.parse(value)));
const uniqueNames = z
  .array(nonempty)
  .min(1)
  .refine((values) => new Set(values).size === values.length);
const stream = z
  .object({
    name: nonempty,
    instance_ids: uniqueNames,
    fields: uniqueNames,
    resources: z.array(nonempty).optional(),
    time_constraint: z
      .object({
        field: nonempty,
        since: date.optional(),
        until: date.optional(),
      })
      .strict()
      .optional(),
  })
  .strict();
// Locked PDPP Core v0.1.0 stream rows (spec-core §7): the frozen time type,
// and the optional frozen sort field. Kept separate from the v0.2 row so a
// v0.2 grant still cannot carry members its revision does not define.
const lockedStream = z
  .object({
    name: nonempty,
    instance_ids: uniqueNames,
    fields: uniqueNames,
    resources: z.array(nonempty).optional(),
    // AS item 51: every locked stream row carries the frozen floor, possibly
    // empty. Its absence marks a pre-lock 0.1.0 grant, which stays refused.
    required_fields: z.array(nonempty),
    sort_field: nonempty.optional(),
    time_constraint: z
      .object({
        type: z.enum(["date", "date-time"]),
        field: nonempty,
        since: date.optional(),
        until: date.optional(),
      })
      .strict()
      .optional(),
  })
  .strict();
function grantShape(
  version: string,
  streamShape: typeof stream | typeof lockedStream,
) {
  return z
    .object({
      version: z.literal(version),
      grant_id: nonempty,
      issued_at: date,
      subject: z.object({ id: nonempty }),
      client: z.object({ client_id: nonempty }).passthrough(),
      source: z.object({
        kind: z.enum(["connector", "provider_native"]),
        id: nonempty,
      }),
      source_declaration: z.object({ version: nonempty }),
      purpose_code: nonempty,
      access_mode: z.enum(["single_use", "continuous"]),
      streams: z
        .array(streamShape)
        .min(1)
        .refine(
          (streams) =>
            new Set(streams.map((entry) => entry.name)).size === streams.length,
        ),
      expires_at: date.optional(),
    })
    .passthrough();
}
// This adapter accepts the complete frozen grant: the v0.2 grant, or the
// locked v0.1.0 grant (AS item 32: `{ type, grant }` with the complete
// immutable grant). The pre-lock v0.1 wire projection omits retained facts;
// inventing them here would create authority, so it stays refused.
const introspection = z.object({
  active: z.literal(true),
  pdpp_token_kind: z.literal("client"),
  subject_id: nonempty,
  grant_id: nonempty,
  client_id: nonempty,
  exp: z.number().int().positive(),
  authorization_details: z.tuple([
    z.union([
      z.object({
        type: z.literal(PDPP_DATA_ACCESS_TYPE_V02),
        grant: grantShape("0.2.0", stream),
      }),
      z.object({
        type: z.literal(PDPP_DATA_ACCESS_TYPE),
        grant: grantShape(PDPP_GRANT_VERSION, lockedStream),
      }),
    ]),
  ]),
  // spec-core §8 (L2002-L2014): RS-only handle → stored-instance bindings.
  pdpp_instance_bindings: z
    .array(
      z
        .object({
          source_id: nonempty,
          stream: nonempty.optional(),
          instance_id: nonempty,
          rs_instance: nonempty,
        })
        .strict(),
    )
    .optional(),
});

async function readContext(response: Response): Promise<unknown> {
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new PdppAuthorizationUnavailableError();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 1024 * 1024) throw new PdppAuthorizationUnavailableError();
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

/**
 * Replica read authority stays at one configured issuer, with no positive cache.
 * The host provisions a source-scoped issuer owner token for the existing
 * authenticated introspection endpoint; it is never accepted as an app token.
 * This harness-only credential has owner read authority. See the issuer's
 * acknowledged separated-RS credential gap in pdpp-auth.ts (RFC 7662 route).
 * No credential, grant, token, or revocation state is imported with records.
 * This is explicit experimental host wiring, not ordinary bootstrap wiring.
 * Inactive RFC 7662 results conceal revocation reasons and yield 401; the
 * co-located issuer can distinguish grant_revoked and returns 401 grant_revoked instead.
 * The returned grant is a translated local enforcement view. Its grant_id
 * identifies the immutable issuer grant; never hash this view as consent.
 */
export function createReplicaAuthorizationService(options: {
  issuerOrigin: string;
  owner: string;
  credential: () => Promise<string>;
  connections: () => readonly ReplicaGrantConnection[];
  fetch?: typeof fetch;
  now?: () => number;
  onDecision?: (event: {
    outcome: "denied" | "unavailable";
    reason: ReplicaAuthorizationReason;
  }) => void;
}): PdppAuthorizationService {
  if (!options.owner) throw new Error("Replica owner is required");
  const issuer = new URL(options.issuerOrigin);
  if (
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash ||
    issuer.pathname !== "/" ||
    (issuer.protocol !== "https:" &&
      !(
        issuer.protocol === "http:" &&
        ["127.0.0.1", "[::1]"].includes(issuer.hostname)
      ))
  ) {
    throw new Error(
      "Replica issuer must be an HTTPS origin or loopback HTTP origin",
    );
  }
  const fetcher = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const denied = (reason: ReplicaAuthorizationReason) => {
    options.onDecision?.({ outcome: "denied", reason });
    return { active: false as const };
  };
  const unavailable = (reason: ReplicaAuthorizationReason): never => {
    options.onDecision?.({ outcome: "unavailable", reason });
    throw new PdppAuthorizationUnavailableError();
  };
  return {
    async resolveToken(accessToken) {
      if (!accessToken) return denied("issuer_inactive");
      let credential: string;
      try {
        credential = await options.credential();
      } catch {
        return unavailable("credential_unavailable");
      }
      if (!credential) return unavailable("credential_unavailable");
      let wire: unknown;
      try {
        const response = await fetcher(`${issuer.origin}/pdpp/v1/introspect`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${credential}`,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({ token: accessToken }),
          redirect: "error",
          cache: "no-store",
          signal: AbortSignal.timeout(10_000),
        });
        wire = await readContext(response);
      } catch {
        return unavailable("issuer_unavailable");
      }
      if (
        z
          .object({ active: z.literal(false) })
          .strict()
          .safeParse(wire).success
      )
        return denied("issuer_inactive");
      if (
        z
          .object({
            active: z.literal(true),
            pdpp_token_kind: z.literal("owner"),
          })
          .safeParse(wire).success
      )
        return denied("token_kind");
      const parsed = introspection.safeParse(wire);
      if (!parsed.success) return unavailable("invalid_response");
      const context = parsed.data;
      const grant = context.authorization_details[0].grant;
      // The introspection `subject_id` is the internal subject the RS
      // enforces against. A locked v0.1.0 grant's `subject.id` is the
      // client's pairwise identifier (AS item 29), so only a v0.2 grant,
      // whose `subject.id` is the subject itself, is compared to the owner.
      // A v0.2 grant issued before pairwise ids carries the subject itself
      // and is compared; one issued since carries a `pws_` pairwise id.
      if (
        context.subject_id !== options.owner ||
        (grant.version === "0.2.0" &&
          !grant.subject.id.startsWith("pws_") &&
          grant.subject.id !== options.owner)
      )
        return denied("owner_mismatch");
      if (
        grant.grant_id !== context.grant_id ||
        grant.client.client_id !== context.client_id
      )
        return denied("grant_mismatch");
      const currentTime = now();
      if (
        context.exp * 1000 <= currentTime ||
        (grant.expires_at && Date.parse(grant.expires_at) <= currentTime)
      )
        return denied("expired");
      const mappings = options.connections();
      let mappingFailure: ReplicaAuthorizationReason | undefined;
      // A separated RS resolves each handle only through
      // `pdpp_instance_bindings` (spec-core L2014): handle → the issuer's
      // stored instance → this replica's local instance. A locked grant
      // without a binding for a handle fails closed; every entry for one
      // (source, handle) must name one instance, and no handle may appear
      // under two sources (L2004).
      const bindings = context.pdpp_instance_bindings;
      const locked = grant.version === PDPP_GRANT_VERSION;
      if (bindings) {
        const bySourceHandle = new Map<string, string>();
        const sourceOfHandle = new Map<string, string>();
        for (const b of bindings) {
          const key = `${b.source_id}\u0000${b.instance_id}`;
          const prior = bySourceHandle.get(key);
          if (prior !== undefined && prior !== b.rs_instance)
            return denied("mapping_ambiguous");
          bySourceHandle.set(key, b.rs_instance);
          const source = sourceOfHandle.get(b.instance_id);
          if (source !== undefined && source !== b.source_id)
            return denied("mapping_ambiguous");
          sourceOfHandle.set(b.instance_id, b.source_id);
        }
      } else if (locked) {
        return denied("mapping_missing");
      }
      const issuerInstanceFor = (streamName: string, handle: string) => {
        if (!bindings) return handle;
        const entry = bindings.find(
          (b) =>
            b.source_id === grant.source.id &&
            b.instance_id === handle &&
            (b.stream === undefined || b.stream === streamName),
        );
        return entry?.rs_instance;
      };
      // local instance → the handle the client holds, for responses.
      const clientInstanceHandles: Record<string, string> = {};
      const streams = grant.streams.map((stream) => ({
        ...stream,
        instance_ids: stream.instance_ids.map((handle) => {
          const issuerInstance = issuerInstanceFor(stream.name, handle);
          if (issuerInstance === undefined) {
            mappingFailure = "mapping_missing";
            return "";
          }
          const local = localFor(issuerInstance);
          if (local) clientInstanceHandles[local] = handle;
          return local ?? "";
        }),
      }));
      function localFor(issuerInstance: string): string | undefined {
        {
          const handle = issuerInstance;
          const matches = mappings.filter(
            (entry) =>
              entry.issuerInstanceId === handle &&
              entry.owner === options.owner &&
              entry.sourceId === grant.source.id,
          );
          const identities = new Set(
            matches.map((entry) => entry.connectionId),
          );
          if (identities.size !== 1) {
            mappingFailure =
              identities.size === 0 ? "mapping_missing" : "mapping_ambiguous";
            return undefined;
          }
          let local: string | undefined;
          try {
            local = resolveLocalInstance(
              {
                owner: options.owner,
                sourceId: grant.source.id,
                connectionId: matches[0].connectionId,
              },
              mappings,
            );
          } catch {
            mappingFailure = "mapping_invalid";
          }
          if (!local) mappingFailure ??= "mapping_missing";
          return local;
        }
      }
      if (mappingFailure) return denied(mappingFailure);
      if (
        streams.some(
          (stream) =>
            new Set(stream.instance_ids).size !== stream.instance_ids.length,
        )
      )
        return denied("mapping_collapsed");
      return {
        active: true,
        tokenKind: "client",
        subjectId: context.subject_id,
        clientId: context.client_id,
        expiresAt: new Date(context.exp * 1000).toISOString(),
        grant: { ...grant, streams },
        // A locked grant's client sees its pairwise handles, not local ids.
        ...(locked && { clientInstanceHandles }),
      };
    },
  };
}

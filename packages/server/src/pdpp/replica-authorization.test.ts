import { afterEach, expect, it } from "vitest";
import { Hono } from "hono";
import pino from "pino";
import {
  AuthorizationSessionStore,
  openPdppAuthStore,
  PdppTokenService,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { pdppAuthRoutes } from "../routes/pdpp-auth.js";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import {
  createReplicaAuthorizationService,
  type ReplicaGrantConnection,
} from "./replica-authorization.js";

const owner = "owner-a";
const sourceId = "https://source.example/messages";
const stores: PdppAuthStore[] = [];
afterEach(() => {
  for (const store of stores.splice(0)) store.close();
});

function fixture(subject = owner, resourceOwner = owner) {
  const store = openPdppAuthStore(":memory:");
  stores.push(store);
  const grant: Grant = {
    version: "0.2.0",
    grant_id: "grant-a",
    issued_at: new Date().toISOString(),
    subject: { id: subject },
    client: { client_id: "app-a" },
    source: { id: sourceId, kind: "connector" },
    source_declaration: { version: "1" },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    streams: [
      { name: "messages", instance_ids: ["issuer-handle"], fields: ["text"] },
    ],
  };
  store.insertGrant({
    grant,
    subjectId: subject,
    reviewDigest: "exact-owner-review",
  });
  store.insertAuthCode("code", {
    grantId: grant.grant_id,
    clientId: "app-a",
    redirectUri: "https://app.example/cb",
    codeChallenge: null,
    codeChallengeMethod: null,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const tokens = new PdppTokenService(store);
  const issued = tokens.redeemAuthorizationCode({
    code: "code",
    clientId: "app-a",
    redirectUri: "https://app.example/cb",
  });
  expect(issued.ok).toBe(true);
  if (!issued.ok) throw new Error("fixture code not redeemed");
  const credential = tokens.issueOwnerToken({
    subjectId: subject,
    sourceId,
  }).access_token;
  const issuer = new Hono().route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger: pino({ level: "silent" }),
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      resolveDeclaration: () => null,
      inventoryFor: () => ({ eligibleFor: () => ["issuer-handle"] }),
      currentSubjectId: () => owner,
    }),
  );
  let connections: ReplicaGrantConnection[] = [
    {
      owner: resourceOwner,
      sourceId,
      connectionId: "logical-a",
      issuerInstanceId: "issuer-handle",
      localInstanceId: "replica-handle",
    },
  ];
  let unavailable = false;
  let responseOverride: (() => Response) | undefined;
  let localTime = Date.now();
  const decisions: { outcome: string; reason: string }[] = [];
  const auth = createReplicaAuthorizationService({
    owner: resourceOwner,
    issuerOrigin: "https://issuer.example",
    credential: async () => credential,
    connections: () => connections,
    now: () => localTime,
    onDecision: (event) => decisions.push(event),
    fetch: (input, init) =>
      unavailable
        ? Promise.reject(new Error("issuer offline"))
        : responseOverride
          ? Promise.resolve(responseOverride())
          : issuer.request(String(input), init),
  });
  const records = createMemoryRecordStore();
  records.ingestBatch(
    [
      {
        instance: "replica-handle",
        stream: "messages",
        key: "one",
        data: {
          id: "one",
          text: resourceOwner === owner ? "approved" : "foreign-approved",
          secret: "hidden",
        },
        emitted_at: "2026-10-01T00:00:00Z",
      },
      {
        instance: "independent",
        stream: "messages",
        key: "one",
        data: { id: "one", text: "C2-SECRET-SENTINEL" },
        emitted_at: "2026-10-01T00:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
  const replica = pdppRecordsRoutes({
    store: records,
    auth,
    declarations: createStreamDeclarationRegistry([
      {
        name: "messages",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
        declaredFields: ["id", "text", "secret"],
      },
    ]),
  });
  const read = (accessToken = issued.issued.access_token) =>
    replica.request("/streams/messages/records", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
  return {
    read,
    auth,
    tokens,
    grant,
    accessToken: issued.issued.access_token,
    credential,
    decisions,
    wire: () => tokens.introspect(issued.issued.access_token),
    setResponse: (value: () => Response) => {
      responseOverride = value;
    },
    setTime: (value: number) => {
      localTime = value;
    },
    setConnections: (value: ReplicaGrantConnection[]) => {
      connections = value;
    },
    setUnavailable: (value: boolean) => {
      unavailable = value;
    },
  };
}

async function expectDenied(pending: Promise<Response> | Response) {
  const response = await pending;
  expect(response.status).toBe(401);
  const body = await response.json();
  expect(body.error.code).toBe("authentication_error");
  expect(body.data).toBeUndefined();
  // copy-assertion-ok: security sentinels must not occur in denied response bytes.
  for (const sentinel of [
    "approved",
    "foreign-approved",
    "hidden",
    "other connection",
  ])
    expect(JSON.stringify(body)).not.toContain(sentinel);
}

it("reads only the issuer-approved connection through its explicit local handle, then rejects the revoked token", async () => {
  const { read, auth, tokens, grant, accessToken, decisions } = fixture();
  const response = await read();
  expect(response.status).toBe(200);
  expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  const body = await response.json();
  expect(body.data).toHaveLength(1);
  expect(body.data[0].id).toBe("one");
  expect(
    (await auth.resolveToken(accessToken)).grant?.streams[0].instance_ids,
  ).toEqual(["replica-handle"]);
  expect(body.data[0].data).toEqual({ text: "approved" });
  tokens.revokeGrant(grant.grant_id);
  await expectDenied(read());
  expect(decisions.at(-1)).toEqual({
    outcome: "denied",
    reason: "issuer_inactive",
  });
});

it("denies another owner's active token even when its handle matches", async () => {
  const { read } = fixture("owner-b");
  await expectDenied(read());
});

it("denies an approved token routed to a different owner's replica with colliding local identifiers", async () => {
  const { read } = fixture(owner, "owner-b");
  await expectDenied(read());
  const foreignControl = fixture("owner-b", "owner-b");
  expect((await foreignControl.read()).status).toBe(200);
});

it("fails closed during a partition while the issuer revokes a previously working token, then still denies on reconnect", async () => {
  const { read, setUnavailable, tokens, grant } = fixture();
  expect((await read()).status).toBe(200);
  setUnavailable(true);
  tokens.revokeGrant(grant.grant_id);
  const unavailable = await read();
  expect(unavailable.status).toBe(500);
  expect(unavailable.headers.get("Retry-After")).toBe("5");
  expect((await unavailable.json()).error.code).toBe("api_error");
  setUnavailable(false);
  await expectDenied(read());
});

it("denies a token from an unconfigured issuer rather than selecting an authority from token content", async () => {
  const { read } = fixture();
  expect((await read()).status).toBe(200);
  await expectDenied(read("pdpp_at_rogue-issuer-token"));
});

it("never accepts the introspection owner's credential as an application token", async () => {
  const { read, credential, decisions } = fixture();
  expect((await read()).status).toBe(200);
  await expectDenied(read(credential));
  expect(decisions.at(-1)).toEqual({ outcome: "denied", reason: "token_kind" });
});

it.each(["grant_id", "client_id", "subject_id"])(
  "rejects inconsistent %s without discarding its reason",
  async (member) => {
    const f = fixture();
    expect((await f.read()).status).toBe(200);
    f.setResponse(() =>
      Response.json({ ...f.wire(), [member]: "substituted" }),
    );
    await expectDenied(f.read());
    expect(f.decisions.at(-1)).toEqual({
      outcome: "denied",
      reason: member === "subject_id" ? "owner_mismatch" : "grant_mismatch",
    });
  },
);

it.each([
  "v01",
  "unknown-stream-restriction",
  "unknown-time-restriction",
  "empty-fields",
  "duplicate-fields",
])(
  "refuses %s instead of reconstructing or widening an issuer context",
  async (kind) => {
    const f = fixture();
    expect((await f.read()).status).toBe(200);
    const wire = JSON.parse(JSON.stringify(f.wire()));
    const grant = wire.authorization_details[0].grant;
    const stream = grant.streams[0];
    if (kind === "v01") grant.version = "0.1.0";
    if (kind === "unknown-stream-restriction")
      stream.extra_restriction = "must not be stripped";
    if (kind === "unknown-time-restriction")
      stream.time_constraint = {
        field: "collected_at",
        future_restriction: "must not be stripped",
      };
    if (kind === "empty-fields") stream.fields = [];
    if (kind === "duplicate-fields") stream.fields = ["text", "text"];
    f.setResponse(() => Response.json(wire));
    const response = await f.read();
    expect(response.status).toBe(500);
    expect(response.headers.get("Retry-After")).toBe("5");
    expect((await response.json()).error.code).toBe("api_error");
    expect(f.decisions.at(-1)).toEqual({
      outcome: "unavailable",
      reason: "invalid_response",
    });
  },
);

it.each([
  "server-error",
  "expired-credential",
  "non-json",
  "oversized",
  "redirect",
])(
  "reports %s as unavailable rather than issuer-confirmed revocation",
  async (kind) => {
    const f = fixture();
    expect((await f.read()).status).toBe(200);
    f.setResponse(() => {
      if (kind === "server-error") return new Response("", { status: 503 });
      if (kind === "expired-credential")
        return new Response("", { status: 401 });
      if (kind === "redirect")
        return new Response("", {
          status: 302,
          headers: { location: "https://rogue.example" },
        });
      return new Response(
        kind === "non-json" ? "not-json" : "x".repeat(1024 * 1024 + 1),
      );
    });
    const response = await f.read();
    expect(response.status).toBe(500);
    expect(response.headers.get("Retry-After")).toBe("5");
    expect((await response.json()).error.code).toBe("api_error");
    expect(f.decisions.at(-1)).toEqual({
      outcome: "unavailable",
      reason: "issuer_unavailable",
    });
  },
);

it("checks token expiry at the exact local boundary without resurrecting an issuer-expired token", async () => {
  const f = fixture();
  const expiry = f.wire().exp! * 1000;
  f.setTime(expiry - 1);
  expect((await f.read()).status).toBe(200);
  f.setTime(expiry);
  await expectDenied(f.read());
  expect(f.decisions.at(-1)).toEqual({ outcome: "denied", reason: "expired" });
  f.tokens.revokeGrant(f.grant.grant_id);
  f.setTime(expiry - 24 * 3600_000);
  await expectDenied(f.read());
  expect(f.decisions.at(-1)).toEqual({
    outcome: "denied",
    reason: "issuer_inactive",
  });
});

it.each([
  "http://remote.example",
  "https://credential@issuer.example",
  "https://issuer.example/path",
  "https://issuer.example?query",
  "https://issuer.example#fragment",
])(
  "rejects unsafe issuer configuration %s before any token is sent",
  (issuerOrigin) => {
    expect(() =>
      createReplicaAuthorizationService({
        owner,
        issuerOrigin,
        credential: async () => "",
        connections: () => [],
      }),
    ).toThrow();
  },
);

it("rejects an empty owner at construction", () => {
  expect(() =>
    createReplicaAuthorizationService({
      owner: "",
      issuerOrigin: "https://issuer.example",
      credential: async () => "",
      connections: () => [],
    }),
  ).toThrow();
});

it.each([
  "missing",
  "wrong-source",
  "wrong-owner",
  "ambiguous-logical",
  "ambiguous-local",
  "independent-collapse",
])(
  "denies %s connection evidence without guessing from the source",
  async (kind) => {
    const { read, setConnections } = fixture();
    const connection = {
      owner,
      sourceId,
      connectionId: "logical-a",
      issuerInstanceId: "issuer-handle",
      localInstanceId: "replica-handle",
    };
    const variants: Record<string, ReplicaGrantConnection[]> = {
      missing: [],
      "wrong-source": [
        { ...connection, sourceId: "independent-source" },
        { ...connection, issuerInstanceId: "different-issuer-handle" },
      ],
      "wrong-owner": [
        { ...connection, owner: "independent-owner" },
        { ...connection, issuerInstanceId: "different-issuer-handle" },
      ],
      "ambiguous-logical": [
        connection,
        { ...connection, connectionId: "independent-connection" },
      ],
      "ambiguous-local": [
        connection,
        { ...connection, localInstanceId: "second-handle" },
      ],
      "independent-collapse": [
        connection,
        {
          ...connection,
          connectionId: "independent-connection",
          issuerInstanceId: "another-issuer-handle",
        },
      ],
    };
    setConnections(variants[kind]);
    await expectDenied(read());
  },
);

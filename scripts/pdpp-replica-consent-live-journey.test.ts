import { mkdtempSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { createReplicaReceiver } from "../packages/server/src/storage/pdpp-replication-receiver.js";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { createSqliteRecordStore } from "../packages/server/src/storage/pdpp-records-sqlite-store.js";
import {
  approveNarrowConsent,
  assertAppRead,
  assertCanonicalEquality,
  assertTokenDenied,
  openConsentIssuer,
  openReplicaResourceServer,
  revokeConsent,
  window,
} from "./pdpp-replica-consent-live-journey.js";
import {
  Device,
  binding,
  digest,
  pause,
  sourceId,
} from "./pdpp-replica-live-journey.js";

function temporaryRoot() {
  const parent = join(homedir(), ".tmp");
  mkdirSync(parent, { recursive: true });
  return mkdtempSync(join(parent, "consent-harness-test-"));
}
function fixture(path: string) {
  const db = new Database(path);
  const store = createSqliteRecordStore(db);
  for (const instance of ["conn", "conn-other"])
    store.registerConnection({
      instance,
      sourceId,
      method: "export",
      label: "test connection",
    });
  const bytes = new TextEncoder().encode("replicated blob fixture");
  const blob = store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  const blobRef = {
    blob_id: blob.blobId,
    mime_type: blob.mimeType,
    size_bytes: bytes.length,
  };
  const expected = {
    text: "public text",
    collected_at: "2026-10-15T12:00:00Z",
    blob_ref: blobRef,
  };
  for (const [instance, key, data] of [
    [
      "conn",
      "visible",
      {
        ...expected,
        id: "visible",
        private_note: "hidden despite schema-required",
      },
    ],
    [
      "conn",
      "outside",
      {
        id: "outside",
        text: "outside window",
        collected_at: "2026-09-30T23:59:59Z",
      },
    ],
    [
      "conn",
      "until-boundary",
      {
        id: "until-boundary",
        text: "exclusive bound",
        collected_at: window.until,
      },
    ],
    [
      "conn-other",
      "other-only",
      {
        id: "other-only",
        text: "other connection",
        collected_at: expected.collected_at,
      },
    ],
  ] as const)
    store.ingestBatch(
      [
        {
          instance,
          stream: "messages",
          key,
          data,
          emitted_at: "2026-10-15T12:00:00Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
    );
  return {
    db,
    store,
    expected,
    blob: { blobId: blob.blobId, bytes: bytes.length, sha256: digest(bytes) },
  };
}

describe("single issuer harness through real HTTP AS/RS and SQLite", () => {
  it("proves exact narrowing, isolation, stale approval/code replay, revocation and real expiry across RS restarts", async () => {
    const root = temporaryRoot();
    const f = fixture(join(root, "records.sqlite"));
    const issuer = await openConsentIssuer(root, "ephemeral-test-owner", 2);
    let rs = await openReplicaResourceServer(f.store, {
      owner: "ephemeral-test-owner",
      issuerOrigin: issuer.origin,
      credential: issuer.credential,
      reads: () => f.store,
    });
    const reopen = async () => {
      await rs.close();
      rs = await openReplicaResourceServer(f.store, {
        owner: "ephemeral-test-owner",
        issuerOrigin: issuer.origin,
        credential: issuer.credential,
        reads: () => f.store,
      });
    };
    try {
      const consent = await approveNarrowConsent(issuer);
      await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
      await reopen();
      await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
      await revokeConsent(issuer, consent);
      await assertTokenDenied(rs.origin, consent.token, f.blob.blobId, issuer);
      await reopen();
      await assertTokenDenied(rs.origin, consent.token, f.blob.blobId, issuer);
      await consent.replayApproval();
      await consent.replayCode();
      const foreign = await approveNarrowConsent(
        issuer,
        issuer.foreignCredential,
      );
      await assertTokenDenied(rs.origin, foreign.token, f.blob.blobId, issuer);
      const expiring = await approveNarrowConsent(issuer, issuer.credential, {
        expiring: true,
      });
      await assertAppRead(rs.origin, expiring.token, f.expected, f.blob);
      await pause((expiring.ttlSeconds + 1) * 1000);
      await assertTokenDenied(rs.origin, expiring.token, f.blob.blobId, issuer);
      await reopen();
      await assertTokenDenied(rs.origin, expiring.token, f.blob.blobId, issuer);
      await expiring.replayApproval();
      await expiring.replayCode();
    } finally {
      await rs.close();
      await issuer.close();
      f.db.close();
      rmSync(root, { recursive: true, force: true });
    }
  }, 15000);

  it("boots a worker process with a real RS listener", async () => {
    const root = temporaryRoot();
    const owner = privateKeyToAccount(generatePrivateKey()).address;
    const issuer = await openConsentIssuer(root, owner, 10);
    const device = new Device({
      root: join(root, "B"),
      owner,
      master: Array(32).fill(1),
      serverKey: generatePrivateKey(),
      scriptSha256: digest(
        readFileSync(
          new URL("./pdpp-replica-live-journey.ts", import.meta.url),
        ),
      ),
      consent: { issuerOrigin: issuer.origin, credential: issuer.credential },
    });
    try {
      await device.start();
      const origin = await device.call<string>("resourceOrigin");
      expect(origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    } finally {
      await device.kill();
      await issuer.close();
      rmSync(root, { recursive: true, force: true });
    }
  }, 10000);

  it("canonical digests ignore JSON object serialization order", () => {
    const root = temporaryRoot();
    const aPath = join(root, "A.sqlite"),
      bPath = join(root, "B.sqlite");
    const a = fixture(aPath),
      b = fixture(bPath);
    try {
      const row = b.db
        .prepare("SELECT data FROM pdpp_records WHERE record_key='visible'")
        .get() as { data: string };
      const reversed = Object.fromEntries(
        Object.entries(JSON.parse(row.data) as object).reverse(),
      );
      b.db
        .prepare("UPDATE pdpp_records SET data=? WHERE record_key='visible'")
        .run(JSON.stringify(reversed));
      expect(() => assertCanonicalEquality(aPath, bPath)).not.toThrow();
    } finally {
      a.db.close();
      b.db.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.each([
    "instance",
    "stream",
    "record_key",
    "data",
    "emitted_at",
    "deleted",
    "blob_id",
  ])("canonical equality catches a mismatch in %s", (field) => {
    const root = temporaryRoot();
    const aPath = join(root, "A.sqlite"),
      bPath = join(root, "B.sqlite");
    const a = fixture(aPath),
      b = fixture(bPath);
    try {
      expect(() => assertCanonicalEquality(aPath, bPath)).not.toThrow();
      const changed =
        field === "deleted"
          ? 1
          : field === "data"
            ? JSON.stringify({ id: "visible", text: "changed" })
            : "changed";
      b.db
        .prepare(
          `UPDATE pdpp_records SET ${field}=? WHERE record_key='visible'`,
        )
        .run(changed);
      expect(() => assertCanonicalEquality(aPath, bPath)).toThrow();
    } finally {
      a.db.close();
      b.db.close();
      rmSync(root, { recursive: true, force: true });
    }
  });
});

// These are public HTTP contract probes. Credentials/codes remain inside closures.
const testClient = "replica-consent-acceptance";
const testRedirect = "https://replica-app.invalid/callback";
const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const approvedFields = ["text", "collected_at", "blob_ref"];
async function request(
  origin: string,
  path: string,
  token?: string,
  body?: unknown,
) {
  return fetch(origin + "/pdpp/v1" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(token && { authorization: `Bearer ${token}` }),
      ...(body !== undefined && { "content-type": "application/json" }),
    },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });
}
async function payload(response: Response, status: number) {
  expect(response.status).toBe(status);
  return response.json() as Promise<Record<string, unknown>>;
}
async function prepareApproval(
  issuer: Awaited<ReturnType<typeof openConsentIssuer>>,
  options: { fields?: string[]; connection?: string; purpose?: string } = {},
) {
  const fields = options.fields ?? approvedFields;
  const connection = options.connection ?? "conn";
  const { computeS256Challenge, PDPP_DATA_ACCESS_TYPE_V02 } =
    await import("@opendatalabs/personal-server-ts-core/pdpp");
  const created = await payload(
    await request(issuer.origin, "/authorize", issuer.credential, {
      client_id: testClient,
      redirect_uri: testRedirect,
      state: "adversarial",
      code_challenge: computeS256Challenge(testVerifier),
      code_challenge_method: "S256",
      authorization_details: [
        {
          type: PDPP_DATA_ACCESS_TYPE_V02,
          source: { id: sourceId },
          purpose_code:
            options.purpose ??
            "https://replica-app.invalid/purposes/acceptance",
          access_mode: "continuous",
          retention: { max_duration: "P1D", on_expiry: "delete" },
          streams: [
            {
              name: "messages",
              necessity: "required",
              fields: ["id", ...approvedFields, "private_note"],
              time_range: {
                since: "2026-01-01T00:00:00Z",
                until: "2027-01-01T00:00:00Z",
              },
              minimum: { fields: ["text"], time_range: window },
            },
          ],
        },
      ],
    }),
    201,
  );
  const base = `/authorize/${created.session_id}`;
  const picks = new URLSearchParams({
    "instance[messages]": connection,
    "since[messages]": window.since,
    "until[messages]": window.until,
  });
  for (const field of fields) picks.append("field[messages]", field);
  const reviewed = await payload(
    await request(issuer.origin, `${base}/review?${picks}`, issuer.credential),
    200,
  );
  const body = {
    review_digest: (reviewed.review as { review_digest: string }).review_digest,
    instance_choices: { messages: [connection] },
    owner_choices: {
      fields: { messages: fields },
      time_ranges: { messages: window },
    },
  };
  const approve = (override: Record<string, unknown> = {}) =>
    request(issuer.origin, `${base}/approve`, issuer.credential, {
      ...body,
      ...override,
    });
  return { body, approve, path: base };
}
async function codeFrom(approval: Awaited<ReturnType<typeof prepareApproval>>) {
  const approved = await payload(await approval.approve(), 200);
  const returned = new URL(String(approved.redirect_uri));
  expect(returned.origin + returned.pathname).toBe(testRedirect);
  const code = returned.searchParams.get("code");
  expect(Boolean(code)).toBe(true);
  return code!;
}
function redeem(
  issuer: Awaited<ReturnType<typeof openConsentIssuer>>,
  code: string,
  overrides: Record<string, string> = {},
) {
  return fetch(issuer.origin + "/pdpp/v1/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: testClient,
      redirect_uri: testRedirect,
      code_verifier: testVerifier,
      ...overrides,
    }),
  });
}
async function mint(
  issuer: Awaited<ReturnType<typeof openConsentIssuer>>,
  options: Parameters<typeof prepareApproval>[1] = {},
) {
  const approval = await prepareApproval(issuer, options);
  const issued = await payload(
    await redeem(issuer, await codeFrom(approval)),
    200,
  );
  return {
    token: String(issued.access_token),
    grantId: String(issued.grant_id),
  };
}
async function scenario(
  run: (context: {
    root: string;
    f: ReturnType<typeof fixture>;
    issuer: Awaited<ReturnType<typeof openConsentIssuer>>;
    rs: Awaited<ReturnType<typeof openReplicaResourceServer>>;
  }) => Promise<void>,
) {
  const root = temporaryRoot();
  const f = fixture(join(root, "records.sqlite"));
  const issuer = await openConsentIssuer(root, "ephemeral-contract-owner", 60);
  const rs = await openReplicaResourceServer(f.store, {
    owner: "ephemeral-contract-owner",
    issuerOrigin: issuer.origin,
    credential: issuer.credential,
    reads: () => f.store,
  });
  try {
    await run({ root, f, issuer, rs });
  } finally {
    await rs.close();
    await issuer.close();
    f.db.close();
    rmSync(root, { recursive: true, force: true });
  }
}
function seed(
  store: ReturnType<typeof createSqliteRecordStore>,
  instance: string,
  key: string,
  data: Record<string, unknown>,
) {
  store.ingestBatch(
    [
      {
        instance,
        stream: "messages",
        key,
        data: { id: key, collected_at: "2026-10-15T12:00:00Z", ...data },
        emitted_at: "2026-10-15T12:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
    {
      method: "export",
      generation: store.getInstanceBinding(instance).generation,
    },
  );
}
async function noDisclosure(
  response: Response,
  status: number,
  sentinels: string[],
) {
  expect(response.status).toBe(status);
  const body = await response.text();
  for (const sentinel of sentinels) expect(body.includes(sentinel)).toBe(false);
}

describe("P0 adversarial public AS and app-read contracts", () => {
  it("#1 rejects supported approval substitutions and still approves the exact reviewed scope", async () =>
    scenario(async ({ issuer, f, rs }) => {
      const mutations = [
        {
          owner_choices: {
            fields: { messages: [...approvedFields, "private_note"] },
            time_ranges: { messages: window },
          },
        },
        {
          owner_choices: {
            fields: { messages: approvedFields },
            time_ranges: {
              messages: { since: "2026-09-01T00:00:00Z", until: window.until },
            },
          },
        },
        { instance_choices: { messages: ["conn-other"] } },
        {
          owner_choices: {
            fields: { messages: approvedFields },
            declined_streams: ["messages"],
          },
        },
        {
          owner_conditions: {
            retention: { max_duration: "P2D", on_expiry: "delete" },
          },
        },
        { owner_conditions: { purpose_code: "https://rogue.invalid/purpose" } },
        { review_digest: "0".repeat(64) },
      ];
      for (const mutation of mutations) {
        const approval = await prepareApproval(issuer);
        const denied = await approval.approve(mutation);
        expect([403, 409]).toContain(denied.status);
        const body = (await denied.json()) as Record<string, unknown>;
        expect(
          "redirect_uri" in body ||
            "access_token" in body ||
            "grant_id" in body,
        ).toBe(false);
        const issued = await payload(
          await redeem(issuer, await codeFrom(approval)),
          200,
        );
        await assertAppRead(
          rs.origin,
          String(issued.access_token),
          f.expected,
          f.blob,
        );
      }
    }));

  it("#1 requires explicit AI-training approval and never substitutes it for the reviewed digest", async () =>
    scenario(async ({ issuer }) => {
      const approval = await prepareApproval(issuer, {
        purpose: "https://pdpp.dev/purpose/ai_training",
      });
      expect(
        (await approval.approve({ explicit_ai_training_consent: false }))
          .status,
      ).toBe(400);
      expect(
        (
          await approval.approve({
            explicit_ai_training_consent: true,
            review_digest: "0".repeat(64),
          })
        ).status,
      ).toBe(409);
      const approved = await payload(
        await approval.approve({ explicit_ai_training_consent: true }),
        200,
      );
      const code = new URL(String(approved.redirect_uri)).searchParams.get(
        "code",
      )!;
      const issued = await payload(await redeem(issuer, code), 200);
      expect(typeof issued.access_token).toBe("string");
    }));

  it("#3 cannot widen a connection through queries, omission, key collisions or another connection cursor", async () =>
    scenario(async ({ issuer, rs, f }) => {
      seed(f.store, "conn-other", "visible", { text: "C2_SECRET_COLLISION" });
      const allowed = await mint(issuer);
      await assertAppRead(rs.origin, allowed.token, f.expected, f.blob);
      for (const query of [
        "instance=conn-other",
        "instance=*",
        "instance[]=conn&instance[]=conn-other",
        "connection=conn-other",
        "instances=conn,conn-other",
      ])
        await noDisclosure(
          await request(
            rs.origin,
            `/streams/messages/records?${query}`,
            allowed.token,
          ),
          400,
          ["C2_SECRET_COLLISION"],
        );
      const other = await mint(issuer, { connection: "conn-other" });
      const page = await payload(
        await request(
          rs.origin,
          "/streams/messages/records?limit=1",
          other.token,
        ),
        200,
      );
      expect(page.has_more).toBe(true);
      expect(typeof page.next_cursor).toBe("string");
      const reused = await payload(
        await request(
          rs.origin,
          `/streams/messages/records?cursor=${encodeURIComponent(String(page.next_cursor))}`,
          allowed.token,
        ),
        200,
      );
      // A cursor positions a read; the current token still owns its scope.
      const reusedRows = reused.data as { id: string; data: unknown }[];
      expect(reusedRows).toEqual([]);
      expect(JSON.stringify(reused).includes("C2_SECRET_COLLISION")).toBe(
        false,
      );
      await assertAppRead(rs.origin, allowed.token, f.expected, f.blob);
    }));

  it("#4 requires a permitted blob_ref for GET, HEAD and Range, even when the hash is known", async () =>
    scenario(async ({ issuer, rs, f }) => {
      const privateBytes = new TextEncoder().encode("C2_PRIVATE_BLOB_BYTES");
      const hidden = f.store.storeBlobBytesForInstance({
        instance: "conn-other",
        method: "export",
        generation: 1,
        bytes: privateBytes,
        mimeType: "application/octet-stream",
      });
      seed(f.store, "conn-other", "other-blob", {
        text: "C2_PRIVATE_REFERENCE",
        blob_ref: {
          blob_id: hidden.blobId,
          mime_type: hidden.mimeType,
          size_bytes: privateBytes.length,
        },
      });
      const allowed = await mint(issuer);
      const noRef = await mint(issuer, { fields: ["text", "collected_at"] });
      for (const [id, token] of [
        [hidden.blobId, allowed.token],
        [f.blob.blobId, noRef.token],
      ] as const) {
        for (const method of ["GET", "HEAD"])
          for (const range of [undefined, "bytes=0-7"]) {
            const response = await fetch(
              `${rs.origin}/pdpp/v1/blobs/${encodeURIComponent(id)}`,
              {
                method,
                headers: {
                  authorization: `Bearer ${token}`,
                  ...(range && { range }),
                },
              },
            );
            expect(response.headers.get("content-type")).not.toBe(
              "application/octet-stream",
            );
            expect(response.headers.get("content-length")).not.toBe(
              String(privateBytes.length),
            );
            await noDisclosure(response, 404, [
              "C2_PRIVATE_BLOB_BYTES",
              "replicated blob fixture",
              "C2_PRIVATE_REFERENCE",
            ]);
          }
      }
      for (const method of ["GET", "HEAD"])
        await noDisclosure(
          await fetch(
            `${rs.origin}/pdpp/v1/blobs/${encodeURIComponent(hidden.blobId)}`,
            { method },
          ),
          401,
          ["C2_PRIVATE_BLOB_BYTES"],
        );
      await assertAppRead(rs.origin, allowed.token, f.expected, f.blob);
    }));

  it("#7/#15 reauthorizes metadata, changes, next pages and blob requests after committed revocation", async () =>
    scenario(async ({ issuer, rs, f }) => {
      const consent = await approveNarrowConsent(issuer);
      await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
      seed(f.store, "conn", "page-two", {
        text: "PAGE_TWO_SECRET_AFTER_REVOKE",
      });
      const page = await payload(
        await request(
          rs.origin,
          "/streams/messages/records?limit=1",
          consent.token,
        ),
        200,
      );
      expect(page.has_more).toBe(true);
      expect(typeof page.next_cursor).toBe("string");
      const changes = await payload(
        await request(
          rs.origin,
          "/streams/messages/records?changes_since=&limit=1",
          consent.token,
        ),
        200,
      );
      await revokeConsent(issuer, consent);
      const paths = [
        "/streams",
        "/streams/messages",
        "/streams/messages/records",
        "/streams/messages/records/visible",
        `/streams/messages/records?cursor=${encodeURIComponent(String(page.next_cursor))}`,
        "/streams/messages/records?changes_since=",
        ...(changes.next_cursor
          ? [
              `/streams/messages/records?changes_since=&cursor=${encodeURIComponent(String(changes.next_cursor))}`,
            ]
          : []),
      ];
      for (const path of paths)
        await noDisclosure(await request(rs.origin, path, consent.token), 401, [
          "public text",
          "PAGE_TWO_SECRET_AFTER_REVOKE",
          "private_note",
          f.blob.blobId,
        ]);
      for (const method of ["GET", "HEAD"])
        await noDisclosure(
          await fetch(
            `${rs.origin}/pdpp/v1/blobs/${encodeURIComponent(f.blob.blobId)}`,
            {
              method,
              headers: {
                authorization: `Bearer ${consent.token}`,
                range: "bytes=0-7",
              },
            },
          ),
          401,
          ["replicated blob fixture"],
        );
    }));

  it("#9/#21 one active AS grant sees the old current record while owner preview is pending, then the confirmed edit", async () =>
    scenario(async ({ issuer, f }) => {
      const owner = "ephemeral-contract-owner";
      f.store.replication.beginBaseline({
        owner,
        declarations: [{ sourceId, binding }],
      });
      const receiver = createReplicaReceiver({
        db: f.db,
        store: f.store,
        owner,
        enabled: true,
        authenticate: (credential) =>
          credential === "test-host" ? owner : undefined,
        declarations: () => [{ sourceId, binding, validateData: () => true }],
      });
      const rs = await openReplicaResourceServer(f.store, {
        owner,
        issuerOrigin: issuer.origin,
        credential: issuer.credential,
        reads: (reader) => receiver.readStore({ reader }),
      });
      try {
        const consent = await approveNarrowConsent(issuer);
        await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
        const bytes = new TextEncoder().encode(
          "NEW_PENDING_BLOB_MUST_NOT_LEAK",
        );
        const id = `sha256:${digest(bytes)}`;
        const descriptor = {
          blobId: id,
          sha256: id,
          mimeType: "application/octet-stream",
          sizeBytes: bytes.length,
        };
        const identity = {
          owner,
          sourceId,
          connectionId: "conn",
          methodId: "export",
          generation: 1,
        };
        const data = {
          id: "visible",
          text: "new confirmed edit",
          collected_at: f.expected.collected_at,
          private_note: "NEW_PENDING_SECRET_MUST_NOT_LEAK",
          blob_ref: {
            blob_id: id,
            mime_type: descriptor.mimeType,
            size_bytes: bytes.length,
          },
        };
        receiver.stage({
          credential: "test-host",
          id: "pending-edit",
          blobs: [{ blobId: id, bytes }],
          envelope: {
            format: "vana-pdpp-replica",
            version: 1,
            owner,
            batchId: "pending-edit",
            operations: [
              {
                ...identity,
                kind: "blob-claim",
                blob: descriptor,
                revision: {
                  counter: 100,
                  writerId: "peer",
                  operationId: "new-claim",
                },
              },
              {
                ...identity,
                kind: "upsert",
                declaration: binding,
                recordKey: "visible",
                emittedAt: "2026-10-21T00:00:00Z",
                data,
                blobs: [descriptor],
                revision: {
                  counter: 101,
                  writerId: "peer",
                  operationId: "new-edit",
                },
              },
            ],
          },
        });
        const ownerRows = receiver.readVisibleRecords({
          reader: "owner",
          connectionId: "conn",
          stream: "messages",
        });
        expect(
          ownerRows.find((r) => r.recordKey === "visible")?.confirmation,
        ).toBe("not yet confirmed"); // copy-assertion-ok: Required receiver confirmation state in returned data.
        expect(
          ownerRows.find((r) => r.recordKey === "visible")?.data.text,
        ).toBe(data.text);
        await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
        for (const path of [
          "/streams/messages/records?changes_since=",
          `/blobs/${encodeURIComponent(id)}`,
        ]) {
          const response = await request(rs.origin, path, consent.token);
          await noDisclosure(response, path.includes("/blobs/") ? 404 : 200, [
            "NEW_PENDING_SECRET_MUST_NOT_LEAK",
            "new confirmed edit",
            id,
            "NEW_PENDING_BLOB_MUST_NOT_LEAK",
          ]);
        }
        receiver.promote({ credential: "test-host", id: "pending-edit" });
        await assertAppRead(
          rs.origin,
          consent.token,
          {
            text: data.text,
            collected_at: data.collected_at,
            blob_ref: data.blob_ref,
          },
          { blobId: id, sha256: digest(bytes), bytes: bytes.length },
        );
        expect(
          receiver
            .readVisibleRecords({
              reader: "owner",
              connectionId: "conn",
              stream: "messages",
            })
            .find((r) => r.recordKey === "visible")?.confirmation,
        ).toBeUndefined();
        await noDisclosure(
          await request(
            rs.origin,
            `/blobs/${encodeURIComponent(f.blob.blobId)}`,
            consent.token,
          ),
          404,
          ["replicated blob fixture"],
        );
      } finally {
        await rs.close();
      }
    }));

  it("denial evidence requires a healthy issuer and an explicit inactive decision", async () => {
    const root = temporaryRoot();
    const f = fixture(join(root, "records.sqlite"));
    const issuer = await openConsentIssuer(root, "ephemeral-contract-owner", 2);
    const rs = await openReplicaResourceServer(f.store, {
      owner: "ephemeral-contract-owner",
      issuerOrigin: issuer.origin,
      credential: issuer.credential,
      reads: () => f.store,
    });
    let closed = false;
    try {
      const consent = await approveNarrowConsent(issuer);
      await expect(
        assertTokenDenied(rs.origin, consent.token, f.blob.blobId, issuer),
      ).rejects.toThrow("issuer explicitly rejects");
      await revokeConsent(issuer, consent);
      const receipt = await assertTokenDenied(
        rs.origin,
        consent.token,
        f.blob.blobId,
        issuer,
      );
      expect(receipt.issuerCredentialActive).toBe(true);
      expect(receipt.introspectionActive).toBe(false);
      await issuer.close();
      closed = true;
      await expect(
        assertTokenDenied(rs.origin, consent.token, f.blob.blobId, issuer),
      ).rejects.toThrow();
      const unavailable = await request(
        rs.origin,
        "/streams/messages/records",
        consent.token,
      );
      expect(unavailable.status).toBe(500);
      expect(unavailable.headers.get("retry-after")).toBe("5");
      await unavailable.body?.cancel();
    } finally {
      await rs.close();
      if (!closed) await issuer.close();
      f.db.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("#10 rejects hidden-field operations and projects direct/list/change and metadata responses", async () =>
    scenario(async ({ issuer, rs, f }) => {
      const allowed = await mint(issuer, { fields: ["text"] });
      const sentinels = [
        "hidden despite schema-required",
        "private_note",
        "blob_ref",
        f.blob.blobId,
        "outside window",
        "exclusive bound",
        "other connection",
      ];
      for (const path of [
        "/streams/messages/records/visible",
        "/streams/messages/records",
        "/streams/messages/records?changes_since=",
        "/streams",
        "/streams/messages",
      ]) {
        const response = await request(rs.origin, path, allowed.token);
        expect(response.status).toBe(200);
        const text = await response.text();
        for (const sentinel of sentinels)
          expect(text.includes(sentinel)).toBe(false);
      }
      for (const query of [
        "fields=*",
        "fields=private_note",
        "fields=nested.secret",
        "fields=alias:private_note",
        "filter[private_note]=x",
        "sort=private_note",
        "count=private_note",
        "group_by=private_note",
        "expand[]=private_note",
        "view=history",
      ])
        await noDisclosure(
          await request(
            rs.origin,
            `/streams/messages/records?${query}`,
            allowed.token,
          ),
          400,
          ["hidden despite schema-required", f.blob.blobId],
        );
      const single = await payload(
        await request(
          rs.origin,
          "/streams/messages/records/visible?fields=text",
          allowed.token,
        ),
        200,
      );
      expect(single.data).toEqual({ text: f.expected.text });
    }));

  it("#13 allows at most one parallel redemption and keeps replay protection across issuer restart", async () => {
    const root = temporaryRoot();
    let issuer = await openConsentIssuer(root, "ephemeral-replay-owner", 60);
    try {
      const approval = await prepareApproval(issuer);
      const code = await codeFrom(approval);
      const responses = await Promise.all([
        redeem(issuer, code),
        redeem(issuer, code),
      ]);
      expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
      for (const response of responses) await response.body?.cancel();
      expect((await redeem(issuer, code)).status).toBe(400);
      // Also preserve an approved, unredeemed code across a real durable AS close/open.
      const unredeemed = await codeFrom(await prepareApproval(issuer));
      await issuer.close();
      issuer = await openConsentIssuer(root, "ephemeral-replay-owner", 60);
      expect((await redeem(issuer, code)).status).toBe(400);
      const issued = await payload(await redeem(issuer, unredeemed), 200);
      expect(typeof issued.access_token).toBe("string");
      expect((await redeem(issuer, unredeemed)).status).toBe(400);
      expect(
        (
          await request(
            issuer.origin,
            `${approval.path}/approve`,
            issuer.credential,
            approval.body,
          )
        ).status,
      ).toBe(404);
    } finally {
      await issuer.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("#14 binds code redemption to client, redirect and PKCE and rejects a rogue issuer's opaque token", async () =>
    scenario(async ({ issuer, rs, f, root }) => {
      for (const override of [
        { client_id: "wrong-client" },
        { redirect_uri: "https://rogue.invalid/callback" },
        { code_verifier: "x".repeat(43) },
      ] as Record<string, string>[]) {
        const code = await codeFrom(await prepareApproval(issuer));
        const denied = await payload(await redeem(issuer, code, override), 400);
        expect("access_token" in denied).toBe(false);
        expect(denied.error).toBe("invalid_grant");
      }
      const rogueRoot = join(root, "rogue");
      mkdirSync(rogueRoot);
      const rogue = await openConsentIssuer(
        rogueRoot,
        "ephemeral-contract-owner",
        60,
      );
      try {
        const token = await mint(rogue);
        await assertTokenDenied(rs.origin, token.token, f.blob.blobId, issuer);
        const good = await mint(issuer);
        await assertAppRead(rs.origin, good.token, f.expected, f.blob);
      } finally {
        await rogue.close();
      }
    }));

  it("#14 B discovery names only its configured issuer", async () =>
    scenario(async ({ issuer, rs }) => {
      const denied = await request(rs.origin, "/streams/messages/records");
      expect(denied.status).toBe(401);
      const challenge = denied.headers.get("www-authenticate");
      expect(
        challenge?.includes(
          `${rs.origin}/.well-known/oauth-protected-resource`,
        ),
      ).toBe(true);
      await denied.body?.cancel();
      const metadata = await payload(
        await fetch(`${rs.origin}/.well-known/oauth-protected-resource`),
        200,
      );
      expect(metadata.authorization_servers).toEqual([issuer.origin]);
      expect(metadata.resource).toBe(rs.origin);
      expect(metadata.pdpp_core_query_base).toBe("/pdpp/v1");
    }));

  it("#12 reset removes live rows and old blob authorization without claiming generation-bound grants", async () =>
    scenario(async ({ issuer, rs, f }) => {
      const consent = await approveNarrowConsent(issuer);
      await assertAppRead(rs.origin, consent.token, f.expected, f.blob);
      f.store.resetInstanceBinding({
        instance: "conn",
        expectedMethod: "export",
        expectedGeneration: 1,
        nextMethod: "export",
      });
      for (const path of [
        "/streams/messages/records/visible",
        `/blobs/${encodeURIComponent(f.blob.blobId)}`,
      ])
        await noDisclosure(await request(rs.origin, path, consent.token), 404, [
          "public text",
          "replicated blob fixture",
        ]);
      const list = await payload(
        await request(rs.origin, "/streams/messages/records", consent.token),
        200,
      );
      expect(list.data).toEqual([]);
      seed(f.store, "conn", "visible", {
        text: "new generation",
        blob_ref: undefined,
      });
      const fresh = await mint(issuer, { fields: ["text"] });
      const record = await payload(
        await request(
          rs.origin,
          "/streams/messages/records/visible",
          fresh.token,
        ),
        200,
      );
      expect(record.data).toEqual({ text: "new generation" });
      await noDisclosure(
        await request(
          rs.origin,
          `/blobs/${encodeURIComponent(f.blob.blobId)}`,
          fresh.token,
        ),
        404,
        ["replicated blob fixture"],
      );
    }));

  it("#15 a read paused before issuer permission decision denies after revocation commits", async () =>
    scenario(async ({ issuer, f }) => {
      const consent = await approveNarrowConsent(issuer);
      const normalFetch = globalThis.fetch;
      let release!: () => void, reached!: () => void;
      const barrier = new Promise<void>((resolve) => {
        release = resolve;
      });
      const atDecision = new Promise<void>((resolve) => {
        reached = resolve;
      });
      let armed = true;
      const ordering: string[] = [];
      const decisionFetch: typeof fetch = async (input, init) => {
        if (String(input).endsWith("/introspect") && armed) {
          armed = false;
          ordering.push("read awaits issuer");
          reached();
          await barrier;
          ordering.push("introspection sent");
        }
        return normalFetch(input, init);
      };
      const rs = await openReplicaResourceServer(f.store, {
        owner: "ephemeral-contract-owner",
        issuerOrigin: issuer.origin,
        credential: issuer.credential,
        reads: () => f.store,
        fetch: decisionFetch,
      });
      try {
        const pendingRead = request(
          rs.origin,
          "/streams/messages/records/visible",
          consent.token,
        );
        await atDecision;
        await revokeConsent(issuer, consent);
        ordering.push("revocation committed");
        release();
        await noDisclosure(await pendingRead, 401, [
          "public text",
          f.blob.blobId,
        ]);
        expect(ordering).toEqual([
          "read awaits issuer",
          "revocation committed",
          "introspection sent",
        ]);
      } finally {
        release();
        await rs.close();
      }
    }));
});

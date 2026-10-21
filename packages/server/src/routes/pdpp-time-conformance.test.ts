import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

for (const backend of ["memory", "sqlite"])
  describe(`${backend} temporal disclosure`, () => {
    it.each(["0.1.0", "0.1.0-candidate"])(
      "enforces offset, precision and validity on list/detail/sync/blob (%s)",
      async (version) => {
        const store =
          backend === "memory"
            ? createMemoryRecordStore()
            : createTestBoundRecordStore(new Database(":memory:"));
        try {
          const blob = store.storeBlobBytes(
            new TextEncoder().encode("private"),
            "text/plain",
          );
          const grant: Grant = {
            version,
            grant_id: "g",
            issued_at: "2026-01-01T00:00:00Z",
            subject: { id: "s" },
            client: { client_id: "c" },
            source: { kind: "connector", id: "src" },
            source_declaration: { version: "1" },
            purpose_code: "test",
            access_mode: "continuous",
            streams: [
              {
                name: "events",
                instance_ids: ["i"],
                fields: ["id", "blob_ref"],
                time_constraint: {
                  field: "at",
                  ...(version.endsWith("candidate")
                    ? { type: "date-time" as const }
                    : {}),
                  since: "2026-01-01T12:00:00Z",
                  until: "2026-01-01T12:00:00.1Z",
                },
              },
            ],
          };
          const auth = createFixtureAuthorizationService({
            t: { active: true, tokenKind: "client", subjectId: "s", grant },
          });
          const declarations = createStreamDeclarationRegistry([
            {
              name: "events",
              semantics: "mutable_state",
              primaryKey: ["id"],
              requiredFields: ["id"],
              cursorField: "emitted_at",
            },
          ]);
          const records = pdppRecordsRoutes({ store, auth, declarations });
          const blobs = pdppBlobsRoutes({
            store,
            auth,
            declarations,
            readBlobBytes: async (id) => {
              const bytes = store.getBlobBytes(id);
              return bytes ? new Uint8Array(bytes) : undefined;
            },
          });
          const headers = { Authorization: "Bearer t" };
          const times: Record<string, unknown> = {
            visible: "2026-01-01T13:00:00+01:00",
            before: "2026-01-01T13:00:00+02:00",
            equalUntil: "2026-01-01T12:00:00.100Z",
            invalid: "2026-99-99T12:00:00Z",
            missing: undefined,
            null: null,
            number: 42,
          };
          for (const [id, at] of Object.entries(times))
            store.ingestBatch(
              [
                {
                  instance: "i",
                  stream: "events",
                  key: id,
                  data: {
                    id,
                    at,
                    ...(id !== "visible"
                      ? { blob_ref: { blob_id: blob.blobId } }
                      : {}),
                  },
                  emitted_at: "2026-04-01T00:00:00Z",
                },
              ],
              () => "mutable_state",
              () => ["id"],
            );
          let checkpoint: string | undefined;
          for (const suffix of [
            "",
            version.endsWith("candidate")
              ? "?changes_since=beginning"
              : "?changes_since=",
          ]) {
            const response = await records.request(
              `/streams/events/records${suffix}`,
              { headers },
            );
            expect(response.status).toBe(200);
            const listed = await response.json();
            checkpoint = listed.next_changes_since ?? checkpoint;
            expect(listed.data.map((r: { id: string }) => r.id)).toEqual([
              "visible",
            ]);
          }
          for (const id of Object.keys(times))
            expect(
              (
                await records.request(`/streams/events/records/${id}`, {
                  headers,
                })
              ).status,
            ).toBe(id === "visible" ? 200 : 404);
          for (const method of ["GET", "HEAD"])
            expect(
              (await blobs.request(`/${blob.blobId}`, { method, headers }))
                .status,
            ).toBe(404);
          // Making one referencing record eligible admits the same content, proving
          // the negative case was the temporal gate rather than missing blob bytes.
          store.ingestBatch(
            [
              {
                instance: "i",
                stream: "events",
                key: "visible",
                data: {
                  id: "visible",
                  at: times.visible,
                  blob_ref: { blob_id: blob.blobId },
                },
                emitted_at: "2026-04-02T00:00:00Z",
              },
            ],
            () => "mutable_state",
            () => ["id"],
          );
          expect(
            (await blobs.request(`/${blob.blobId}`, { headers })).status,
          ).toBe(200);
          if (version.endsWith("candidate")) {
            expect(checkpoint).toBeTruthy();
            store.ingestBatch(
              [
                {
                  instance: "i",
                  stream: "events",
                  key: "visible",
                  data: { id: "visible", at: "invalid" },
                  emitted_at: "2026-04-03T00:00:00Z",
                },
              ],
              () => "mutable_state",
              () => ["id"],
            );
            const changed = await records.request(
              `/streams/events/records?changes_since=${encodeURIComponent(checkpoint!)}`,
              { headers },
            );
            expect(changed.status).toBe(200);
            expect((await changed.json()).data).toEqual([
              {
                object: "record",
                id: "visible",
                stream: "events",
                deleted: true,
              },
            ]);
          }
        } finally {
          store.close();
        }
      },
    );
  });

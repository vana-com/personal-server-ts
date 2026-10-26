/**
 * Candidate response records and tombstones name their instance; the current
 * contract's wire shape is unchanged (request-resolution audit F5).
 */
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const put = (store: PdppRecordStore, instance: string, key: string) =>
  store.ingestBatch(
    [
      {
        instance,
        stream: "events",
        key,
        data: { id: key },
        emitted_at: "2026-04-01T00:00:00Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );

for (const backend of ["memory", "sqlite"])
  describe(`${backend} record identity on the wire`, () => {
    it.each(["0.1.0", "0.1.0-candidate"])(
      "serves instance_id on records and tombstones only for a candidate grant (%s)",
      async (version) => {
        const candidate = version.endsWith("candidate");
        const store =
          backend === "memory"
            ? createMemoryRecordStore()
            : createTestBoundRecordStore(new Database(":memory:"));
        try {
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
                instance_ids: ["inst_a"],
                fields: ["id"],
                ...(candidate && { required_fields: ["id"] }),
              },
            ],
          };
          const records = pdppRecordsRoutes({
            store,
            auth: createFixtureAuthorizationService({
              t: { active: true, tokenKind: "client", subjectId: "s", grant },
            }),
            declarations: createStreamDeclarationRegistry([
              {
                name: "events",
                semantics: "mutable_state",
                primaryKey: ["id"],
                requiredFields: ["id"],
                cursorField: "emitted_at",
              },
            ]),
          });
          const get = async (path: string) => {
            const response = await records.request(path, {
              headers: { Authorization: "Bearer t" },
            });
            expect(response.status).toBe(200);
            return response.json();
          };
          put(store, "inst_a", "r1");
          put(store, "inst_a", "gone");
          const identity = candidate ? { instance_id: "inst_a" } : {};

          const listed = await get("/streams/events/records?order=asc");
          expect(listed.data).toEqual(
            ["gone", "r1"].map((id) =>
              expect.objectContaining({ id, ...identity }),
            ),
          );
          if (!candidate)
            for (const row of listed.data)
              expect(row).not.toHaveProperty("instance_id");

          const detail = await get("/streams/events/records/r1");
          expect(detail).toEqual(
            expect.objectContaining({ id: "r1", ...identity }),
          );
          if (!candidate) expect(detail).not.toHaveProperty("instance_id");

          const first = await get(
            `/streams/events/records?order=asc&changes_since=${candidate ? "beginning" : ""}`,
          );
          expect(first.data).toEqual(
            ["gone", "r1"].map((id) =>
              expect.objectContaining({ id, ...identity }),
            ),
          );
          store.deleteRecord(
            "inst_a",
            "events",
            "gone",
            "2026-04-02T00:00:00Z",
            "mutable_state",
          );
          const next = await get(
            `/streams/events/records?order=asc&changes_since=${encodeURIComponent(first.next_changes_since)}`,
          );
          expect(next.data).toEqual([
            expect.objectContaining({ id: "gone", deleted: true, ...identity }),
          ]);
          if (!candidate)
            expect(next.data[0]).not.toHaveProperty("instance_id");
        } finally {
          store.close();
        }
      },
    );
  });

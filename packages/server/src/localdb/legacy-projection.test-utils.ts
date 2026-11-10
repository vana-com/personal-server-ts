import { vi } from "vitest";
import type {
  LegacyScopeBinding,
  PdppRecord,
  ProjectPdppRecordsOptions,
} from "../../../core/src/legacy-projection/types.js";

/** Synthetic bindings exercise the migration seam without embedding product
 * connector identities or reproducing any connector's projection logic. */
const synthetic = vi.hoisted(() => {
  const make = (
    scope: string,
    connector: string,
    streams: string[],
    kind: "identity" | "time" | "rows",
    arrival = false,
  ) => ({
    scope,
    pdppSource: `https://fixture.invalid/${connector}`,
    pdppStreams: streams,
    primaryKey: Object.fromEntries(streams.map((stream) => [stream, ["id"]])),
    fieldsRead: Object.fromEntries(streams.map((stream) => [stream, ["id"]])),
    legacySchemaPath: "fixture.json",
    lossy: [],
    provenance: [],
    ...(arrival ? { rowOrder: "arrival" as const } : {}),
    project(records: PdppRecord[], options: ProjectPdppRecordsOptions) {
      if (streams.some((stream) => !options.fetchedStreams.includes(stream)))
        return {
          ok: false as const,
          error: {
            kind: "missing_stream" as const,
            scope,
            expectedStream: streams[0]!,
          },
        };
      const values = records
        .filter((r) => r.stream === streams[0])
        .map((r) => r.data);
      if (kind === "identity")
        return values.length
          ? { ok: true as const, payload: { ...values[0] } }
          : {
              ok: false as const,
              error: { kind: "empty_singleton" as const, scope },
            };
      if (kind === "time")
        return {
          ok: true as const,
          payload: {
            entries: values.map((value) => ({
              ...value,
              created_at: value.created_at ?? options.now,
              type: "entry",
            })),
            total: values.length,
          },
        };
      return { ok: true as const, payload: { records: values } };
    },
  });
  const bindings = new Map<string, LegacyScopeBinding>([
    [
      "fixture.profile",
      make("fixture.profile", "profile-source", ["profile"], "identity"),
    ],
    [
      "fixture-time.entries",
      make("fixture-time.entries", "time-source", ["entries"], "time"),
    ],
    [
      "fixture-join.entries",
      make("fixture-join.entries", "join-source", ["entries", "peers"], "rows"),
    ],
    [
      "fixture-order.items",
      make("fixture-order.items", "order-source", ["items"], "rows", true),
    ],
  ]);
  const project = (
    scope: string,
    records: PdppRecord[],
    options: ProjectPdppRecordsOptions,
  ) => {
    const binding = bindings.get(scope);
    if (!binding)
      return {
        ok: false as const,
        error: { kind: "unknown_scope" as const, scope },
      };
    const ordered = options.orderByPrimaryKey
      ? [...records].sort(
          (a, b) =>
            a.stream.localeCompare(b.stream) ||
            String(a.data.id).localeCompare(String(b.data.id)),
        )
      : records;
    return binding.project(ordered, options);
  };
  return { bindings, project };
});
vi.mock("../../../core/src/legacy-projection/index.js", async (original) => ({
  ...(await original<object>()),
  LEGACY_SCOPE_BINDINGS: synthetic.bindings,
  projectPdppRecordsToLegacyPayload: synthetic.project,
}));
vi.mock(
  "@opendatalabs/personal-server-ts-core/legacy-projection",
  async (original) => ({
    ...(await original<object>()),
    LEGACY_SCOPE_BINDINGS: synthetic.bindings,
    projectPdppRecordsToLegacyPayload: synthetic.project,
  }),
);
export const fixtureBindings = synthetic.bindings;

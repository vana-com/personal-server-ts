import type {
  ImportProjectionBinding,
  ImportProjectionPort,
} from "../../../core/src/localdb/legacy-import-types.js";

type FixtureBinding = ImportProjectionBinding & {
  project: (
    records: Parameters<ImportProjectionPort["project"]>[1],
    options: Parameters<ImportProjectionPort["project"]>[2],
  ) => Record<string, unknown> | null;
};
function make(
  connector: string,
  streams: string[],
  kind: "identity" | "time" | "rows",
  arrival = false,
): FixtureBinding {
  return {
    connector,
    streams,
    primaryKey: Object.fromEntries(streams.map((stream) => [stream, ["id"]])),
    ...(arrival ? { rowOrder: "arrival" as const } : {}),
    project(records, options) {
      if (streams.some((stream) => !options.fetchedStreams.includes(stream)))
        return null;
      const ordered = [...records].sort(
        (a, b) =>
          a.stream.localeCompare(b.stream) ||
          String(a.data.id).localeCompare(String(b.data.id)),
      );
      const values = ordered
        .filter((r) => r.stream === streams[0])
        .map((r) => r.data);
      if (kind === "identity") return values.length ? { ...values[0] } : null;
      if (kind === "time")
        return {
          entries: values.map((value) => ({
            ...value,
            created_at: value.created_at ?? options.now,
            type: "entry",
          })),
          total: values.length,
        };
      return { records: values };
    },
  };
}
/** Generic fixture ports avoid global catalogue mocks or product identities. */
export const fixtureBindings = new Map<string, FixtureBinding>([
  ["fixture.profile", make("profile-source", ["profile"], "identity")],
  ["fixture-time.entries", make("time-source", ["entries"], "time")],
  ["fixture-join.entries", make("join-source", ["entries", "peers"], "rows")],
  ["fixture-order.items", make("order-source", ["items"], "rows", true)],
]);
export const fixtureProjections: ImportProjectionPort = {
  bindings: fixtureBindings,
  project(name, records, options) {
    return fixtureBindings.get(name)?.project(records, options) ?? null;
  },
};

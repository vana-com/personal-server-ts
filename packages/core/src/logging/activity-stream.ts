import { createSystemStreamPager } from "../localdb/system-stream-page.js";
import type { AccessLogReader } from "./access-reader.js";
import type { JsonObject } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "../localdb/deps.js";
import { createSystemStreamStore } from "../localdb/system-streams.js";
import { isReservedSystemScope } from "../policy/reserved-scopes.js";
import type { AccessLogEntry, AccessLogWriter } from "./access-log.js";

export const ACCESS_ACTIVITY_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

export interface AccessActivityEvent extends JsonObject {
  schemaVersion: 1;
  eventId: string;
  instanceId: string;
  occurredAt: string;
  action: AccessLogEntry["action"];
  scope: string;
  grantId: string;
  builder: string;
  phase: "served-start";
}

/** No headers, network identities, request bodies or credentials belong here. */
export const ACCESS_ACTIVITY_DESCRIPTOR = {
  connector: "vana-system-access-v1",
  stream: "events",
  version: "1",
  primaryKey: ["eventId"],
  timestampField: "occurredAt",
  validate(data: JsonObject) {
    const fields = [
      "schemaVersion",
      "eventId",
      "instanceId",
      "occurredAt",
      "action",
      "scope",
      "grantId",
      "builder",
      "phase",
    ];
    if (
      Object.keys(data).length !== fields.length ||
      fields.some((key) => !(key in data)) ||
      data.schemaVersion !== 1 ||
      data.phase !== "served-start" ||
      !["read", "write", "delete", "lineage"].includes(String(data.action))
    )
      throw new Error("Invalid access activity event");
    if (
      typeof data.occurredAt !== "string" ||
      !Number.isFinite(Date.parse(data.occurredAt))
    )
      throw new Error("Invalid access activity timestamp");
    for (const key of ["eventId", "instanceId"])
      if (
        typeof data[key] !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          data[key],
        )
      )
        throw new Error("Invalid access activity identity");
    for (const key of ["eventId", "instanceId", "scope", "grantId", "builder"])
      if (typeof data[key] !== "string" || !data[key] || data[key].length > 512)
        throw new Error("Invalid access activity field");
  },
} as const;

/** One consumer of the generic reserved-system-stream mechanism. */
export function createAccessActivity(deps: LocalSyncDeps) {
  const store = createSystemStreamStore(deps, ACCESS_ACTIVITY_DESCRIPTOR);
  const page = createSystemStreamPager(deps, ACCESS_ACTIVITY_DESCRIPTOR);
  const reader: AccessLogReader = {
    async read(options) {
      await store.project();
      const result = await page(
        new Date(deps.now() - ACCESS_ACTIVITY_RETENTION_MS).toISOString(),
        options,
      );
      const { bodies, ...paging } = result;
      return {
        ...paging,
        logs: bodies.map((body) => {
          const event = JSON.parse(body) as AccessActivityEvent;
          return {
            ...event,
            logId: event.eventId,
            timestamp: event.occurredAt,
          };
        }),
      };
    },
  };
  const writer: AccessLogWriter = {
    async write(entry) {
      if (isReservedSystemScope(entry.scope)) return;
      await store.append({
        schemaVersion: 1,
        eventId: entry.logId,
        instanceId: await store.instanceId(),
        occurredAt: entry.timestamp,
        action: entry.action,
        scope: entry.scope,
        grantId: entry.grantId,
        builder: entry.builder,
        phase: "served-start",
      });
    },
  };
  return {
    ...writer,
    ...reader,
    drain: store.drain,
    project: store.project,
    prune: () =>
      store.removeBefore(
        new Date(deps.now() - ACCESS_ACTIVITY_RETENTION_MS).toISOString(),
      ),
  };
}

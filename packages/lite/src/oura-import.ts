import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  projectPdppRecordsToLegacyPayload,
  type PdppRecord,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { compareLegacyCoverage } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-coverage";
import { LEGACY_SCOPE_ENTITY_KEYS } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-entity-keys";

const STREAMS = ["sleep", "readiness", "activity"] as const;
export interface OuraBrowserImportInput {
  records: PdppRecord[];
  collectedAt: string;
  completion: {
    streams: {
      stream: (typeof STREAMS)[number];
      status: "complete";
      recordCount: number;
    }[];
  };
}
export type OuraBrowserImportResult =
  | { ok: true; scopes: string[] }
  | { ok: false; reason: string; scope?: string };

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Completed staged bodies are not proof of full historical coverage. Never delete old entities. */
export async function importOuraBrowserRecords(
  storage: DataStoragePort,
  input: OuraBrowserImportInput,
): Promise<OuraBrowserImportResult> {
  // This public boundary also receives untrusted JSON from the owner route.
  if (
    !object(input) ||
    !Array.isArray(input.records) ||
    ("complete" in input && input.complete === false) ||
    typeof input.collectedAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(
      input.collectedAt,
    ) ||
    !Number.isFinite(Date.parse(input.collectedAt)) ||
    new Date(input.collectedAt).toISOString() !==
      input.collectedAt.replace(
        /Z$/,
        input.collectedAt.includes(".") ? "Z" : ".000Z",
      ) ||
    !object(input.completion) ||
    !Array.isArray(input.completion.streams) ||
    input.completion.streams.length !== STREAMS.length
  ) {
    return { ok: false, reason: "invalid_completion" };
  }
  const counts = new Map<string, number>(STREAMS.map((stream) => [stream, 0]));
  const ids = new Set<string>();
  for (const record of input.records) {
    if (
      !object(record) ||
      !counts.has(record.stream) ||
      !object(record.data) ||
      typeof record.data.id !== "string" ||
      !record.data.id.trim()
    ) {
      return { ok: false, reason: "invalid_records" };
    }
    const key = JSON.stringify([record.stream, record.data.id]);
    if (ids.has(key)) return { ok: false, reason: "duplicate_record" };
    ids.add(key);
    counts.set(record.stream, counts.get(record.stream)! + 1);
    for (const field of [
      "timestamp",
      "daily_sleep_timestamp",
      "bedtime_start",
      "bedtime_end",
    ]) {
      const value = record.data[field];
      if (
        value !== undefined &&
        value !== null &&
        (typeof value !== "string" ||
          !/^\d{4}-\d{2}-\d{2}T/.test(value) ||
          !Number.isFinite(Date.parse(value)))
      ) {
        return { ok: false, reason: "invalid_records" };
      }
    }
  }
  const proven = new Set<string>();
  for (const proof of input.completion.streams) {
    if (
      !object(proof) ||
      !counts.has(proof.stream) ||
      proven.has(proof.stream) ||
      proof.status !== "complete" ||
      !Number.isSafeInteger(proof.recordCount) ||
      proof.recordCount < 0 ||
      proof.recordCount !== counts.get(proof.stream)
    ) {
      return { ok: false, reason: "invalid_completion" };
    }
    proven.add(proof.stream);
  }
  // Snapshot caller-owned input before awaiting locks/reads.
  const snapshot = structuredClone(input);
  return withScopeLock("oura.activity", () =>
    withScopeLock("oura.readiness", () =>
      withScopeLock("oura.sleep", () => importLocked(storage, snapshot)),
    ),
  );
}

async function importLocked(
  storage: DataStoragePort,
  input: OuraBrowserImportInput,
): Promise<OuraBrowserImportResult> {
  // Current connector records have no trusted upstream account identity.
  // Compare this complete batch alone; never union raw windows across requests.
  const plans = [];
  for (const stream of STREAMS) {
    const scope = `oura.${stream}`;
    const projection = projectPdppRecordsToLegacyPayload(scope, input.records, {
      profileKey: "oura-browser",
      fetchedStreams: [...STREAMS],
    });
    if (!projection.ok || (projection.diagnostics?.length ?? 0) > 0) {
      return { ok: false, reason: "projection_incomplete", scope };
    }
    const head = storage.findEntry({ scope });
    let headTime = head?.collectedAt;
    if (
      head?.producer === "pdpp-import-projection" &&
      head.producerProvenance
    ) {
      try {
        const provenance: unknown = JSON.parse(head.producerProvenance);
        if (
          object(provenance) &&
          provenance.method === "oura-browser" &&
          typeof provenance.sourceCollectedAt === "string"
        )
          headTime = provenance.sourceCollectedAt;
      } catch {
        return { ok: false, reason: "invalid_prior_provenance", scope };
      }
    }
    if (head) {
      const priorTime = Date.parse(headTime ?? "");
      if (
        !Number.isFinite(priorTime) ||
        Date.parse(input.collectedAt) < priorTime
      ) {
        return { ok: false, reason: "stale_collection", scope };
      }
      const legacy = await (
        storage.readStoredEnvelope ?? storage.readEnvelope
      ).call(storage, scope, head.collectedAt);
      const verdict = compareLegacyCoverage(legacy.data, projection.payload, {
        scope,
        entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
        projectionOmissions: projection.projectionOmissions,
        canonicalNewer: Date.parse(input.collectedAt) > priorTime,
        allowProvenDeletion: false,
      });
      if (!verdict.covered)
        return { ok: false, reason: verdict.reason!, scope };
      if (
        head.producer === "pdpp-import-projection" &&
        headTime === input.collectedAt &&
        JSON.stringify(legacy.data) === JSON.stringify(projection.payload)
      )
        continue;
    }
    // File names use collectedAt. Allocate a distinct instant on same-time import;
    // retain the source horizon separately so retries/freshness use collection time.
    const storedAt = new Date(
      Math.max(
        Date.parse(input.collectedAt),
        head ? Date.parse(head.collectedAt) + 1 : 0,
      ),
    ).toISOString();
    plans.push({
      scope,
      head,
      envelope: createDataFileEnvelope(scope, storedAt, projection.payload),
    });
  }
  // Recheck the selected heads after asynchronous reads, before touching any file.
  if (
    plans.some(
      ({ scope, head }) => storage.findEntry({ scope })?.path !== head?.path,
    )
  ) {
    return { ok: false, reason: "head_changed" };
  }
  for (const { scope, envelope } of plans) {
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      scope,
      collectedAt: envelope.collectedAt,
      path: write.relativePath,
      sizeBytes: write.sizeBytes,
      fileId: null,
      producer: "pdpp-import-projection",
      producerProvenance: JSON.stringify({
        method: "oura-browser",
        sourceCollectedAt: input.collectedAt,
      }),
    });
  }
  return { ok: true, scopes: STREAMS.map((stream) => `oura.${stream}`) };
}

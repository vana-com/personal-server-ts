import { withLegacyProjection } from "../storage/legacy-projection.js";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../api/index.js";
import { canonicalJsonBytes, sha256Hex } from "../contracts/index.js";
import { withScopeLock } from "../additions/index.js";
import type { DataStoragePort } from "../ports/index.js";
import {
  projectPdppRecordsToLegacyPayload,
  OURA_BROWSER_DECLARATION_DIGEST,
  type PdppRecord,
} from "../legacy-projection/index.js";
import { compareLegacyCoverage } from "../storage/legacy-scope-coverage.js";
import { LEGACY_SCOPE_ENTITY_KEYS } from "../storage/legacy-scope-entity-keys.js";
import { OURA_BROWSER_HISTORY_POLICY } from "./history-policy.js";

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
/** Ordinary owner-ingest effects supplied by the runtime after owner authentication. */
export type OuraBrowserImportOptions = Pick<
  PersonalServerDataApiDeps,
  | "syncManager"
  | "scopeDeletions"
  | "additions"
  | "onDataWritten"
  | "legacyScopeView"
> & {
  /** Node commits the validated current batch to its existing canonical store. */
  beforeCommit?: (
    input: OuraBrowserImportInput,
  ) => Promise<Extract<OuraBrowserImportResult, { ok: false }> | void>;
};
export interface OuraImportReceipt {
  scope: string;
  collectedAt: string;
  plaintextBytes: number;
}

export type OuraBrowserImportResult =
  | { ok: true; scopes: string[]; receipts: OuraImportReceipt[] }
  | { ok: false; reason: string; scope?: string };

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Completed staged bodies are not proof of full historical coverage. Never delete old entities. */
export async function importOuraBrowserRecords(
  storage: DataStoragePort,
  input: OuraBrowserImportInput,
  options: OuraBrowserImportOptions = {},
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
  // Ingest updates the per-scope first-seen ledger under its own scope lock.
  // Serialize imports with a distinct mutex; those locks are not re-entrant.
  return withScopeLock("ps-lite:oura-browser-import", () =>
    importLocked(storage, snapshot, options),
  );
}

async function importLocked(
  storage: DataStoragePort,
  input: OuraBrowserImportInput,
  options: OuraBrowserImportOptions,
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
    const served = await options.legacyScopeView?.readLatest(scope);
    if (
      served?.kind === "refused" &&
      !["no_connection", "no_synced_data"].includes(served.refusal.reason)
    )
      return { ok: false, reason: "canonical_view_unavailable", scope };
    if (served?.kind === "canonical") {
      if (
        Date.parse(input.collectedAt) < Date.parse(served.envelope.collectedAt)
      )
        return { ok: false, reason: "stale_collection", scope };
      const verdict = compareLegacyCoverage(
        served.envelope.data,
        projection.payload,
        {
          scope,
          entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
          projectionOmissions: projection.projectionOmissions,
          canonicalNewer:
            Date.parse(input.collectedAt) >
            Date.parse(served.envelope.collectedAt),
          ...OURA_BROWSER_HISTORY_POLICY,
        },
      );
      if (!verdict.covered)
        return { ok: false, reason: verdict.reason!, scope };
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
      // Stored PDPP heads constrain the next batch through the same projected
      // form apps read. Diagnostic omissions must never weaken this check.
      let legacy;
      try {
        legacy = await withLegacyProjection(storage, {
          onIssue: () => {
            throw new Error("Incomplete stored Oura projection");
          },
        }).readEnvelope(scope, head.collectedAt);
      } catch {
        return { ok: false, reason: "prior_projection_unavailable", scope };
      }
      const verdict = compareLegacyCoverage(legacy.data, projection.payload, {
        scope,
        entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
        projectionOmissions: projection.projectionOmissions,
        canonicalNewer: Date.parse(input.collectedAt) > priorTime,
        ...OURA_BROWSER_HISTORY_POLICY,
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
      collectedAt: storedAt,
      payload: projection.payload,
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
  const refused = await options.beforeCommit?.(input);
  if (refused) return refused;
  for (const { scope, collectedAt, payload, head } of plans) {
    const provenance = {
      method: "oura-browser",
      sourceCollectedAt: input.collectedAt,
      projector_version: "oura-browser-lite/1",
      declaration_digest: OURA_BROWSER_DECLARATION_DIGEST,
      inputs: [], // This batch has no durable canonical change cursor.
      payload_sha256: await sha256Hex(canonicalJsonBytes(payload)),
    };
    const encodedProvenance = btoa(JSON.stringify(provenance))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const headers = new Headers({
      "content-type": "application/json",
      "vana-producer": "pdpp-import-projection",
      "vana-producer-provenance": encodedProvenance,
    });
    if (storage.commitEnvelope) {
      if (head)
        headers.set("if-match", `"${head.casRevision ?? head.version}"`);
      else headers.set("if-none-match", "*");
    }
    // The public runtime authorizes the owner before entering this helper.
    // This in-process call runs the same body/provenance validation, tombstone
    // ordering, commit, additions ledger, derivative hook and sync path as POST.
    const response = await handlePersonalServerDataRequest(
      new Request(`https://ps-lite.internal/v1/data/${scope}`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      }),
      {
        ...options,
        storage,
        auth: {
          authorizeOwner: async () => {},
          authorizeBuilderList: async () => {
            throw new Error("Owner ingest only");
          },
          authorizeBuilderRead: async () => {
            throw new Error("Owner ingest only");
          },
        },
        accessLogWriter: { write: async () => {} },
        now: () => new Date(collectedAt),
      },
      { basePath: "/v1/data" },
    );
    if (!response.ok) {
      const failure = (await response.json()) as { error?: string };
      return { ok: false, reason: failure.error ?? "ingest_failed", scope };
    }
  }
  const receipts: OuraImportReceipt[] = [];
  for (const stream of STREAMS) {
    const scope = `oura.${stream}`;
    const current = await options.legacyScopeView?.readLatest(scope);
    if (current?.kind === "refused")
      return { ok: false, reason: "canonical_view_unavailable", scope };
    const head = storage.findEntry({ scope });
    const envelope =
      current?.kind === "canonical"
        ? current.envelope
        : head
          ? await (storage.readStoredEnvelope ?? storage.readEnvelope).call(
              storage,
              scope,
              head.collectedAt,
            )
          : null;
    if (!envelope)
      return { ok: false, reason: "committed_head_unavailable", scope };
    receipts.push({
      scope,
      collectedAt: envelope.collectedAt,
      plaintextBytes: new TextEncoder().encode(JSON.stringify(envelope))
        .byteLength,
    });
  }
  return {
    ok: true,
    scopes: STREAMS.map((stream) => `oura.${stream}`),
    receipts,
  };
}

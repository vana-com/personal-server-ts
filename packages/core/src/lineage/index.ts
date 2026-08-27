export {
  LINEAGE_FIELD,
  LINEAGE_KEY,
  LOCAL_SCOPE_SCAN_PAGE,
  MAX_LINEAGE_SOURCES,
  assertDerivedScopeNaming,
  derivedScopeViolatesNaming,
  extractLineageField,
  hasReservedLineageKey,
  parseLineageSources,
  prepareLineage,
  readStoredLineage,
  resolveLineageSources,
  scopeNamespace,
  stampLineage,
  type LineageDataPointRecord,
  type LineageSourceLookup,
  type PrepareLineageInput,
  type ResolveLineageSourcesInput,
  type ResolvedLineageSource,
  type StoredLineage,
} from "./lineage.js";
export {
  createGatewayLineageClient,
  type GatewayLineageClientOptions,
  type GatewayProof,
  type GetLineageInput,
  type LineageGatewayPort,
  type LineageGatewayResult,
  type LineageNode,
  type LineageView,
  type RegisterDataPointWithLineageParams,
  type RegisterDataPointWithLineageResult,
} from "./gateway.js";
export {
  LINEAGE_ATTESTATION_TYPES,
  type LineageAttestationMessage,
} from "./attestation.js";
export { computeDataPointId } from "../sync/data-point-id.js";

/** Compile-time reader boundary. This file is included by the server typecheck. */
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import type { ReplicaReader } from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";

declare const _receiver: ReturnType<typeof createReplicaReceiver>;
type Owner = ReturnType<typeof _receiver.readStore<"owner">>;
type Grant = ReturnType<typeof _receiver.readStore<"grant">>;
type DefaultOrUnion = ReturnType<typeof _receiver.readStore<ReplicaReader>>;
type Assert<T extends true> = T;
type HasDiagnostics<T> = "readCopyConflicts" extends keyof T
  ? "listCopyConflicts" extends keyof T
    ? true
    : false
  : false;
type NoDiagnostics<T> =
  Extract<"readCopyConflicts" | "listCopyConflicts", keyof T> extends never
    ? true
    : false;
export type ReplicaReaderCapabilityChecks = [
  Assert<HasDiagnostics<Owner>>,
  Assert<NoDiagnostics<Grant>>,
  Assert<NoDiagnostics<DefaultOrUnion>>,
];

import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { StreamDeclaration } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

/** Resolve a stream using only facts retained with the approved grant. */
export function streamDeclarationFromSnapshot(
  snapshot: DeclarationSnapshot,
  streamName: string,
): StreamDeclaration | undefined {
  const stream = snapshot.streams.find(({ name }) => name === streamName);
  if (!stream) return undefined;
  return {
    name: stream.name,
    semantics: stream.semantics ?? "mutable_state",
    primaryKey: stream.primary_key,
    cursorField: "emitted_at",
    consentTimeField: stream.consent_time_field,
    requiredFields: stream.required_fields,
    declaredFields: stream.fields,
    ...(stream.schema && { schema: stream.schema }),
    ...(stream.selection && { selection: stream.selection }),
  };
}

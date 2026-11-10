/** Immutable writer-qualified reference, shared without loading the ingress schema. */
export function operationReferenceOf(operation: {
  revision: { writerId: string; operationId: string };
}): { writerId: string; operationId: string } {
  return {
    writerId: operation.revision.writerId,
    operationId: operation.revision.operationId,
  };
}

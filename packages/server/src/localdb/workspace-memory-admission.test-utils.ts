export interface WorkspaceMemoryAdmission {
  readonly availableGiB: number;
  readonly fullAvg60: number;
}

/** Runner imports can change pressure after outer admission. Check again in
 * the workload process, before creating a database or taking an RSS baseline.
 * Keep the same thresholds; wait rather than measuring an invalid admission. */
export async function awaitWorkspaceMemoryAdmission(
  sample: () => Promise<WorkspaceMemoryAdmission>,
  wait: () => Promise<void>,
): Promise<WorkspaceMemoryAdmission> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const admission = await sample();
    if (admission.availableGiB >= 16 && admission.fullAvg60 < 1)
      return admission;
    if (attempt < 3) await wait();
  }
  throw new Error("workspace_memory_gate_closed: no measurement started");
}

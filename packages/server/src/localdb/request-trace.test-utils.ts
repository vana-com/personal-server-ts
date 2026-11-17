// Counts the requests a device makes and the longest chain of requests that
// each had to wait for an earlier one. Every request is held for a fixed
// latency, so a dependency chain and a set of concurrent requests differ in
// order of events, not in wall time on the host: a request that begins after
// another ended may have waited for it; one that begins before cannot have.
export type TracedRequest = {
  readonly kind: string;
  readonly label: string;
  readonly begin: number;
  readonly end: number;
};

export function requestTrace(
  /**
   * How long each request is held: a fixed time, or one per request from its
   * kind and how many of that kind came before it (to make requests that the
   * code issues together answer at different times, as a loaded host does).
   */
  latencyMs: number | ((kind: string, nth: number) => number) = 5,
) {
  const requests: TracedRequest[] = [];
  const begun = new Map<string, number>();
  let tick = 0;
  const track = async <T>(
    kind: string,
    label: string,
    run: () => Promise<T>,
  ): Promise<T> => {
    const begin = ++tick;
    const nth = begun.get(kind) ?? 0;
    begun.set(kind, nth + 1);
    const wait =
      typeof latencyMs === "number" ? latencyMs : latencyMs(kind, nth);
    await new Promise((resolve) => setTimeout(resolve, wait));
    try {
      return await run();
    } finally {
      requests.push({ kind, label, begin, end: ++tick });
    }
  };
  /** Requests that ended by the time `of` began: what `of` may have waited for. */
  const depthOf = (of: TracedRequest): number => {
    const memo = new Map<TracedRequest, number>();
    const depth = (r: TracedRequest): number => {
      const known = memo.get(r);
      if (known !== undefined) return known;
      let deepest = 0;
      for (const other of requests)
        if (other.end < r.begin) deepest = Math.max(deepest, depth(other));
      memo.set(r, deepest + 1);
      return deepest + 1;
    };
    return depth(of);
  };
  return {
    requests,
    track,
    count: (kind?: string) =>
      requests.filter((r) => kind === undefined || r.kind === kind).length,
    /** Serial depth of the last request of `kind`: the chain that ends in it. */
    depthToLast: (kind: string) => {
      const last = requests.filter((r) => r.kind === kind).at(-1);
      return last ? depthOf(last) : 0;
    },
    /** Serial depth of the whole trace. */
    depth: () => Math.max(0, ...requests.map(depthOf)),
    clear: () => {
      requests.length = 0;
      begun.clear();
    },
    /** `kind:label` in order of beginning, for a failure message. */
    describe: () =>
      [...requests]
        .sort((a, b) => a.begin - b.begin)
        .map((r) => `${r.kind}${r.label ? ":" + r.label : ""}`)
        .join(" "),
  };
}
export type RequestTrace = ReturnType<typeof requestTrace>;

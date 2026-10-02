// Explicit classification of every legacy-vs-projection difference the oracle
// has observed. A difference that matches no rule stays UNCLASSIFIED and makes
// generate.mjs exit non-zero, so new drift cannot hide behind an old label.
// Rules are deliberately narrow (scope + path shape + value shape).
const ABSENT = "<absent>";
const isIsoZ = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v);
const isIsoAny = (v) => typeof v === "string" && !Number.isNaN(Date.parse(v));

const RULES = [
  {
    scope: "chatgpt.conversations",
    path: /^conversations\[id=[^\]]+\]\.create_time$/,
    when: (l, p) => typeof l === "number" && isIsoZ(p) && Math.abs(l * 1000 - Date.parse(p)) < 1,
    category: "time-format: epoch seconds (legacy) vs ISO-8601 string (projected)",
    cause: "legacy 4.0.0 discovers ids via /conversations/search, whose items have no create_time, so toConversationRecord falls back to the detail body's epoch-float create_time; the PDPP conversations stream stores ISO (ms, Z). Same instant.",
  },
  {
    scope: "chatgpt.conversations",
    path: /^conversations\[id=[^\]]+\]\.update_time$/,
    when: (l, p) => isIsoAny(l) && isIsoZ(p) && Date.parse(l) === Date.parse(p) && l !== p,
    category: "time-format: ISO precision/offset (legacy verbatim provider string vs projected ms+Z)",
    cause: "legacy copies the search item's update_time string verbatim (microseconds, +00:00 in this fixture); PDPP normalises to toISOString() form. Same instant. Fixture assumption: search update_time is an ISO string; if the provider returns epoch numbers legacy would emit a number here.",
  },
  {
    scope: "chatgpt.conversations",
    path: /^conversations\[id=[^\]]+\]\.messages\[id=[^\]]+\]\.content$/,
    when: (l, p) => typeof l === "string" && typeof p === "string" && /^\[asset:[^\]]+\]\n/.test(p) && p.replace(/^(\[asset:[^\]]+\]\n)+/, "") === l,
    category: "content normalisation: [asset:...] placeholder for non-string multimodal parts",
    cause: "legacy walkMessages joins only string parts; the PDPP connector renders image_asset_pointer parts as `[asset:<asset_pointer>]` lines before the text, and the adapter passes content through.",
  },
  {
    scope: "chatgpt.conversations",
    path: /^conversations\[id=[^\]]+\]\.messages\[id=[^\]]+\]$/,
    when: (l, p, ctx) => l !== ABSENT && p === ABSENT && ctx.pastCurrentNode(ctx.path),
    category: "branch walk past current_node (legacy includes descendants of current_node)",
    cause: "legacy walkMessages keeps walking from current_node into its last child; the adapter stops at current_node (messages with on_current_branch=true, chain from current_node to root).",
  },
  {
    scope: "chatgpt.conversations",
    path: /^conversations\[id=[^\]]+\]\.message_count$/,
    when: (l, p, ctx) => typeof l === "number" && typeof p === "number" && l > p && ctx.pastCurrentNodeCount(ctx.path) === l - p,
    category: "branch walk past current_node (message_count follows the extra messages)",
    cause: "message_count is the retained message count on both sides; it differs by exactly the messages legacy kept past current_node.",
  },
  {
    scope: "claude.conversations",
    path: /^conversations\[id=[^\]]+\]\.fetchError$/,
    when: (l, p) => l === null && p === ABSENT,
    category: "missing key (legacy-only constant): fetchError",
    cause: "legacy claude-export always writes fetchError: null; the binding omits it (documented in the binding's lossy note).",
  },
  {
    scope: "claude.projects",
    path: /^projects\[id=[^\]]+\]\.detail\.raw_docs$/,
    when: (l, p) => l === ABSENT && Array.isArray(p),
    category: "extra key (projection-only): detail.raw_docs",
    cause: "legacy detail is the raw project JSON, which has no raw_docs key; the adapter adds raw_docs from the PDPP projects stream.",
  },
  {
    scope: "claude.projects",
    path: /^projects\[id=[^\]]+\]\.detail\.archived_at$/,
    when: (l, p) => l === ABSENT && p === null,
    category: "extra key (projection-only, null): detail.archived_at",
    cause: "the raw project JSON has no archived_at key unless archived; the PDPP projects stream always carries archived_at (null when absent) and the adapter copies any defined value.",
  },
  {
    scope: "claude.projects",
    path: /^projects\[id=[^\]]+\]\.detail\.docs\[[^\]]+\]\.updated_at$/,
    when: (l, p) => l === ABSENT && p === null,
    category: "extra key (projection-only, null): detail.docs[].updated_at",
    cause: "raw export docs carry no updated_at; project_documents.update_time is null and the adapter always writes updated_at.",
  },
  {
    scope: "claude.projects",
    path: /^projects\[id=[^\]]+\]\.detail\.(description|prompt_template)$/,
    when: (l, p) => l === "" && p === null,
    category: "value normalisation: empty string (legacy raw) vs null (projected)",
    cause: "legacy detail is the raw project JSON (\"\"); the PDPP connector maps empty description/prompt_template to null in the projects stream.",
  },
  {
    scope: "claude.projects",
    path: /^projects\[id=[^\]]+\]\.detail\.docs\[\d+\]$/,
    when: (l, p) => l && typeof l === "object" && l.uuid === undefined && p === ABSENT,
    category: "missing element: raw doc without uuid is absent from detail.docs",
    cause: "the PDPP connector emits project_documents only for docs with a uuid, and detail.docs is built from project_documents; the doc survives only inside detail.raw_docs.",
  },
];

export function classify(scope, row, { legacy, streams }) {
  // Helpers bound to this scope's data.
  const conv = (path) => {
    const id = path.match(/^conversations\[id=([^\]]+)\]/)?.[1];
    return id ? { id, conv: streams.conversations?.find((c) => c.id === id), legacy: legacy.conversations?.find((c) => c.id === id) } : null;
  };
  const ctx = {
    path: row.path,
    // legacy message whose node is a descendant of the conversation's current_node
    pastCurrentNode: (path) => {
      const c = conv(path);
      const mid = path.match(/\.messages\[id=([^\]]+)\]$/)?.[1];
      const msg = streams.messages?.find((m) => m.id === mid);
      if (!c?.conv || !msg) return false;
      const byId = new Map(streams.messages.filter((m) => m.conversation_id === c.id).map((m) => [m.id, m]));
      for (let cur = byId.get(msg.parent_id); cur; cur = byId.get(cur.parent_id)) if (cur.id === c.conv.current_node) return true;
      return false;
    },
    pastCurrentNodeCount: (path) => {
      const c = conv(path);
      if (!c?.legacy) return -1;
      return c.legacy.messages.filter((m) => ctx.pastCurrentNode(`conversations[id=${c.id}].messages[id=${m.id}]`)).length;
    },
  };
  for (const rule of RULES) {
    if (rule.scope !== scope || !rule.path.test(row.path)) continue;
    if (rule.when(row.legacy, row.projected, ctx)) return { category: rule.category, cause: rule.cause };
  }
  return { category: "UNCLASSIFIED", cause: "no rule matched; investigate" };
}

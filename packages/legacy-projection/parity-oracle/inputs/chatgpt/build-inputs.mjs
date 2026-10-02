// Authoring script for the synthetic ChatGPT upstream fixture. All values are
// invented. Shapes follow the ChatGPT web backend as used by both connectors
// (see REPORT.md "ChatGPT inputs" for which fields are assumptions).
// Run once: node inputs/chatgpt/build-inputs.mjs  (writes JSON next to it).
import { writeFileSync } from "node:fs";
const here = new URL(".", import.meta.url);
const T0 = 1789200000; // 2026-09-12T08:00:00Z
const iso = (epoch) => new Date(epoch * 1000).toISOString().replace("Z", "000+00:00").replace(/\.(\d{3})000\+/, ".$1000+");
const msg = (id, role, content, create_time, metadata = {}, extra = {}) => ({
  id, author: { role, name: extra.authorName ?? null, metadata: {} }, create_time, update_time: null,
  content, status: "finished_successfully", end_turn: extra.end_turn ?? (role === "assistant" ? true : null),
  weight: extra.weight ?? 1, metadata, recipient: extra.recipient ?? "all", channel: null,
});
const text = (...parts) => ({ content_type: "text", parts });
const node = (id, parent, children, message) => ({ id, message: message ?? null, parent, children });

function conversation(id, title, create, update, current, nodes, extra = {}) {
  return {
    title, create_time: create, update_time: update,
    mapping: Object.fromEntries(nodes.map((n) => [n.id, n])),
    moderation_results: [], current_node: current, plugin_ids: null,
    conversation_id: id, id, conversation_template_id: null, gizmo_id: null, gizmo_type: null,
    is_archived: false, is_starred: null, safe_urls: [], blocked_urls: [],
    default_model_slug: extra.default_model_slug ?? "auto", conversation_origin: null,
    voice: null, async_status: null, disabled_tool_ids: [], is_do_not_remember: false,
    memory_scope: "global_enabled",
  };
}

const C1 = "6700a1b2-0000-4000-8000-00000000c001";
const C2 = "6700a1b2-0000-4000-8000-00000000c002";
const C3 = "6700a1b2-0000-4000-8000-00000000c003";
const C4 = "6700a1b2-0000-4000-8000-00000000c004";
const id = (c, n) => `${c.slice(-4)}-${n}`;

// C1: branching conversation. u1 has two assistant children; the older one
// (a1-old) has its own continuation and is NOT on the current branch. The
// current branch includes a multimodal user turn with an image asset part.
const c1 = conversation(C1, "Weekend trip planning", T0, T0 + 900, id(C1, "a2"), [
  node("client-created-root", null, [id(C1, "sys")]),
  node(id(C1, "sys"), "client-created-root", [id(C1, "u1")],
    msg(id(C1, "sys"), "system", text(""), null, { is_visually_hidden_from_conversation: true }, { weight: 0 })),
  node(id(C1, "u1"), id(C1, "sys"), [id(C1, "a1-old"), id(C1, "a1-new")],
    msg(id(C1, "u1"), "user", text("Plan a weekend in Lisbon for two."), T0 + 10.5)),
  node(id(C1, "a1-old"), id(C1, "u1"), [id(C1, "u2-old")],
    msg(id(C1, "a1-old"), "assistant", text("Draft itinerary: day one Alfama, day two Sintra."), T0 + 20.25,
      { model_slug: "gpt-4o", finish_details: { type: "stop" } })),
  node(id(C1, "u2-old"), id(C1, "a1-old"), [],
    msg(id(C1, "u2-old"), "user", text("Make it cheaper."), T0 + 30)),
  node(id(C1, "a1-new"), id(C1, "u1"), [id(C1, "u2")],
    msg(id(C1, "a1-new"), "assistant", text("Here is a two-day plan: Alfama walk, tram 28, then Belem."), T0 + 40.75,
      { model_slug: "gpt-4o", finish_details: { type: "stop" } })),
  node(id(C1, "u2"), id(C1, "a1-new"), [id(C1, "a2")],
    msg(id(C1, "u2"), "user", {
      content_type: "multimodal_text",
      parts: [
        { content_type: "image_asset_pointer", asset_pointer: "file-service://file-SynthImage0001", size_bytes: 123456, width: 1024, height: 768, fovea: null, metadata: { dalle: null, sanitized: true } },
        "What is this building?",
      ],
    }, T0 + 600, { attachments: [{ id: "file-SynthImage0001", name: "photo.jpg", mime_type: "image/jpeg", size: 123456 }] })),
  node(id(C1, "a2"), id(C1, "u2"), [],
    msg(id(C1, "a2"), "assistant", text("That looks like the Belem Tower."), T0 + 610,
      { model_slug: "gpt-4o", finish_details: { type: "stop" } })),
]);

// C2: tool use. Assistant writes code to the python tool, the tool returns
// execution_output, the assistant answers. The final answer has no
// model_slug in metadata.
const c2 = conversation(C2, "CSV analysis", T0 + 3600, T0 + 4000, id(C2, "a2"), [
  node("client-created-root", null, [id(C2, "u1")]),
  node(id(C2, "u1"), "client-created-root", [id(C2, "a1")],
    msg(id(C2, "u1"), "user", text("Which region sold the most?"), T0 + 3601,
      { attachments: [{ id: "file-SynthCsv0002", name: "sales.csv", mime_type: "text/csv", size: 2048 }] })),
  node(id(C2, "a1"), id(C2, "u1"), [id(C2, "t1")],
    msg(id(C2, "a1"), "assistant", { content_type: "code", language: "unknown", response_format_name: null, text: "import pandas as pd\ndf = pd.read_csv('/mnt/data/sales.csv')\ndf.groupby('region').total.sum()" },
      T0 + 3602, { model_slug: "gpt-4o" }, { recipient: "python", end_turn: false })),
  node(id(C2, "t1"), id(C2, "a1"), [id(C2, "a2")],
    msg(id(C2, "t1"), "tool", { content_type: "execution_output", text: "region\nnorth    10\nsouth     7" },
      T0 + 3603, { aggregate_result: { status: "success" } }, { authorName: "python" })),
  node(id(C2, "a2"), id(C2, "t1"), [],
    msg(id(C2, "a2"), "assistant", text("North sold the most, with a total of 10."), T0 + 3604, {})),
]);

// C3: no title, no model on any message, and current_node is NOT the leaf:
// the assistant turn it points at has one later child (a user draft).
const c3 = conversation(C3, null, T0 + 7200, T0 + 7300, id(C3, "a1"), [
  node("client-created-root", null, [id(C3, "u1")]),
  node(id(C3, "u1"), "client-created-root", [id(C3, "a1")],
    msg(id(C3, "u1"), "user", text("hello?"), T0 + 7201)),
  node(id(C3, "a1"), id(C3, "u1"), [id(C3, "u2")],
    msg(id(C3, "a1"), "assistant", text("Hi! How can I help?"), T0 + 7202, {})),
  node(id(C3, "u2"), id(C3, "a1"), [],
    msg(id(C3, "u2"), "user", text("never mind"), T0 + 7203)),
], { default_model_slug: null });

// C4: reasoning model. Includes user_editable_context, thoughts,
// reasoning_recap, an empty assistant text, and a multi-part text answer.
const c4 = conversation(C4, "Prime proof", T0 + 10800, T0 + 11000, id(C4, "a3"), [
  node("client-created-root", null, [id(C4, "ctx")]),
  node(id(C4, "ctx"), "client-created-root", [id(C4, "u1")],
    msg(id(C4, "ctx"), "user", { content_type: "user_editable_context", user_profile: "Synthetic profile text.", user_instructions: "Be brief." }, null,
      { is_visually_hidden_from_conversation: true, user_context_message_data: { about_user_message: "Synthetic profile text." } })),
  node(id(C4, "u1"), id(C4, "ctx"), [id(C4, "th")],
    msg(id(C4, "u1"), "user", text("Prove there are infinitely many primes."), T0 + 10801)),
  node(id(C4, "th"), id(C4, "u1"), [id(C4, "rr")],
    msg(id(C4, "th"), "assistant", { content_type: "thoughts", thoughts: [{ summary: "Euclid", content: "Assume finitely many and multiply them.", chunks: [], finished: true }], source_analysis_msg_id: "synthetic" },
      T0 + 10802, { model_slug: "o3", reasoning_status: "is_reasoning" }, { end_turn: false })),
  node(id(C4, "rr"), id(C4, "th"), [id(C4, "a-empty")],
    msg(id(C4, "rr"), "assistant", { content_type: "reasoning_recap", content: "Thought for 4 seconds" }, T0 + 10803, { model_slug: "o3", reasoning_status: "reasoning_ended" }, { end_turn: false })),
  node(id(C4, "a-empty"), id(C4, "rr"), [id(C4, "a3")],
    msg(id(C4, "a-empty"), "assistant", text(""), T0 + 10804, { model_slug: "o3" }, { end_turn: false })),
  node(id(C4, "a3"), id(C4, "a-empty"), [],
    msg(id(C4, "a3"), "assistant", text("Suppose the primes are finite.", "Their product plus one has a new prime factor."), T0 + 10805,
      { model_slug: "o3", finish_details: { type: "stop" } })),
]);

// C5: an older conversation (June 2026), outside a 30-day window ending
// 2026-10-01; used by the time-window variant.
const C5 = "6700a1b2-0000-4000-8000-00000000c005";
const T5 = 1781000000; // 2026-06-09T10:13:20Z
const c5 = conversation(C5, "Old packing list", T5, T5 + 120, id(C5, "a1"), [
  node("client-created-root", null, [id(C5, "u1")]),
  node(id(C5, "u1"), "client-created-root", [id(C5, "a1")], msg(id(C5, "u1"), "user", text("Packing list for camping?"), T5 + 1)),
  node(id(C5, "a1"), id(C5, "u1"), [], msg(id(C5, "a1"), "assistant", text("Tent, sleeping bag, stove, water filter."), T5 + 2, { model_slug: "gpt-4o-mini", finish_details: { type: "stop" } })),
]);

const conversations = [c1, c2, c3, c4, c5];
// Newest first, as the list/search endpoints return them.
const newestFirst = [...conversations].sort((a, b) => b.update_time - a.update_time);
const listItems = newestFirst.map((c) => ({
  id: c.id, title: c.title, create_time: iso(c.create_time), update_time: iso(c.update_time),
  mapping: null, current_node: null, conversation_template_id: null, gizmo_id: null,
  is_archived: false, is_starred: null, is_do_not_remember: false, workspace_id: null, async_status: null,
  safe_urls: [], blocked_urls: [], conversation_origin: null, snippet: null,
}));
const searchItems = newestFirst.map((c) => ({
  conversation_id: c.id, current_node_id: c.current_node, title: c.title, is_archived: false,
  update_time: iso(c.update_time),
  payload: { kind: "message", message_id: c.current_node, snippet: null },
}));
const memories = {
  memories: [
    { id: "mem-synth-0001", content: "Prefers metric units.", created_at: "2026-08-01T10:00:00.123456+00:00", updated_at: "2026-08-02T11:30:00.654321+00:00" },
    { id: "mem-synth-0002", content: "Is learning Portuguese.", created_at: null, updated_at: "2026-09-03T09:15:00.000000+00:00" },
    { id: "mem-synth-0003", content: "Has a dog named Pixel.", created_at: "2026-07-20T08:00:00.000000+00:00" },
  ],
  memory_max_tokens: 10000,
  memory_num_tokens: 42,
};
const session = {
  user: { id: "user-synthetic0001", name: "Synthetic User", email: "synthetic.user@example.invalid", image: null, picture: null, idp: "auth0", iat: 1789000000, mfa: false },
  expires: "2026-12-30T00:00:00.000Z",
  accessToken: "synthetic-access-token",
  authProvider: "auth0",
};
const out = { "conversations.json": conversations, "list-items.json": listItems, "search-items.json": searchItems, "memories.json": memories, "session.json": session };
for (const [name, value] of Object.entries(out)) writeFileSync(new URL(name, here), `${JSON.stringify(value, null, 2)}\n`);
console.log("wrote", Object.keys(out).join(", "));

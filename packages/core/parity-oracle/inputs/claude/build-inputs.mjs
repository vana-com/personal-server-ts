// Authoring script for the synthetic Claude upstream fixture. All values are
// invented. Entry names and JSON keys follow the real Claude export structure
// recorded (values-free) in data-connectors
// connectors/anthropic/__fixtures__/split-export (observed 2026-09-22) and
// fixtures/scrubbed/pilot-real-shape, packed in the OLD single-archive layout
// (one ZIP: users.json, conversations.json, projects/<uuid>.json) because that
// is the only layout the legacy claude-export 2.0.1 script can read.
// Run once: node inputs/claude/build-inputs.mjs
import { writeFileSync } from "node:fs";
const here = new URL(".", import.meta.url);
const ORG = "0a9e1f00-0000-4000-8000-0000000000a1";
const USER = "0a9e1f00-0000-4000-8000-0000000000u1".replace("u1", "b1");
const ROOT_PARENT = "00000000-0000-4000-8000-000000000000";
const ts = (s) => `2026-09-${s}Z`;
const block = (type, extra) => ({ start_timestamp: null, stop_timestamp: null, flags: null, type, ...extra });
const textBlock = (text) => block("text", { text, citations: [] });
const UNSUPPORTED = "\n```\nThis block is not supported on your current device yet.\n```\n";
const m = (uuid, sender, created, text, content, extra = {}) => ({
  uuid, text, content, sender, created_at: created, updated_at: extra.updated_at ?? created,
  attachments: extra.attachments ?? [], files: extra.files ?? [], parent_message_uuid: extra.parent ?? ROOT_PARENT,
});

const P1 = "0a9e1f00-0000-4000-8000-0000000000d1";
const P2 = "0a9e1f00-0000-4000-8000-0000000000d2";
const P3 = "0a9e1f00-0000-4000-8000-0000000000d3";
const K = (n) => `0a9e1f00-0000-4000-8000-00000000c00${n}`;
const M = (c, n) => `0a9e1f00-0000-4000-8000-000000000${c}0${n}`;

const conversations = [
  { // K1: starred, in project P1, tool use + thinking blocks, attachment, out-of-order messages.
    uuid: K(1), name: "Debugging a flaky test", summary: "", created_at: ts("10T09:00:00.000000"), updated_at: ts("10T09:30:00.000000"),
    is_starred: true, project_uuid: P1, account: { uuid: USER },
    chat_messages: [
      m(M(1, 2), "assistant", ts("10T09:01:00.000000"),
        `Let me check the test runner.${UNSUPPORTED}${UNSUPPORTED}The test depends on wall-clock time.`,
        [block("thinking", { thinking: "The user wants the cause.", summaries: [], cut_off: false }), textBlock("Let me check the test runner."),
         block("tool_use", { id: "toolu_synth01", name: "bash", input: { command: "npm test" }, message: null, integration_name: null }),
         block("tool_result", { tool_use_id: "toolu_synth01", name: "bash", content: [{ type: "text", text: "1 failed" }], is_error: false }),
         textBlock("The test depends on wall-clock time.")],
        { parent: M(1, 1) }),
      m(M(1, 1), "human", ts("10T09:00:30.000000"), "Why does this test fail only on CI?", [textBlock("Why does this test fail only on CI?")],
        { attachments: [{ file_name: "ci.log", file_size: 18, file_type: "txt", extracted_content: "FAIL clock.test.ts" }],
          files: [{ file_uuid: "0a9e1f00-0000-4000-8000-0000000000f1", file_name: "ci.log" }] }),
      m(M(1, 3), "human", ts("10T09:05:00.000000"), "Thanks, that fixed it.", [textBlock("Thanks, that fixed it.")], { parent: M(1, 2), updated_at: ts("10T09:06:00.000000") }),
    ],
  },
  { // K2: empty name, non-empty summary; not starred.
    uuid: K(2), name: "", summary: "Recipe ideas for a dinner party", created_at: ts("11T18:00:00.000000"), updated_at: ts("11T18:10:00.000000"),
    is_starred: false, project_uuid: null, account: { uuid: USER },
    chat_messages: [
      m(M(2, 1), "human", ts("11T18:00:00.000000"), "Ideas for six people?", [textBlock("Ideas for six people?")]),
      m(M(2, 2), "assistant", ts("11T18:00:10.000000"), "Try a paella and a green salad.", [textBlock("Try a paella and a green salad.")], { parent: M(2, 1) }),
    ],
  },
  { // K3: no name or summary, no is_starred/project_uuid keys; one message has an
    // empty `text` and carries its words only in content blocks.
    uuid: K(3), name: "", summary: "", created_at: ts("12T07:00:00.000000"), updated_at: ts("12T07:01:00.000000"),
    account: { uuid: USER },
    chat_messages: [
      m(M(3, 1), "human", ts("12T07:00:00.000000"), "", [textBlock("Block-only question?"), textBlock("Second block.")]),
      m(M(3, 2), "assistant", ts("12T07:00:05.000000"), "Block-only answer.", [textBlock("Block-only answer.")], { parent: M(3, 1) }),
    ],
  },
  { // K4: a conversation with no messages.
    uuid: K(4), name: "Empty chat", summary: "", created_at: ts("13T12:00:00.000000"), updated_at: ts("13T12:00:00.000000"),
    is_starred: false, project_uuid: null, account: { uuid: USER }, chat_messages: [],
  },
  { // K5: an older conversation (June 2026), outside a 30-day window ending 2026-10-01.
    uuid: K(5), name: "Old travel notes", summary: "", created_at: "2026-06-01T10:00:00.000000Z", updated_at: "2026-06-01T10:05:00.000000Z",
    is_starred: false, project_uuid: null, account: { uuid: USER },
    chat_messages: [
      m(M(5, 1), "human", "2026-06-01T10:00:00.000000Z", "Best time to visit Porto?", [textBlock("Best time to visit Porto?")]),
      m(M(5, 2), "assistant", "2026-06-01T10:00:05.000000Z", "Late spring or early autumn.", [textBlock("Late spring or early autumn.")], { parent: M(5, 1) }),
    ],
  },
];

const creator = { uuid: USER, full_name: "Synthetic Claude User" };
const projects = [
  { uuid: P1, name: "Design System", description: "Tokens and components.", is_private: true, is_starter_project: false,
    prompt_template: "Answer as a design-system reviewer.", created_at: ts("01T00:00:00.000000"), updated_at: ts("09T00:00:00.000000"), creator,
    docs: [
      { uuid: "0a9e1f00-0000-4000-8000-00000000d011", filename: "tokens.md", content: "# Tokens\nspacing-1: 4px", created_at: ts("02T00:00:00.000000") },
      { filename: "id-less.md", content: "A document without a uuid.", created_at: ts("03T00:00:00.000000") },
    ] },
  { uuid: P2, name: "Old Research", description: "", is_private: true, is_starter_project: false, prompt_template: "",
    created_at: "2026-03-01T00:00:00.000000Z", updated_at: "2026-05-01T00:00:00.000000Z", archived_at: "2026-05-01T00:00:00.000000Z", creator, docs: [] },
  { uuid: P3, name: "How to use Claude", description: "An example project.", is_private: false, is_starter_project: true, prompt_template: "",
    created_at: ts("05T00:00:00.000000"), updated_at: ts("05T00:00:00.000000"), creator: null,
    docs: [{ uuid: "0a9e1f00-0000-4000-8000-00000000d031", filename: "intro.md", content: "Example content.", created_at: ts("05T00:00:00.000000") }] },
];
const users = [{ uuid: USER, full_name: "Synthetic Claude User", email_address: "synthetic.claude@example.invalid", verified_phone_number: "" }];

const entries = [
  ["users.json", users],
  ["conversations.json", conversations],
  ...projects.map((p) => [`projects/${p.uuid}.json`, p]),
];
const organizations = [
  { uuid: ORG, name: "synthetic.claude@example.invalid's Organization", capabilities: ["chat", "claude_pro"], rate_limit_tier: "default_claude_ai", billing_type: "stripe_subscription", raven_type: null, active_flags: [] },
];
const site = { organizationId: ORG, nonce: "nonce-synthetic-0001", signedUrl: "https://storage.claude-export.test/export.zip?sig=synthetic",
  menuName: "Synthetic Claude User", menuPlan: "Pro plan" };
writeFileSync(new URL("export-entries.json", here), `${JSON.stringify(entries, null, 2)}\n`);
writeFileSync(new URL("organizations.json", here), `${JSON.stringify(organizations, null, 2)}\n`);
writeFileSync(new URL("site.json", here), `${JSON.stringify(site, null, 2)}\n`);
console.log("wrote export-entries.json organizations.json site.json");

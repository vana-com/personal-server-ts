---
id: chatgpt
title: ChatGPT export
profileVersion: 1
schemaVersion: chatgpt-export/2026-08
scopes:
  - chatgpt.*
summary: ChatGPT conversation export. Each conversation is a tree, not a list — flattening it invents ~15% of messages that were never sent.
---

## Shape

`conversations.json` is an array of conversations. Each conversation is roughly:

```
{ conversation_id, title, create_time, update_time,
  current_node: "<node id>",
  mapping: { "<node id>": { id, message, parent, children: [...] }, ... } }
```

A node's `message` is `null` for the synthetic root and for some structural
nodes. A message is roughly `{id, author: {role}, create_time, content:
{content_type, parts, ...}, metadata, recipient, status, weight}`.

Timestamps are **unix seconds as floats** (not milliseconds, not ISO strings).
`create_time` on a message is **nullable**.

This is the one source in a typical corpus that is mostly prose, and the one
worth reading as text. Volume for a heavy 2–3 year user: 100–200 MB, 10^4
conversations, 10^5 messages.

## The rule that matters: a conversation is a tree

`mapping` is a **tree, not a transcript**. Every edit of a prompt and every
regenerated answer is added as an **additional child of the same parent** — a
sibling — and nothing is overwritten. The abandoned branches stay in the file
forever.

`Object.values(mapping)` therefore returns every message the user ever saw _and
every draft they discarded_. Flattening it and sorting by `create_time` yields
roughly **15% more messages than were actually exchanged**, inflating every
count, every "how often did I", and every date range built on it. The phantom
messages look completely ordinary; there is no field that marks them.

**The correct reconstruction is the only one: start at `current_node`, follow
`parent` to the root, collect, and reverse.**

```js
function activeBranch(conversation) {
  const out = [];
  const seen = new Set();
  let id = conversation.current_node;
  while (id && !seen.has(id)) {
    seen.add(id);
    const node = conversation.mapping[id];
    if (!node) break;
    if (node.message) out.push(node.message);
    id = node.parent;
  }
  return out.reverse();
}
```

The `seen` guard is not decoration — malformed exports do contain cycles, and a
naive walk hangs. Also handle a `current_node` that is missing from `mapping`.

If a question genuinely is about drafts and regenerations, walk the whole
`mapping` deliberately and **say that you did** — the count means something
different from the count of messages exchanged.

## Exports are snapshots, never increments

Every export is a **full dump of the account at that moment**. Two exports are
not two halves of a history; the newer one contains the older one, plus edits.
If a scope holds more than one export, deduplicate by `conversation_id` and keep
the copy with the newest `update_time` before counting anything. Concatenating
them doubles the corpus.

Deletion is invisible: a conversation the user deleted is simply absent from
later exports. You cannot tell "deleted" from "never existed", so do not claim a
conversation was removed.

## Counting messages honestly

Even on the correct branch, not every message is one the user exchanged:

- `author.role` is `user | assistant | system | tool | function`. `system`
  includes injected custom instructions; `tool` and `function` are model
  plumbing.
- `metadata.is_visually_hidden_from_conversation` marks messages the UI never
  showed.
- Content types like `code` (code-interpreter input), `thoughts` (reasoning),
  and browsing status updates are internal even when the role is `assistant`.
- `weight: 0` marks a message dropped from the model's context.

"How many messages" has at least three defensible answers. Pick one — usually
`role === "user"` on the active branch, excluding hidden messages — and **state
the rule you used** alongside the number.

## Reading message text

`content.parts` is nullable, and its items are **not always strings**. A part
can be an object such as `{content_type: "image_asset_pointer",
asset_pointer: "file-service://..."}`. `parts.join("")` throws or produces
`[object Object]` and quietly corrupts character counts and search.

Text can also live outside `parts` depending on `content_type`: `content.text`
(quotes from browsing), `content.result` (tool output), `content.thoughts` (a
list of `{summary, content}` reasoning objects), `content.content` (canvas and
reasoning recaps). Extract defensively: filter `parts` to strings, then fall
back to the other fields, and skip what you cannot read rather than coercing it.

Attachments appear under `metadata.attachments`; their contents are **not** in
`conversations.json`. If a question depends on an attached file, say it was not
readable.

## Dates

- Use `message.create_time` where present; fall back to the conversation's
  `create_time`, and say you did.
- `create_time` can be `null` on individual messages. Do not let a null become
  epoch 1970 — that would make it the "earliest" record and answer a
  first-occurrence question with a date that does not exist.
- The conversation's `create_time` is when the thread started, which can be years
  before a message added to it. For "when did I first say X", use the message's
  own timestamp and order by time, not by relevance.

## Known gaps and unverified points

- **The full list of files in a current export is not verified here.**
  `conversations.json` is the substantive one; other files (chat HTML, user
  metadata, feedback) may or may not be present and their shapes are unconfirmed.
  Enumerate what the scope actually contains.
- **The export schema drifts.** Fields have been added and removed over time —
  some 2026-era exports omit `status` and `weight` on messages. Treat every field
  outside `mapping` / `current_node` / `parent` / `children` / `author.role` /
  `content` as optional and guard accordingly.
- `title` can be `null`.
- Whether a given conversation's `current_node` points at the branch the user
  last _viewed_ versus last _created_ is not documented. It is the best available
  signal for "what the conversation actually says", and it is what this profile
  tells you to use, but it is not a guarantee.

_The tree-walk reconstruction, the message and content field shapes, the role
enum, hidden-message handling and the cycle guard were checked against
`mohamed-chs/convoviz`, a maintained open-source parser of this export format.
The export's file inventory was not verifiable from OpenAI's documentation._

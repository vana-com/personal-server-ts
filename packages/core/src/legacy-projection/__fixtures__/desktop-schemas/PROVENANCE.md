# Frozen Desktop schema provenance

These nine files are byte-identical to the app contract bundled in `vana-com/unity-surfaces` at commit `9155456f7a90a10b7af902c7ae5ea68ee8cef12d`. SHA-256 covers each complete source JSON file.

| Scope | Desktop source path | SHA-256 |
| --- | --- | --- |
| `heb.profile` | `apps/desktop/connectors/heb/schemas/heb.profile.json` | `0a27981ccdcffad91afd2a78a80407c67227b05ea1cf0c918ddfa5cb6338a3e0` |
| `heb.orders` | `apps/desktop/connectors/heb/schemas/heb.orders.json` | `d3579f4ae1b163a1bbcbfb9d2177892d81c395cd29cc81937ac21b8d8cff2b45` |
| `heb.nutrition` | `apps/desktop/connectors/heb/schemas/heb.nutrition.json` | `2dbc47a40391b7ee11c8601a2b2cd5bf327aaa552898f0d8c957dc111d92807c` |
| `wholefoods.profile` | `apps/desktop/connectors/wholefoods/schemas/wholefoods.profile.json` | `53643cbb7f783a759691ad7eb25c06d41a4d6e245bde0e948fbccf2e60379bf1` |
| `wholefoods.orders` | `apps/desktop/connectors/wholefoods/schemas/wholefoods.orders.json` | `0e3cfe49b006ea9811df4d398c131cc5c8f4a14137aea359a20777162bed1b1b` |
| `wholefoods.nutrition` | `apps/desktop/connectors/wholefoods/schemas/wholefoods.nutrition.json` | `e362ab6d391debd007fa13df8fe8743a67439ce5e2395d41c14aa89f987882fa` |
| `chatgpt.conversations` | `apps/desktop/connectors/openai/schemas/chatgpt.conversations.json` | `c83eba044962dfe4401c6f8637daac7aa7273fe88eaa9cd1734b7f51ca61265b` |
| `shop.orders` | `apps/desktop/connectors/shopify/schemas/shop.orders.json` | `13ace1a15d6d5e4d19ed1e77169d50d203fd9f16d608e8e8f133a55b06199713` |
| `youtube.history` | `apps/desktop/connectors/google/schemas/youtube.history.json` | `224811b6b73834e542f5d84f54a82acba095dfa64688592b658b0c97a73ba352` |

The six H-E-B and Whole Foods schemas were already present byte-for-byte in `desktop-schemas/` and are now also vendored in `legacy-schemas/`. ChatGPT Conversations, Shop Orders, and YouTube History were added here as frozen comparison copies because Personal Server keeps deliberate later revisions in `legacy-schemas/`.

The three later Personal Server revisions were first added by commit `865a6e4` with the projection feature. Existing tests record the intended newer shapes in `index.test.ts` and `youtube-history-watched-at.test.ts`: ChatGPT timestamps accept string, number, and null and include `fetched_at`; Shop includes top-level `total`; YouTube History is version 1.1.0 and includes `history[].watchedAt`. These are deliberate PS revisions, so they remain in `legacy-schemas/`. The parity suite validates against these separate frozen Desktop copies and reports where projections diverge.

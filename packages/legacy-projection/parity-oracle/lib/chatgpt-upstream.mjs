// Fake chatgpt.com served from inputs/chatgpt/*.json. Both the legacy script
// and the PDPP bundle talk to this same object, so they see the same upstream.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { html, json } from "./host.mjs";

export function chatgptUpstream(inputDir) {
  const load = (name) => JSON.parse(readFileSync(join(inputDir, name), "utf8"));
  const conversations = load("conversations.json");
  const listItems = load("list-items.json");
  const searchItems = load("search-items.json");
  const memories = load("memories.json");
  const session = load("session.json");
  const byId = new Map(conversations.map((c) => [c.conversation_id, c]));
  const SEARCH_PAGE = 30;
  const unknown = [];

  // Logged-in chatgpt.com shell: nav (legacy login check), client-bootstrap
  // (both connectors' token fallback), and an inline script carrying the
  // account email (legacy extractEmail scans scripts > 100 chars).
  const home = html(
    `<nav aria-label="Chat history"><a href="/c/${conversations[0].conversation_id}">recent</a></nav>` +
      `<button data-testid="profile-button">profile</button>` +
      `<script id="client-bootstrap" type="application/json">${JSON.stringify({ session: { accessToken: session.accessToken, user: session.user } })}</script>` +
      `<script>window.__synthetic = ${JSON.stringify({ user: { "email": session.user.email }, padding: "x".repeat(120) })};</script>`,
  );

  function resolve(raw, { method = "GET", body = null } = {}) {
    const url = new URL(raw);
    if (url.hostname !== "chatgpt.com") {
      unknown.push(`${method} ${raw}`);
      return { status: 404, contentType: "text/html", body: "" };
    }
    const p = url.pathname;
    if (p === "/" || p === "" || p.startsWith("/c/")) return home;
    if (p === "/auth/login") return html("<button>Log in</button>");
    if (p === "/api/auth/session") return json(session);
    if (p === "/backend-api/memories") return json(memories);
    if (p === "/backend-api/conversations/search") {
      const cursor = Number(url.searchParams.get("cursor") ?? "0") || 0;
      const items = searchItems.slice(cursor, cursor + SEARCH_PAGE);
      const more = cursor + SEARCH_PAGE < searchItems.length;
      return json({ items, cursor: more ? cursor + SEARCH_PAGE : null });
    }
    if (p === "/backend-api/conversations" && method === "GET") {
      const offset = Number(url.searchParams.get("offset") ?? "0") || 0;
      const limit = Number(url.searchParams.get("limit") ?? "28") || 28;
      return json({ items: listItems.slice(offset, offset + limit), total: listItems.length, limit, offset, has_missing_conversations: false });
    }
    if (p === "/backend-api/conversations/batch" && method === "POST") {
      let ids = [];
      try { ids = JSON.parse(body || "{}").conversation_ids || []; } catch {}
      return json(ids.map((id) => byId.get(id)).filter(Boolean));
    }
    const detail = p.match(/^\/backend-api\/conversation\/([^/]+)$/);
    if (detail && method === "GET") {
      const c = byId.get(decodeURIComponent(detail[1]));
      return c ? json(c) : json({ detail: "Can't load conversation" }, 404);
    }
    unknown.push(`${method} ${p}${url.search}`);
    return json({ detail: "Not Found" }, 404);
  }
  return { resolve, unknown, session };
}

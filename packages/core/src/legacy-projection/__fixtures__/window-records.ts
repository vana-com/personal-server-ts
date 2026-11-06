import type { LegacyScopeBinding, PdppRecord } from "../types.js";

// Window inputs shared by the window join test and the stream-sync
// projection test. Each builder makes a handful of parents in an order
// unlike their output order.

function chatgptRecords(): PdppRecord[] {
  // Update times with a tie, a missing time and an unparseable one, so the
  // windows' order depends on both the time and the id.
  const updates = [
    "2026-01-03T00:00:00.000Z",
    "2026-01-05T00:00:00.000Z",
    "2026-01-03T00:00:00.000Z",
    null,
    "not a time",
    "2026-01-04T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
  ];
  const records: PdppRecord[] = [];
  updates.forEach((update_time, c) => {
    const id = `c${(7 - c) % 7}`;
    const count = c % 3;
    let parent: string | null = null;
    for (let m = 0; m < count; m++) {
      const node = `n${m}`;
      records.push({
        stream: "messages",
        data: {
          id: `${id}:${node}`,
          conversation_id: id,
          parent_id: parent ? `${id}:${parent}` : null,
          role: m % 2 ? "assistant" : "user",
          content: `message ${m} of ${id}`,
          content_type: "text",
          model_slug: null,
          create_time: "2026-01-01T00:00:00.000Z",
          on_current_branch: true,
        },
      });
      parent = node;
    }
    records.push({
      stream: "conversations",
      data: {
        id,
        title: `conversation ${id}`,
        create_time: "2026-01-01T00:00:00.000Z",
        update_time,
        current_node: parent,
        message_count_on_current_branch: count,
      },
    });
  });
  return records;
}

function claudeRecords(binding: LegacyScopeBinding): PdppRecord[] {
  const live = binding.pdppStreams.includes("account_plan");
  const records: PdppRecord[] = [
    live
      ? {
          stream: "account_plan",
          data: { id: "plan-1", account_id: "org-1", plan_display_name: "Pro" },
        }
      : {
          stream: "account_profile",
          data: {
            id: "org-1",
            organization_id: "org-1",
            plan: "Pro",
            full_name: "Ada Example",
            name_source: "browser_menu",
            metadata_status: "valid",
          },
        },
  ];
  // Ids that sort differently as plain text and as JSON text, a conversation
  // with no messages, and one whose count the source does not know.
  const ids = ["chat-b", 'chat-"q', "chat-a", "chat-a-2", "chat-c", "chat-d"];
  ids.forEach((id, c) => {
    const count = c % 4;
    for (let m = 0; m < count; m++) {
      records.push({
        stream: "messages",
        data: {
          id: `${id}:m${m}`,
          conversation_id: id,
          role: m % 2 ? "assistant" : "human",
          parent_id: m ? `${id}:m${m - 1}` : null,
          content: `message ${m} of ${id}`,
          create_time: `2026-01-01T00:0${m}:00Z`,
          update_time: null,
          attachments: [],
        },
      });
    }
    records.push({
      stream: "conversations",
      data: {
        id,
        title: `conversation ${id}`,
        create_time: "2026-01-01T00:00:00Z",
        update_time: "2026-01-02T00:00:00Z",
        project_id: null,
        message_count: c === 5 ? null : count,
        is_starred: c % 2 === 0,
      },
    });
  });
  return records;
}

function claudeProjectRecords(): PdppRecord[] {
  const records: PdppRecord[] = [
    {
      stream: "account_profile",
      data: {
        id: "org-1",
        organization_id: "org-1",
        plan: "Pro",
        full_name: "Ada Example",
        name_source: "browser_menu",
        metadata_status: "valid",
      },
    },
  ];
  ["p-b", "p-a", "p-d", "p-c", "p-f", "p-e", "p-g"].forEach((id, c) => {
    for (let d = 0; d < c % 3; d++) {
      records.push({
        stream: "project_documents",
        data: {
          id: `${id}:d${d}`,
          project_id: id,
          filename: `doc${d}.md`,
          content: `document ${d} of ${id}`,
          create_time: null,
          update_time: null,
        },
      });
    }
    records.push({
      stream: "projects",
      data: {
        id,
        name: `Project ${id}`,
        description: null,
        create_time: "2026-01-01T00:00:00Z",
        update_time: null,
        is_archived: false,
        prompt_template: null,
      },
    });
  });
  return records;
}

function spotifyRecords(): PdppRecord[] {
  const records: PdppRecord[] = [];
  ["pl-c", "pl-a", "pl-b", "pl-e", "pl-d", "pl-g", "pl-f"].forEach((id, c) => {
    for (let t = 0; t < c % 4; t++) {
      records.push({
        stream: "playlist_items",
        data: {
          id: `${id}:${t}`,
          playlist_id: id,
          position: 3 - t,
          track_id: `${String(t).repeat(22)}`,
          name: `track ${t}`,
          artist_names: ["artist"],
          album_name: "album",
          duration_ms: 1000 + t,
          added_at: "2026-01-01T00:00:00Z",
          added_by: "user",
        },
      });
    }
    records.push({
      stream: "playlists",
      data: {
        id,
        name: `Playlist ${id}`,
        description: null,
        owner_name: "owner",
        uri: `spotify:playlist:${id}`,
        followers: c,
        images: [],
      },
    });
  });
  return records;
}

function amazonRecords(): PdppRecord[] {
  const records: PdppRecord[] = [];
  ["o-3", "o-1", "o-2", "o-7", "o-5", "o-4", "o-6"].forEach((id, c) => {
    for (let i = 0; i < c % 3; i++) {
      records.push({
        stream: "order_items",
        data: {
          id: `${id}:${i}`,
          order_id: id,
          name: `item ${i}`,
          url: `https://example.test/${id}/${i}`,
          unit_price: "$1.00",
        },
      });
    }
    records.push({
      stream: "orders",
      data: {
        id,
        order_date: "2026-01-05",
        order_total: "$10.00",
        delivery_status: "Delivered",
      },
    });
  });
  return records;
}

function instagramRecords(): PdppRecord[] {
  const records: PdppRecord[] = [];
  [
    "post-c",
    "post-a",
    "post-b",
    "post-e",
    "post-d",
    "post-g",
    "post-f",
  ].forEach((id, c) => {
    for (let l = 0; l < c % 3; l++) {
      records.push({
        stream: "post_likes",
        data: {
          post_id: id,
          liker_ordinal: l,
          user_id: `u${l}`,
          username: `user${l}`,
        },
      });
    }
    records.push({
      stream: "posts",
      data: {
        id,
        media_url: `https://example.test/${id}.jpg`,
        caption: `caption ${id}`,
        like_count: c % 3,
        taken_at: "2026-01-01T00:00:00Z",
      },
    });
  });
  return records;
}

/** Input that exercises a windowed scope: more parents than one window holds. */
export const WINDOW_FIXTURES: Record<
  string,
  (binding: LegacyScopeBinding) => PdppRecord[]
> = {
  "chatgpt.conversations": chatgptRecords,
  "claude.conversations": claudeRecords,
  "claude.projects": claudeProjectRecords,
  "spotify.playlists": spotifyRecords,
  "amazon.orders": amazonRecords,
  "instagram.posts": instagramRecords,
};

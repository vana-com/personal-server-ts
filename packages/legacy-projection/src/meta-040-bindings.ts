import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { LegacyScopeBinding, ProjectionResult } from "./types.js";

const source = "https://registry.pdpp.dev/connectors/meta";
const manifestDigest =
  "sha256:2340917b44ca61f0d4ab947fcd6dbac90103329b7d40ed5fb1a815248483f5fb";
const sourceRevision =
  "PDP-Connect/data-connectors@c03818f6ad733f90980784274e3eb4e90a168009";

const original = LEGACY_SCOPE_BINDINGS.get("instagram.posts");
if (!original) throw new Error("Missing retained Instagram posts binding");

const instagramPosts040: LegacyScopeBinding = {
  ...original,
  pdppSource: source,
  fieldsRead: {
    ...original.fieldsRead,
    post_likes: [
      "post_id",
      "liker_ordinal",
      "user_id",
      "username",
      "profile_pic_url",
      "pk",
      "id",
    ],
  },
  primaryKey: { posts: ["id"], post_likes: ["post_id", "liker_ordinal"] },
  lossy: original.lossy.filter(
    (item) =>
      !item.startsWith("who_liked.profile_pic_url") &&
      !item.startsWith("who_liked.pk"),
  ),
  project(records, options): ProjectionResult {
    const invalidLiker = records.some(
      (record) =>
        record.stream === "post_likes" &&
        (!Number.isInteger(record.data.liker_ordinal) ||
          (record.data.liker_ordinal as number) < 0),
    );
    if (invalidLiker) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "instagram.posts",
          reason: "post_likes record lacks a valid liker ordinal",
        },
      };
    }
    const projected = original.project(records, options);
    if (!projected.ok) return projected;

    const likesByPost = new Map<
      string,
      { ordinal: number; value: Record<string, unknown> }[]
    >();
    for (const record of records) {
      if (record.stream !== "post_likes") continue;
      const liker = record.data;
      if (
        typeof liker.post_id !== "string" ||
        typeof liker.user_id !== "string" ||
        typeof liker.username !== "string"
      ) {
        continue;
      }
      const id =
        (typeof liker.id === "string" && liker.id) ||
        (typeof liker.pk === "string" && liker.pk) ||
        liker.user_id;
      const whoLiked = likesByPost.get(liker.post_id) ?? [];
      whoLiked.push({
        ordinal: liker.liker_ordinal as number,
        value: {
          profile_pic_url:
            typeof liker.profile_pic_url === "string"
              ? liker.profile_pic_url
              : "",
          pk:
            (typeof liker.pk === "string" && liker.pk) ||
            (typeof liker.id === "string" && liker.id) ||
            id,
          username: liker.username,
          id:
            (typeof liker.id === "string" && liker.id) ||
            (typeof liker.pk === "string" && liker.pk) ||
            id,
        },
      });
      likesByPost.set(liker.post_id, whoLiked);
    }

    const sourcePosts = records.filter((record) => record.stream === "posts");
    const posts = Array.isArray(projected.payload.posts)
      ? projected.payload.posts.map((post, index) => {
          if (!post || typeof post !== "object" || Array.isArray(post))
            return post;
          const postId = sourcePosts[index]?.data.id;
          return {
            ...(post as Record<string, unknown>),
            who_liked:
              typeof postId === "string"
                ? (likesByPost.get(postId) ?? [])
                    .sort((left, right) => left.ordinal - right.ordinal)
                    .map(({ value }) => value)
                : [],
          };
        })
      : projected.payload.posts;

    return { ...projected, payload: { ...projected.payload, posts } };
  },
};

export const META_040_BINDINGS: ReadonlyMap<string, LegacyScopeBinding> =
  new Map(
    [...LEGACY_SCOPE_BINDINGS]
      .filter(([, binding]) => binding.pdppSource === source)
      .map(([scope, binding]): [string, LegacyScopeBinding] => {
        const profile =
          scope === "instagram.posts" ? instagramPosts040 : binding;
        return [
          scope,
          {
            ...profile,
            provenance: [
              {
                kind: "source-manifest",
                ref: sourceRevision,
                digest: manifestDigest,
                path: `connectors/meta/manifest.json#streams[name=${profile.pdppStreams.join(",")}]`,
              },
            ],
          },
        ];
      }),
  );

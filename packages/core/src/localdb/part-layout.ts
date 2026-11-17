/**
 * The bytes of a record's body. `length(body)` counts characters, so the text is
 * cast to bytes first.
 */
export const BODY_BYTES = "LENGTH(CAST(body AS BLOB))";

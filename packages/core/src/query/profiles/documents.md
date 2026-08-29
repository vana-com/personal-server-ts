---
id: documents
title: Documents
profileVersion: 1
schemaVersion: vana-fixture-corpus/1
scopes:
  - documents.*
summary: PDF records where `text_extracted` is nullable. A document that failed extraction is one you have not read, not an empty one — treating it as empty turns "I found nothing" into a false negative.
---

> **Describes the seeded fixture corpus, not a document store.**

## Shape

One JSON array, `documents.json`. A few hundred rows — always read all of them,
since this scope exists to answer existence questions and those require totality.

| Field              | Type           | Notes                                    |
| ------------------ | -------------- | ---------------------------------------- |
| `id`               | string         | Stable identifier. Cite it.              |
| `title`            | string         | Document title.                          |
| `content_type`     | string         | MIME type.                               |
| `created`          | string         | `YYYY-MM-DD`, date only.                 |
| `text_extracted`   | string \| null | **Nullable.** Body, or null.             |
| `extraction_error` | string \| null | Non-null exactly when extraction failed. |

## The rule that matters: null `text_extracted` is unread, not empty

Some documents have `text_extracted: null` and a non-null `extraction_error`.
These are **real documents whose contents were never extracted** — scanned
images with no text layer. They are not empty. They are documents you **have not
read**.

This decides whether an absence answer is honest. A search that skips them and
reports "there is nothing like that in your documents" makes a completeness
claim it cannot support — the answer could be in a file that never got a text
layer. That is the worst failure mode in this system: a confident "no" the user
cannot distinguish from a correct one.

For any "have I ever" or "is there any" question:

1. **Partition** into readable (`text_extracted` non-null) and unreadable.
2. **Search the readable set exhaustively** — every row, not a top-k.
3. **Report both counts**, scoped, never absolute: _"No match across the 318
   documents whose text could be read. 22 could not be read (`extraction_error`:
   'scanned image, no text layer'), so I cannot rule out a match in those."_

Never write "no such document exists" while unread documents remain.
`row.text_extracted.includes(...)` throws on null rows — a truthiness guard that
quietly skips them produces exactly the dishonest negative above. Guard
deliberately and count what you skipped.

## Match substance, not keywords

The corpus contains documents sharing vocabulary with a conflict question
without being one — an unexecuted draft, a declined offer, an expired agreement.
A keyword scan flags all of them. Before reporting a match, check whether it is
**in force**: executed rather than draft, accepted rather than declined, current
rather than expired. _"Three documents mention exclusivity; one is an unsigned
draft, one was declined, one expired, so none is a live conflict"_ is far more
useful than either a bare "no" or three false positives.

## Known gaps

- **All rows are `application/pdf`**; no images, spreadsheets or office formats.
- **No file size, page count, author, or modification date**; no folder or
  source path, so provenance and sharing are unknown.
- **One error reason string** for every failed row, so the corpus cannot
  distinguish an encrypted PDF from a scan from a corrupt file. Against real
  data, read the actual error.
- **Readable bodies are generated filler** apart from planted documents;
  semantic similarity is meaningless, exact-phrase search is not.
- `created` is date-only. No versioning: an amended document appears as
  unrelated rows, if at all.

_Field names, the nullable `text_extracted` paired with a non-null
`extraction_error`, and the non-binding near-miss documents were read from the
fixture generator._

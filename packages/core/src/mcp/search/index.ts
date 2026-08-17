import MiniSearch, {
  type Options as MiniSearchOptions,
  type SearchResult,
} from "minisearch";

export interface SearchDocument {
  id: string;
  scope: string;
  source?: string;
  text: string;
  title?: string;
  preview?: string;
  blockRef?: string;
}

export interface SearchHit extends Omit<SearchDocument, "text"> {
  score: number;
  terms: string[];
}

export interface SearchQuery {
  query: string;
  scopes?: readonly string[];
  limit?: number;
}

export interface SearchIndex {
  add(documents: readonly SearchDocument[]): void;
  search(query: SearchQuery): SearchHit[];
  serialize(): string;
}

const SEARCH_FIELDS = ["title", "text", "preview"];
const STORE_FIELDS = ["id", "scope", "source", "title", "preview", "blockRef"];

/**
 * Terms shorter than this are indexed but never prefix-expanded: with
 * `prefix: true` on every term a two-letter query expands to "starts with those
 * two letters", which matches essentially every document and turns search into
 * "return whatever came first".
 */
const PREFIX_MIN_TERM_CHARS = 4;

/** Single characters carry no signal and match nearly everything. */
const MIN_TERM_CHARS = 2;

/**
 * MiniSearch ships no stopword list, so an ordinary question ("what did I say
 * about the kiln") matches every document containing "the". Dropping function
 * words at index AND query time is what makes the remaining scores meaningful.
 */
const STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "but",
  "by",
  "did",
  "do",
  "does",
  "for",
  "from",
  "had",
  "has",
  "have",
  "he",
  "how",
  "i",
  "if",
  "in",
  "is",
  "it",
  "its",
  "me",
  "my",
  "no",
  "not",
  "of",
  "on",
  "or",
  "our",
  "she",
  "so",
  "that",
  "the",
  "their",
  "them",
  "then",
  "there",
  "they",
  "this",
  "to",
  "was",
  "we",
  "were",
  "what",
  "when",
  "where",
  "which",
  "who",
  "why",
  "will",
  "with",
  "you",
  "your",
]);

/**
 * Relevance floor, expressed as a fraction of the best hit for the same query.
 * BM25 scores are corpus-relative, so an absolute floor would be meaningless
 * across scopes of wildly different size; a relative floor reliably drops the
 * tail of documents that merely share one weak term with the query.
 */
const SCORE_FLOOR_RATIO = 0.25;

function processTerm(term: string): string | null {
  const normalized = term.toLowerCase();
  if (normalized.length < MIN_TERM_CHARS) return null;
  return STOPWORDS.has(normalized) ? null : normalized;
}

/**
 * Single source of truth for index + query behaviour. `load()` MUST be given
 * the same options the index was built with, otherwise a deserialized index
 * tokenizes queries differently from the documents it holds.
 */
const MINISEARCH_OPTIONS: MiniSearchOptions<SearchDocument> = {
  idField: "id",
  fields: SEARCH_FIELDS,
  storeFields: STORE_FIELDS,
  processTerm,
  searchOptions: {
    boost: { title: 2, preview: 1.2, text: 1 },
    prefix: (term) => term.length >= PREFIX_MIN_TERM_CHARS,
  },
};

function createMiniSearch(): MiniSearch<SearchDocument> {
  return new MiniSearch<SearchDocument>(MINISEARCH_OPTIONS);
}

function toHit(result: SearchResult): SearchHit {
  return {
    id: String(result.id),
    scope: String(result.scope),
    source: typeof result.source === "string" ? result.source : undefined,
    title: typeof result.title === "string" ? result.title : undefined,
    preview: typeof result.preview === "string" ? result.preview : undefined,
    blockRef: typeof result.blockRef === "string" ? result.blockRef : undefined,
    score: result.score,
    terms: result.terms,
  };
}

export class MiniSearchIndex implements SearchIndex {
  private readonly index: MiniSearch<SearchDocument>;

  private constructor(index: MiniSearch<SearchDocument>) {
    this.index = index;
  }

  static empty(): MiniSearchIndex {
    return new MiniSearchIndex(createMiniSearch());
  }

  static build(documents: readonly SearchDocument[]): MiniSearchIndex {
    const index = MiniSearchIndex.empty();
    index.add(documents);
    return index;
  }

  static load(serialized: string): MiniSearchIndex {
    return new MiniSearchIndex(
      MiniSearch.loadJSON<SearchDocument>(serialized, MINISEARCH_OPTIONS),
    );
  }

  add(documents: readonly SearchDocument[]): void {
    this.index.addAll(documents);
  }

  search({ query, scopes, limit = 20 }: SearchQuery): SearchHit[] {
    const allowedScopes = scopes ? new Set(scopes) : null;
    const results = this.index.search(query, {
      filter: allowedScopes
        ? (result) => allowedScopes.has(String(result.scope))
        : undefined,
    });
    const scoreFloor = (results[0]?.score ?? 0) * SCORE_FLOOR_RATIO;
    return results
      .filter((result) => result.score >= scoreFloor)
      .slice(0, limit)
      .map(toHit);
  }

  serialize(): string {
    return JSON.stringify(this.index);
  }
}

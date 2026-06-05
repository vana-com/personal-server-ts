import MiniSearch, { type SearchResult } from "minisearch";

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

function createMiniSearch(): MiniSearch<SearchDocument> {
  return new MiniSearch<SearchDocument>({
    idField: "id",
    fields: SEARCH_FIELDS,
    storeFields: STORE_FIELDS,
    searchOptions: {
      boost: { title: 2, preview: 1.2, text: 1 },
      prefix: true,
    },
  });
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
      MiniSearch.loadJSON<SearchDocument>(serialized, {
        idField: "id",
        fields: SEARCH_FIELDS,
        storeFields: STORE_FIELDS,
        searchOptions: {
          boost: { title: 2, preview: 1.2, text: 1 },
          prefix: true,
        },
      }),
    );
  }

  add(documents: readonly SearchDocument[]): void {
    this.index.addAll(documents);
  }

  search({ query, scopes, limit = 20 }: SearchQuery): SearchHit[] {
    const allowedScopes = scopes ? new Set(scopes) : null;
    return this.index
      .search(query, {
        filter: allowedScopes
          ? (result) => allowedScopes.has(String(result.scope))
          : undefined,
      })
      .slice(0, limit)
      .map(toHit);
  }

  serialize(): string {
    return JSON.stringify(this.index);
  }
}

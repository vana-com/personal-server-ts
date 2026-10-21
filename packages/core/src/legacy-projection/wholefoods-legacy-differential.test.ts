import Ajv from "ajv";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { diffBodies, type BodyDifference } from "./__fixtures__/parity/diff.js";
import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import profile from "./declarations/wholefoods.collection-profile.json";
import type { PdppRecord } from "./types.js";

/**
 * Differential test: one Whole Foods account is run through the retired legacy
 * connector and through the PDPP projection, and the two outputs are compared
 * field by field.
 *
 * Legacy side. The real `wholefoods-playwright` 1.0.2 script (the version the
 * desktop app shipped, pinned below by SHA-256) runs unmodified in a `vm`
 * context. Only its `page` object is replaced. `page.evaluate` returns the
 * scrape results that `WORLD` describes in place of DOM queries, and
 * `page.httpFetch` answers the USDA lookups. Everything the script does after
 * a scrape (order assembly, product de-duplication, image back-fill, nutrition
 * fallbacks, result shaping) is the legacy code itself.
 *
 * PDPP side. `pdppRecords` states what the data connector emits for the same
 * facts, following `buildOrderRecord`, `buildOrderItemRecord` and the nutrition
 * row shape in PDP-Connect/data-connectors `connectors/wholefoods`. The records
 * are checked against the vendored collection profile's stream schemas, which
 * catches wrong types and missing required fields (it does not catch extra or
 * omitted optional fields). Nutrition rows are built from the facts legacy
 * settled on, so the nutrition comparison tests field mapping and shape, not
 * whether the connector extracts the same facts; the connector's own tests own
 * that. A lookup that ends without usable facts yields no row, as in the
 * connector. The projection under test is not involved in building any record.
 *
 * "First order line" below means first in the order the records are supplied.
 * Legacy took its first line in Amazon's newest-first scrape order; here both
 * sides use ascending order id, so they agree by construction.
 *
 * Every remaining difference is listed in REVIEWED_DIFFERENCES with the reason.
 * A new, changed or vanished difference fails the test.
 */

const LEGACY_SCRIPT = new URL(
  "./__fixtures__/legacy-connector/wholefoods-playwright-1.0.2.js.txt",
  import.meta.url,
);
// unity-surfaces 25e532758256d0410d81675e00340bb5a9117db5,
// apps/desktop/connectors/wholefoods/wholefoods-playwright.js (1.0.2).
const LEGACY_SCRIPT_SHA256 =
  "55b08116972ad5bfd248435830cfa839bc40723ba475d364e9a2ece7e0d6e7a5";

interface WorldItem {
  asin: string;
  imageUrl: string;
  name: string;
  price: number | null;
  quantity: string;
}
interface WorldOrder {
  /** Item rows the order detail page lists; a cancelled order lists none. */
  items: WorldItem[];
  orderId: string;
  /** Raw text after "Ordered on", as the legacy scraper reads it. */
  rawDate: string;
  state: "completed" | "cancelled";
}
type NutritionFacts = Record<string, unknown>;
interface World {
  /** Amazon product page result per ASIN. */
  amazon: Record<string, NutritionFacts>;
  orders: WorldOrder[];
  profile: { email: string; name: string };
  /** USDA search hit per ASIN; absent means no match. */
  usda: Record<string, Record<string, unknown>>;
}

const orderUrl = (orderId: string) =>
  `https://www.amazon.com/uff/your-account/order-details?orderID=${orderId}`;
const productUrl = (asin: string) =>
  `https://www.amazon.com/dp/${asin}?almBrandId=ctnow`;

const OATS = "B000OATS01";
const MILK = "B000MILK01";
const APPLES = "B000APPL01";
const ROLLS = "B000ROLL01";
const SALT = "B000SALT01";

const WORLD: World = {
  profile: { name: "Ada Example", email: "ada@example.test" },
  // Scrape order is ascending by order id, which is the order the projection
  // receives rows in. "First occurrence" below means that shared order.
  orders: [
    {
      orderId: "111-0000001-0000001",
      rawDate: "October 3, 2026",
      state: "completed",
      items: [
        {
          asin: OATS,
          name: "Organic Oats, 18 oz",
          quantity: "2",
          price: 3.99,
          imageUrl: "https://m.media-amazon.com/images/oats-first.jpg",
        },
        {
          // The order page has no image for this product.
          asin: MILK,
          name: "Whole Milk, 1 gal",
          quantity: "1",
          price: 4.5,
          imageUrl: "",
        },
      ],
    },
    {
      orderId: "111-0000002-0000002",
      rawDate: "October 9, 2026",
      state: "completed",
      items: [
        {
          // The same product again, listed under another name and image.
          asin: OATS,
          name: "Organic Oats 18 oz (new listing)",
          quantity: "1",
          price: 4.25,
          imageUrl: "https://m.media-amazon.com/images/oats-second.jpg",
        },
        {
          asin: APPLES,
          name: "Honeycrisp Apples",
          quantity: "3",
          price: null,
          imageUrl: "https://m.media-amazon.com/images/apples.jpg",
        },
        {
          // No image on the order page or on the product page.
          asin: ROLLS,
          name: "Dinner Rolls, 12 ct",
          quantity: "1",
          price: 2,
          imageUrl: "",
        },
      ],
    },
    {
      orderId: "111-0000003-0000003",
      rawDate: "October 12, 2026",
      state: "cancelled",
      items: [],
    },
  ],
  amazon: {
    [OATS]: {
      "@type": "https://schema.org/NutritionInformation",
      source: "amazon_product_page",
      confidence: "medium",
      imageUrl: "https://m.media-amazon.com/images/oats-hero.jpg",
      upc: "012345678905",
      servingSize: "40 g",
      servingsPerContainer: "10",
      calories: 150,
      protein_g: 5,
      carbs_g: 27,
      fat_g: 3,
      saturated_fat_g: 0.5,
      trans_fat_g: 0,
      cholesterol_mg: 0,
      fiber_g: 4,
      sugar_g: 1,
      added_sugar_g: 0,
      sodium_mg: 0,
      potassium_mg: 150,
      calcium_mg: 20,
      iron_mg: 1.5,
      vitamin_d_mcg: 0,
      ingredients: "Whole grain oats",
      allergens: null,
      highlights: [],
      category: [],
      rawNutritionText: "Calories150 Total Fat3g",
    },
    [MILK]: {
      source: "not_found",
      confidence: "low",
      imageUrl: "https://m.media-amazon.com/images/milk-hero.jpg",
      upc: "070000000001",
    },
    [APPLES]: {
      "@type": "https://schema.org/NutritionInformation",
      source: "amazon_product_page",
      confidence: "medium",
      imageUrl: "",
      upc: null,
      servingSize: "1 medium",
      servingsPerContainer: null,
      calories: 95,
      protein_g: 0.5,
      carbs_g: 25,
      fat_g: 0.3,
      saturated_fat_g: null,
      trans_fat_g: null,
      cholesterol_mg: null,
      fiber_g: 4.4,
      sugar_g: 19,
      added_sugar_g: null,
      sodium_mg: 2,
      potassium_mg: null,
      calcium_mg: null,
      iron_mg: null,
      vitamin_d_mcg: null,
      ingredients: null,
      allergens: null,
      highlights: [],
      category: [],
      rawNutritionText: null,
    },
    [ROLLS]: {
      "@type": "https://schema.org/NutritionInformation",
      source: "amazon_product_page",
      confidence: "medium",
      imageUrl: "",
      upc: null,
      servingSize: "1 roll",
      servingsPerContainer: null,
      calories: 80,
      protein_g: 2,
      carbs_g: 14,
      fat_g: 1.5,
      saturated_fat_g: null,
      trans_fat_g: null,
      cholesterol_mg: null,
      fiber_g: 1,
      sugar_g: 2,
      added_sugar_g: null,
      sodium_mg: 140,
      potassium_mg: null,
      calcium_mg: null,
      iron_mg: null,
      vitamin_d_mcg: null,
      ingredients: null,
      allergens: null,
      highlights: [],
      category: [],
      rawNutritionText: null,
    },
  },
  usda: {
    [MILK]: {
      fdcId: 123456,
      description: "WHOLE MILK",
      brandOwner: "Dairy Co",
      servingSize: 240,
      servingSizeUnit: "ml",
      gtinUpc: "070000000001",
      ingredients: "MILK",
      foodNutrients: [
        { nutrientId: 1008, value: 61 },
        { nutrientId: 1003, value: 3.2 },
        { nutrientId: 1005, value: 4.8 },
        { nutrientId: 1004, value: 3.3 },
      ],
    },
  },
};

/**
 * A product the Amazon page lists with no major macros and USDA cannot match.
 * Legacy settles it as an Amazon row of nulls; the data connector (#499
 * `lookupNutritionForProduct`) settles it as "not_found" and emits no nutrition
 * row ("Lookup failures emit no nutrition row").
 */
const UNMATCHED_ITEM: WorldItem = {
  asin: SALT,
  name: "Sea Salt, 4 oz",
  quantity: "1",
  price: 2,
  imageUrl: "https://m.media-amazon.com/images/salt.jpg",
};
const UNMATCHED_FACTS: NutritionFacts = {
  "@type": "https://schema.org/NutritionInformation",
  source: "amazon_product_page",
  confidence: "medium",
  imageUrl: "",
  upc: null,
  servingSize: null,
  servingsPerContainer: null,
  calories: null,
  protein_g: null,
  carbs_g: null,
  fat_g: null,
  saturated_fat_g: null,
  trans_fat_g: null,
  cholesterol_mg: null,
  fiber_g: null,
  sugar_g: null,
  added_sugar_g: null,
  sodium_mg: null,
  potassium_mg: null,
  calcium_mg: null,
  iron_mg: null,
  vitamin_d_mcg: null,
  ingredients: null,
  allergens: null,
  highlights: [],
  category: [],
  rawNutritionText: null,
};

// ─── Legacy side ─────────────────────────────────────────────────────────

interface LegacyResult {
  "wholefoods.nutrition": Record<string, unknown>;
  "wholefoods.orders": Record<string, unknown>;
  "wholefoods.profile": Record<string, unknown>;
}

function searchPage(world: World) {
  return {
    orders: world.orders.map((order) => ({
      orderId: order.orderId,
      orderUrl: orderUrl(order.orderId),
      orderDate: order.rawDate,
      total: null,
      itemCount: null,
      status: "Completed",
    })),
    hasNext: false,
    maxPage: 1,
    totalOrders: world.orders.length,
    noOrders: false,
  };
}

function legacyPage(world: World) {
  let url = "";
  const evaluate = (code: string): unknown => {
    if (code.includes("hasLoginForm")) return true;
    if (code.includes("ya-myab-display-name")) return world.profile;
    if (code.includes("ordersMap")) return searchPage(world);
    if (code.includes("itemRows")) {
      const orderId = new URL(url).searchParams.get("orderID");
      const order = world.orders.find((o) => o.orderId === orderId);
      if (!order) throw new Error(`no world order for ${url}`);
      return {
        orderDate: order.rawDate,
        items: order.items.map((item) => ({
          name: item.name,
          productId: item.asin,
          productUrl: productUrl(item.asin),
          imageUrl: item.imageUrl,
          quantity: item.quantity,
          price: item.price,
        })),
      };
    }
    if (code.includes("hasCaptcha")) return { blocked: false };
    if (code.includes("nutritionTable")) {
      const asin = url.match(/\/dp\/([A-Z0-9]{10})/)?.[1] ?? "";
      const facts = world.amazon[asin];
      if (!facts) throw new Error(`no world nutrition for ${url}`);
      return facts;
    }
    // The Whole Foods site search finds nothing.
    if (code.includes("product-tile")) return null;
    throw new Error(
      `legacy script scraped something the world omits: ${code.slice(0, 80)}`,
    );
  };
  const noop = async () => undefined;
  return {
    goto: async (target: string) => {
      url = target;
    },
    sleep: noop,
    setProgress: noop,
    setData: noop,
    showBrowser: noop,
    goHeadless: noop,
    promptUser: noop,
    evaluate: async (code: string) => evaluate(code),
    httpFetch: async (target: string) => {
      const query = decodeURIComponent(
        target.match(/query=([^&]*)/)?.[1] ?? "",
      );
      const hit = Object.entries(world.usda).find(([asin]) => {
        const name = world.orders
          .flatMap((o) => o.items)
          .find((item) => item.asin === asin)?.name;
        return query.startsWith("gtinUpc:")
          ? String(world.amazon[asin]?.upc) === query.replace("gtinUpc:", "")
          : name?.toLowerCase().startsWith(query.toLowerCase().slice(0, 6));
      });
      return { ok: true, json: { foods: hit ? [hit[1]] : [] } };
    },
  };
}

async function runLegacy(world: World): Promise<LegacyResult> {
  const source = readFileSync(LEGACY_SCRIPT, "utf8");
  expect(createHash("sha256").update(source).digest("hex")).toBe(
    LEGACY_SCRIPT_SHA256,
  );
  const context = vm.createContext({
    page: legacyPage(world),
    process: { env: {} },
    console,
  });
  const run = vm.runInContext(source, context) as Promise<{
    data: LegacyResult;
    success: boolean;
  }>;
  const outcome = await run;
  expect(outcome.success).toBe(true);
  return outcome.data;
}

// ─── PDPP side ───────────────────────────────────────────────────────────

const ISO_DATES: Record<string, string> = {
  "October 3, 2026": "2026-10-03",
  "October 9, 2026": "2026-10-09",
  "October 12, 2026": "2026-10-12",
};

const NUTRITION_FIELD_MAP: Record<string, string> = {
  "@type": "type",
  servingSize: "serving_size",
  servingsPerContainer: "servings_per_container",
  rawNutritionText: "raw_nutrition_text",
  usdaFdcId: "usda_fdc_id",
  usdaMatchMethod: "usda_match_method",
  usdaDescription: "usda_description",
  usdaBrand: "usda_brand",
  pageTitle: "page_title",
};

/** The nutrition row the data connector emits for the facts the legacy script
 *  settled on. `settled` is the legacy per-product nutrition object. */
function nutritionRow(
  asin: string,
  name: string,
  settled: Record<string, unknown>,
): Record<string, unknown> {
  const row: Record<string, unknown> = { id: asin, product_id: asin, name };
  for (const [key, value] of Object.entries(settled)) {
    if (["name", "productUrl", "images", "imageUrl"].includes(key)) continue;
    const field = NUTRITION_FIELD_MAP[key] ?? key;
    // The declared type of servings_per_container is a number.
    row[field] =
      field === "servings_per_container" && typeof value === "string"
        ? Number(value)
        : value;
  }
  row.type ??= "https://schema.org/NutritionInformation";
  return row;
}

/** The data connector withholds the row when a lookup ends without usable
 *  facts: `not_found`, `error` and `blocked`, and a page with none of calories,
 *  protein, fat or carbs (`hasMajorMacros`) when USDA has no match either. */
function connectorEmitsNutritionRow(settled: Record<string, unknown>) {
  if (["not_found", "error", "blocked"].includes(String(settled.source)))
    return false;
  if (settled.source === "usda_fdc") return true;
  return ["calories", "protein_g", "fat_g", "carbs_g"].some(
    (field) => typeof settled[field] === "number",
  );
}

function pdppRecords(world: World, legacy: LegacyResult): PdppRecord[] {
  const records: PdppRecord[] = [
    { stream: "profile", data: { id: "amazon-account", ...world.profile } },
  ];
  const firstItem = new Map<string, WorldItem>();
  for (const order of world.orders) {
    records.push({
      stream: "orders",
      data: {
        id: order.orderId,
        item_count: order.state === "cancelled" ? 0 : order.items.length,
        order_date: ISO_DATES[order.rawDate] ?? null,
        order_url: orderUrl(order.orderId),
        status: order.state === "cancelled" ? "Cancelled" : null,
        total_cents: null,
      },
    });
    for (const item of order.items) {
      if (!firstItem.has(item.asin)) firstItem.set(item.asin, item);
      records.push({
        stream: "order_items",
        data: {
          id: `${order.orderId}#${item.asin}`,
          order_id: order.orderId,
          name: item.name,
          product_id: item.asin,
          product_url: productUrl(item.asin),
          // The connector reads a missing image as null (parsers.ts).
          image_url: item.imageUrl || null,
          quantity: Number(item.quantity),
          unit_price_cents:
            item.price === null ? null : Math.round(item.price * 100),
        },
      });
    }
  }
  const settled = legacy["wholefoods.nutrition"].items as Record<
    string,
    Record<string, unknown>
  >;
  for (const [asin, item] of firstItem) {
    const facts = settled[asin] ?? {};
    if (!connectorEmitsNutritionRow(facts)) continue;
    records.push({
      stream: "nutrition",
      data: nutritionRow(asin, item.name, facts),
    });
  }
  return records;
}

function assertSchemaValid(records: PdppRecord[]) {
  const ajv = new Ajv({ allErrors: true, strict: false });
  for (const { stream, data } of records) {
    const declared = profile.streams.find((s) => s.name === stream);
    const validate = ajv.compile(
      (declared?.schema ?? {}) as Record<string, unknown>,
    );
    expect(
      validate(data),
      `${stream}: ${JSON.stringify(validate.errors)}`,
    ).toBe(true);
  }
}

function projectScope(scope: string, records: PdppRecord[]) {
  return projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams: LEGACY_SCOPE_BINDINGS.get(scope)?.pdppStreams ?? [],
    now: "2026-10-21T00:00:00.000Z",
  });
}

function project(scope: string, records: PdppRecord[]) {
  const result = projectScope(scope, records);
  expect(result.ok, JSON.stringify(result)).toBe(true);
  if (!result.ok) throw new Error(`projection failed for ${scope}`);
  return result;
}

// ─── Comparison ──────────────────────────────────────────────────────────

/** Orders and items are matched by identity so a reorder cannot hide a field
 *  difference; `sequence` compares the order separately. */
function keyed(scope: string, body: Record<string, unknown>) {
  if (scope !== "wholefoods.orders") return body;
  const orders = body.orders as Array<Record<string, unknown>>;
  return {
    ...body,
    orders: Object.fromEntries(
      orders.map((order) => [
        order.orderId as string,
        {
          ...order,
          items: Object.fromEntries(
            (order.items as Array<Record<string, unknown>>).map((item) => [
              item.productId as string,
              item,
            ]),
          ),
        },
      ]),
    ),
  };
}

/** Identity sequence of the orders and of each order's items, in output order. */
function sequence(scope: string, body: Record<string, unknown>): string[] {
  if (scope !== "wholefoods.orders") return [];
  return (body.orders as Array<Record<string, unknown>>).flatMap((order) => [
    `order ${order.orderId as string}`,
    ...(order.items as Array<Record<string, unknown>>).map(
      (item) => `item ${order.orderId as string}/${item.productId as string}`,
    ),
  ]);
}

interface ReviewedDifference extends BodyDifference {
  reason: string;
  scope: string;
}

const ABSENT = "<absent>";
const HERO = "https://m.media-amazon.com/images/milk-hero.jpg";
const DATE_REASON =
  "The data connector parses the order date to ISO 8601 and the projection passes it through; legacy kept the page text. Predates this change and is not part of it.";

const REVIEWED_DIFFERENCES: ReviewedDifference[] = [
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000001-0000001.orderDate",
    legacy: "October 3, 2026",
    projected: "2026-10-03",
    reason: DATE_REASON,
  },
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000002-0000002.orderDate",
    legacy: "October 9, 2026",
    projected: "2026-10-09",
    reason: DATE_REASON,
  },
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000003-0000003.orderDate",
    legacy: "October 12, 2026",
    projected: "2026-10-12",
    reason: DATE_REASON,
  },
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000003-0000003.status",
    legacy: "Completed",
    projected: "Cancelled",
    reason:
      "Legacy labeled every order Completed because it could not see cancellations. The data connector records them, and the projection reports the source status. The order itself is kept, with no items and a null itemCount, as legacy kept it.",
  },
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000001-0000001.items.B000MILK01.imageUrl",
    legacy: HERO,
    projected: ABSENT,
    reason:
      "Legacy back-filled a missing order-page image from the Amazon product page's hero image. The data connector's nutrition stream carries no image field, so that image never reaches the projection. A connector gap, not a projection choice.",
  },
  {
    scope: "wholefoods.orders",
    path: "orders.111-0000002-0000002.items.B000ROLL01.imageUrl",
    legacy: "",
    projected: ABSENT,
    reason:
      "Legacy wrote an empty string for an item with no image. The data connector records a missing image as null, and the projection leaves the optional imageUrl out rather than invent an empty string (the frozen schema makes it optional). Existing behavior, kept.",
  },
  {
    scope: "wholefoods.nutrition",
    path: "items.B000MILK01.images.thumbnail",
    legacy: HERO,
    projected: "",
    reason: "Same hero-image gap as the order item above.",
  },
];

describe("Whole Foods projection against the legacy connector", () => {
  it("is compared against the real legacy script's output for the same account", async () => {
    const legacy = await runLegacy(WORLD);
    const records = pdppRecords(WORLD, legacy);
    assertSchemaValid(records);

    const differences: Record<string, BodyDifference[]> = {};
    for (const scope of [
      "wholefoods.profile",
      "wholefoods.orders",
      "wholefoods.nutrition",
    ] as const) {
      const projected = project(scope, records).payload as Record<
        string,
        unknown
      >;
      expect(sequence(scope, projected), scope).toEqual(
        sequence(scope, legacy[scope]),
      );
      differences[scope] = diffBodies(
        keyed(scope, legacy[scope]),
        keyed(scope, projected),
      );
    }

    const byPath = (a: { scope: string; path: string }, b: typeof a) =>
      `${a.scope} ${a.path}`.localeCompare(`${b.scope} ${b.path}`);
    const observed = Object.entries(differences)
      .flatMap(([scope, list]) => list.map((d) => ({ scope, ...d })))
      .sort(byPath);
    const reviewed = REVIEWED_DIFFERENCES.map(
      ({ reason: _reason, ...rest }) => rest,
    ).sort(byPath);
    expect(observed).toEqual(reviewed);
  });

  it("fails the nutrition scope closed when the connector withholds a failed lookup's row", async () => {
    // The data connector emits no nutrition row for a product whose lookup
    // ends in not_found, error or blocked (data-connectors#499), but the
    // binding requires one outcome per ordered product. Until one side
    // changes, a single unmatched product makes the whole scope incomplete.
    // Legacy delivered such a product as an ordinary row.
    const world: World = {
      ...WORLD,
      orders: WORLD.orders.map((order, index) =>
        index === 1
          ? { ...order, items: [...order.items, UNMATCHED_ITEM] }
          : order,
      ),
      amazon: { ...WORLD.amazon, [SALT]: UNMATCHED_FACTS },
    };
    const legacy = await runLegacy(world);
    expect(
      (legacy["wholefoods.nutrition"].items as Record<string, unknown>)[SALT],
    ).toMatchObject({ source: "amazon_product_page", calories: null });

    const records = pdppRecords(world, legacy);
    assertSchemaValid(records);
    expect(records.some((r) => r.data.product_id === SALT)).toBe(true);
    expect(
      records.some(
        (r) => r.stream === "nutrition" && r.data.product_id === SALT,
      ),
    ).toBe(false);

    expect(projectScope("wholefoods.orders", records).ok).toBe(true);
    expect(projectScope("wholefoods.nutrition", records)).toMatchObject({
      ok: false,
      error: {
        kind: "incomplete_scope",
        reason: "nutrition outcomes do not cover every ordered product",
      },
    });
  });
});

import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import hebNutritionSchema from "./__fixtures__/desktop-schemas/heb.nutrition.json";
import hebProfileSchema from "./__fixtures__/desktop-schemas/heb.profile.json";
import wholefoodsNutritionSchema from "./__fixtures__/desktop-schemas/wholefoods.nutrition.json";
import wholefoodsOrdersSchema from "./__fixtures__/desktop-schemas/wholefoods.orders.json";
import wholefoodsProfileSchema from "./__fixtures__/desktop-schemas/wholefoods.profile.json";
import profileFixtures from "./__fixtures__/grocery-profiles.compatibility.json";
import pendingOutcomes from "./__fixtures__/grocery-pending-source-outcomes.json";
import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { PdppRecord } from "./types.js";
import { createMemoryRecordStore } from "../storage/pdpp-records/memory-store.js";

const ajv = new Ajv({ allErrors: true, strict: false });

function project(scope: string, records: PdppRecord[], streams: string[]) {
  const result = LEGACY_SCOPE_BINDINGS.get(scope)?.project(records, {
    fetchedStreams: streams,
  });
  expect(result?.ok, JSON.stringify(result)).toBe(true);
  if (!result?.ok) throw new Error(`Projection failed for ${scope}`);
  return result.payload;
}

function validates(schema: { schema: unknown }, payload: unknown) {
  const validate = ajv.compile(schema.schema as Record<string, unknown>);
  expect(validate(payload), JSON.stringify(validate.errors, null, 2)).toBe(
    true,
  );
}

function rejects(scope: string, records: PdppRecord[]) {
  const result = LEGACY_SCOPE_BINDINGS.get(scope)?.project(records, {
    fetchedStreams: ["profile"],
  });
  expect(result?.ok).toBe(false);
}

describe("grocery legacy scope projections", () => {
  for (const scope of ["heb.profile", "wholefoods.profile"] as const) {
    it.each(profileFixtures[scope])(
      `preserves ${scope} legacy payload fields and types`,
      ({ records, expected }) => {
        const payload = project(scope, records as PdppRecord[], ["profile"]);
        expect(payload).toEqual(expected);
        validates(
          scope === "heb.profile" ? hebProfileSchema : wholefoodsProfileSchema,
          payload,
        );
      },
    );
  }

  it.each(["heb.profile", "wholefoods.profile"] as const)(
    "fails closed for duplicate %s profile records",
    (scope) => {
      rejects(scope, [
        {
          stream: "profile",
          data: {
            id: "one",
            name: "Ada",
            email: "ada@example.test",
            delivery_addresses: [],
          },
        },
        {
          stream: "profile",
          data: {
            id: "two",
            name: "Grace",
            email: "grace@example.test",
            delivery_addresses: [],
          },
        },
      ]);
    },
  );

  it("fails closed when H-E-B address evidence is absent", () => {
    rejects("heb.profile", [
      { stream: "profile", data: { id: "heb-account" } },
    ]);
  });

  it.each(["heb.profile", "wholefoods.profile"] as const)(
    "fails closed for malformed non-null name and email in %s",
    (scope) => {
      for (const field of ["name", "email"])
        for (const malformed of [42, {}, []]) {
          rejects(scope, [
            {
              stream: "profile",
              data: {
                id: "account",
                [field]: malformed,
                delivery_addresses: [],
              },
            },
          ]);
        }
    },
  );

  it("maps H-E-B profile details from the declared account stream", () => {
    const payload = project(
      "heb.profile",
      [
        {
          stream: "profile",
          data: {
            id: "profile-1",
            name: "Ada Example",
            email: "ada@example.test",
            phone: "555-0100",
            delivery_addresses: [
              { address: "1 Main St", is_primary: true, label: "Home" },
            ],
          },
        },
      ],
      ["profile"],
    );
    expect(payload).toEqual({
      name: "Ada Example",
      email: "ada@example.test",
      phone: "555-0100",
      deliveryAddresses: [
        { address: "1 Main St", isPrimary: true, label: "Home" },
      ],
    });
    validates(hebProfileSchema, payload);
  });

  it("keys H-E-B nutrition by the source product id and carries declared nutrient values", () => {
    const records: PdppRecord[] = [
      {
        stream: "order_items",
        data: {
          id: "line-1",
          product_id: "12345678",
          name: "Oats",
          product_url: "https://www.heb.com/product-detail/12345678",
        },
      },
      {
        stream: "order_items",
        data: {
          id: "line-2",
          product_id: null,
          name: "Store credit",
          product_url: null,
        },
      },
      {
        stream: "nutrition",
        data: {
          id: "nutrition-1",
          product_id: "12345678",
          name: "Oats",
          source: "heb_product_page",
          confidence: "high",
          product_url: "https://www.heb.com/product-detail/12345678",
          calories: 150,
          protein_g: 5,
          serving_size: "40 g",
          servings_per_container: "10",
        },
      },
    ];
    const payload = project("heb.nutrition", records, [
      "nutrition",
      "orders",
      "order_items",
    ]);
    expect(payload).toEqual({
      items: {
        "12345678": {
          name: "Oats",
          productUrl: "https://www.heb.com/product-detail/12345678",
          source: "heb_product_page",
          confidence: "high",
          calories: 150,
          protein_g: 5,
          servingSize: "40 g",
          servingsPerContainer: "10",
          images: {
            thumbnail:
              "https://images.heb.com/is/image/HEBGrocery/prd-small/012345678.jpg",
            full: "https://images.heb.com/is/image/HEBGrocery/12345678-1",
          },
        },
      },
      coverage: {
        total: 1,
        found: 1,
        foundUSDA: 0,
        blocked: 0,
        percentCovered: 100,
      },
    });
    validates(hebNutritionSchema, payload);
  });

  it("requires the order-history stream for H-E-B nutrition projection", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("heb.nutrition");
    expect(
      binding?.project(
        [
          {
            stream: "order_items",
            data: {
              id: "line-1",
              product_id: "heb-1",
              name: "Oats",
              product_url: "https://www.heb.com/product-detail/heb-1",
            },
          },
          {
            stream: "nutrition",
            data: {
              product_id: "heb-1",
              name: "Oats",
              product_url: "https://www.heb.com/product-detail/heb-1",
              source: "heb_product_page",
            },
          },
        ],
        { fetchedStreams: ["nutrition", "order_items"] },
      ),
    ).toMatchObject({
      ok: false,
      error: { kind: "missing_stream", expectedStream: "orders" },
    });
  });

  it("keeps observed H-E-B blocked products and counts them", () => {
    const records = pendingOutcomes.heb as PdppRecord[];
    const orderItems = records.map(({ data }) => ({
      stream: "order_items",
      data: {
        id: `line-${data.product_id}`,
        product_id: data.product_id,
        name: data.name,
        product_url: data.product_url,
      },
    }));
    const payload = project(
      "heb.nutrition",
      [...orderItems, ...records],
      ["nutrition", "orders", "order_items"],
    );
    expect(payload).toMatchObject({
      items: {
        "heb-2": {
          productUrl: "https://www.heb.com/product-detail/heb-2",
          source: "blocked",
        },
      },
      coverage: {
        total: 2,
        found: 1,
        foundUSDA: 0,
        blocked: 1,
        percentCovered: 50,
      },
    });
    validates(hebNutritionSchema, payload);
  });

  it("preserves a not-found H-E-B product with its matching null URL", () => {
    const payload = project(
      "heb.nutrition",
      [
        {
          stream: "order_items",
          data: {
            id: "line-1",
            product_id: "heb-1",
            name: "Mystery item",
            product_url: null,
          },
        },
        {
          stream: "nutrition",
          data: {
            product_id: "heb-1",
            name: "Mystery item",
            product_url: null,
            source: "not_found",
          },
        },
      ],
      ["nutrition", "orders", "order_items"],
    );
    expect(payload).toMatchObject({
      items: {
        "heb-1": {
          name: "Mystery item",
          productUrl: null,
          source: "not_found",
        },
      },
      coverage: { total: 1, found: 0, foundUSDA: 0, percentCovered: 0 },
    });
    validates(hebNutritionSchema, payload);
  });

  it("requires a null H-E-B URL to have a matching not-found outcome", () => {
    expect(
      LEGACY_SCOPE_BINDINGS.get("heb.nutrition")?.project(
        [
          {
            stream: "order_items",
            data: {
              id: "line-1",
              product_id: "heb-1",
              name: "Oats",
              product_url: null,
            },
          },
          {
            stream: "nutrition",
            data: {
              product_id: "heb-1",
              name: "Oats",
              product_url: null,
              source: "blocked",
            },
          },
        ],
        { fetchedStreams: ["nutrition", "orders", "order_items"] },
      ),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
  });

  it("uses the first order-line name when nutrition metadata uses a different name", () => {
    const payload = project(
      "heb.nutrition",
      [
        {
          stream: "order_items",
          data: {
            id: "line-1",
            product_id: "heb-1",
            name: "Oats 16 oz",
            product_url: "https://www.heb.com/product-detail/heb-1",
          },
        },
        {
          stream: "order_items",
          data: {
            id: "line-2",
            product_id: "heb-1",
            name: "Oats",
            product_url: "https://www.heb.com/product-detail/heb-1",
          },
        },
        {
          stream: "nutrition",
          data: {
            product_id: "heb-1",
            name: "Oats",
            product_url: "https://www.heb.com/product-detail/heb-1",
            source: "heb_product_page",
          },
        },
      ],
      ["nutrition", "orders", "order_items"],
    );
    expect(payload).toMatchObject({
      items: { "heb-1": { name: "Oats 16 oz" } },
    });
  });

  it("fails closed when H-E-B nutrition outcomes omit, duplicate, or diverge from observed products", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("heb.nutrition");
    const items: PdppRecord[] = [
      {
        stream: "order_items",
        data: {
          id: "line-1",
          product_id: "heb-1",
          name: "Oats",
          product_url: "https://www.heb.com/product-detail/heb-1",
        },
      },
      {
        stream: "order_items",
        data: {
          id: "line-2",
          product_id: "heb-2",
          name: "Milk",
          product_url: "https://www.heb.com/product-detail/heb-2",
        },
      },
    ];
    const outcomes: PdppRecord[] = items.map(({ data }, i) => ({
      stream: "nutrition",
      data: {
        id: `nutrition-${i + 1}`,
        product_id: data.product_id,
        name: data.name,
        product_url: data.product_url,
        source: "blocked",
      },
    }));
    const options = { fetchedStreams: ["nutrition", "orders", "order_items"] };
    for (const records of [
      [...items, outcomes[0]!],
      [...items, ...outcomes, outcomes[1]!],
      [
        ...items,
        ...outcomes,
        {
          stream: "nutrition",
          data: {
            product_id: "heb-3",
            name: "Beans",
            product_url: "https://www.heb.com/product-detail/heb-3",
            source: "blocked",
          },
        },
      ],
      [
        ...items,
        {
          ...outcomes[0]!,
          data: {
            ...outcomes[0]!.data,
            product_url: "https://www.heb.com/product-detail/wrong",
          },
        },
        outcomes[1]!,
      ],
    ]) {
      expect(binding?.project(records, options)).toMatchObject({
        ok: false,
        error: { kind: "incomplete_scope" },
      });
    }
  });

  it("projects the Whole Foods account profile without emitting its internal account id", () => {
    const payload = project(
      "wholefoods.profile",
      [
        {
          stream: "profile",
          data: {
            id: "amazon-customer-1",
            name: "Ada Example",
            email: "ada@example.test",
          },
        },
      ],
      ["profile"],
    );
    expect(payload).toEqual({ name: "Ada Example", email: "ada@example.test" });
    validates(wholefoodsProfileSchema, payload);
  });

  it("joins Whole Foods line items by order id and keeps the Amazon product identity", () => {
    const payload = project(
      "wholefoods.orders",
      [
        {
          stream: "orders",
          data: {
            id: "order-1",
            order_date: "2026-09-01",
            order_url: "https://amazon.test/order/1",
            status: null,
            total_cents: 1234,
            item_count: 1,
          },
        },
        {
          stream: "order_items",
          data: {
            id: "line-1",
            order_id: "order-1",
            name: "Apples",
            product_id: "B000000001",
            product_url: "https://amazon.test/dp/B000000001",
            image_url: "https://img.test/apple.jpg",
            quantity: 2,
            unit_price_cents: 617,
          },
        },
      ],
      ["orders", "order_items"],
    );
    expect(payload).toEqual({
      orders: [
        {
          orderId: "order-1",
          orderUrl: "https://amazon.test/order/1",
          orderDate: "2026-09-01",
          status: "Completed",
          total: 12.34,
          itemCount: 1,
          items: [
            {
              name: "Apples",
              productId: "B000000001",
              productUrl: "https://amazon.test/dp/B000000001",
              imageUrl: "https://img.test/apple.jpg",
              quantity: "2",
              price: 6.17,
            },
          ],
        },
      ],
      totalOrders: 1,
      totalItems: 1,
    });
    validates(wholefoodsOrdersSchema, payload);
  });

  it("maps Whole Foods nutrition values to the frozen legacy script shape", () => {
    const payload = project(
      "wholefoods.nutrition",
      [
        {
          stream: "order_items",
          data: {
            id: "line-1",
            product_id: "B000000001",
            name: "Apples",
            product_url: "https://amazon.test/dp/B000000001",
            image_url: "https://img.test/apple.jpg",
          },
        },
        {
          stream: "nutrition",
          data: {
            product_id: "B000000001",
            name: "Apples",
            source: "usda_fdc",
            confidence: "medium",
            calories: 52,
            carbs_g: 14,
            serving_size: "100 g",
            servings_per_container: 4,
          },
        },
      ],
      ["nutrition", "order_items"],
    );
    expect(payload).toMatchObject({
      items: {
        B000000001: {
          name: "Apples",
          source: "usda_fdc",
          productUrl: "https://amazon.test/dp/B000000001",
          images: {
            thumbnail: "https://img.test/apple.jpg",
            full: "",
          },
          calories: 52,
          carbs_g: 14,
          servingSize: "100 g",
          servingsPerContainer: "4",
        },
      },
      coverage: { total: 1, found: 0, foundUSDA: 1, percentCovered: 100 },
    });
    validates(wholefoodsNutritionSchema, payload);
  });

  it("keeps cancelled orders with no item rows and preserves nullable legacy fields", () => {
    const payload = project(
      "wholefoods.orders",
      [
        {
          stream: "orders",
          data: {
            id: "cancelled-order",
            status: "Cancelled",
            order_date: null,
            order_url: "https://amazon.test/order/cancelled",
            total_cents: null,
            item_count: null,
          },
        },
      ],
      ["orders", "order_items"],
    );
    expect(payload).toEqual({
      orders: [
        {
          orderId: "cancelled-order",
          orderUrl: "https://amazon.test/order/cancelled",
          orderDate: null,
          total: null,
          itemCount: null,
          status: "Cancelled",
          items: [],
        },
      ],
      totalOrders: 1,
      totalItems: 0,
    });
    validates(wholefoodsOrdersSchema, payload);
  });

  it("differentially projects good, failed, and recovered offline refreshes through ingest", () => {
    const store = createMemoryRecordStore();
    const streamSemantics = () => "mutable_state" as const;
    const primaryKeyFields = (stream: string) =>
      stream === "orders"
        ? ["id"]
        : stream === "order_items"
          ? ["id"]
          : ["product_id"];
    const ingest = (
      emittedAt: string,
      records: Array<{
        stream: string;
        key: string;
        data: Record<string, unknown>;
      }>,
    ) =>
      store.ingestBatch(
        records.map((record) => ({
          instance: "amazon-account",
          stream: record.stream,
          key: record.key,
          data: record.data,
          emitted_at: emittedAt,
        })),
        streamSemantics,
        primaryKeyFields,
      );
    const projectStored = (scope: string, streams: string[]) => {
      const records: PdppRecord[] = streams.flatMap((stream) =>
        store
          .listRecords(stream, {
            instanceIds: ["amazon-account"],
            limit: 100,
            order: "asc",
          })
          .data.map((row) => ({ stream, data: row.data })),
      );
      const result = LEGACY_SCOPE_BINDINGS.get(scope)?.project(records, {
        fetchedStreams: streams,
      });
      expect(result?.ok, JSON.stringify(result)).toBe(true);
      if (!result?.ok) throw new Error(`Projection failed for ${scope}`);
      return result.payload;
    };
    const nutrition = (calories: number) => ({
      product_id: "B000000001",
      name: "Apples",
      source: "wholefoods_structured_data",
      confidence: "high",
      calories,
      protein_g: 0.3,
      carbs_g: 14,
      fat_g: 0.2,
      saturated_fat_g: 0,
      trans_fat_g: 0,
      cholesterol_mg: 0,
      added_sugar_g: null,
      sodium_mg: 1,
      potassium_mg: 107,
      calcium_mg: 6,
      iron_mg: 0.1,
      vitamin_d_mcg: 0,
      fiber_g: 2.4,
      sugar_g: 10,
      ingredients: "Apples",
      allergens: null,
      highlights: [],
      category: ["Produce"],
      upc: "012345678905",
      raw_nutrition_text: null,
      usda_fdc_id: null,
      usda_match_method: null,
      usda_description: null,
      usda_brand: null,
      type: "https://schema.org/NutritionInformation",
      serving_size: "1 medium",
      servings_per_container: null,
    });
    const order = (id: string, status = "Completed") => ({
      id,
      order_date: "2026-10-01",
      order_url: `https://amazon.test/order/${id}`,
      status,
      total_cents: null,
      item_count: status === "Cancelled" ? 0 : 1,
    });
    const item = (id: string, orderId: string) => ({
      id,
      order_id: orderId,
      name: "Apples",
      product_id: "B000000001",
      product_url: "https://amazon.test/dp/B000000001",
      image_url: "https://img.test/apples.jpg",
      quantity: 1,
      unit_price_cents: null,
    });

    const good = ingest("2026-10-01T00:00:00.000Z", [
      { stream: "orders", key: "order-1", data: order("order-1") },
      {
        stream: "orders",
        key: "cancelled-1",
        data: order("cancelled-1", "Cancelled"),
      },
      {
        stream: "order_items",
        key: "order-1#B000000001",
        data: item("order-1#B000000001", "order-1"),
      },
      { stream: "nutrition", key: "B000000001", data: nutrition(52) },
    ]);
    expect(good.rejected).toEqual([]);
    expect(
      projectStored("wholefoods.nutrition", ["nutrition", "order_items"]),
    ).toMatchObject({
      items: {
        B000000001: {
          images: { thumbnail: "https://img.test/apples.jpg", full: "" },
          calories: 52,
          ingredients: "Apples",
          upc: "012345678905",
          "@type": "https://schema.org/NutritionInformation",
        },
      },
    });

    // This is a failed refresh: a new order and item arrived, one detail was
    // unreadable, and nutrition lookup failed. The data connector withholds
    // both failed same-key rows; absence is not a delete in mutable-state ingest.
    const failed = ingest("2026-10-02T00:00:00.000Z", [
      { stream: "orders", key: "order-2", data: order("order-2") },
      {
        stream: "order_items",
        key: "order-2#B000000001",
        data: item("order-2#B000000001", "order-2"),
      },
    ]);
    expect(failed.rejected).toEqual([]);
    expect(
      store.getRecord("amazon-account", "nutrition", "B000000001")?.data
        .calories,
    ).toBe(52);
    expect(
      store.getRecord("amazon-account", "orders", "order-1")?.data.order_date,
    ).toBe("2026-10-01");
    expect(
      projectStored("wholefoods.orders", ["orders", "order_items"]),
    ).toMatchObject({
      totalOrders: 3,
      orders: [
        {
          orderId: "cancelled-1",
          status: "Cancelled",
          items: [],
          itemCount: null,
          total: null,
        },
        {
          orderId: "order-1",
          items: [{ productId: "B000000001", quantity: "1" }],
        },
        {
          orderId: "order-2",
          items: [{ productId: "B000000001", quantity: "1" }],
        },
      ],
    });

    const recovered = ingest("2026-10-03T00:00:00.000Z", [
      { stream: "orders", key: "order-3", data: order("order-3") },
      {
        stream: "order_items",
        key: "order-3#B000000001",
        data: item("order-3#B000000001", "order-3"),
      },
      { stream: "nutrition", key: "B000000001", data: nutrition(53) },
    ]);
    expect(recovered.rejected).toEqual([]);
    expect(
      projectStored("wholefoods.nutrition", ["nutrition", "order_items"]),
    ).toMatchObject({
      items: {
        B000000001: { calories: 53, source: "wholefoods_structured_data" },
      },
      coverage: { total: 1, found: 1 },
    });
  });

  it("projects every Whole Foods nutrition outcome and counts blocked lookups", () => {
    const payload = project(
      "wholefoods.nutrition",
      pendingOutcomes.wholefoods as PdppRecord[],
      ["nutrition", "order_items"],
    );
    expect(payload).toMatchObject({
      items: {
        B000000001: {
          source: "wholefoods_product_page",
          productUrl: "https://www.amazon.com/dp/B000000001",
        },
        B000000002: { source: "usda_fdc" },
        B000000003: { source: "not_found" },
        B000000004: { source: "error" },
        B000000005: { source: "blocked" },
      },
      coverage: {
        total: 5,
        found: 1,
        foundUSDA: 1,
        blocked: 1,
        percentCovered: 40,
      },
    });
    validates(wholefoodsNutritionSchema, payload);
  });

  it("fails closed when Whole Foods nutrition omits, duplicates, or invents a product outcome", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("wholefoods.nutrition");
    const records = pendingOutcomes.wholefoods as PdppRecord[];
    for (const incomplete of [
      records.slice(0, -1),
      [...records, records.at(-1)!],
      [
        ...records,
        {
          stream: "nutrition",
          data: { product_id: "B000000099", name: "Extra", source: "blocked" },
        },
      ],
    ]) {
      expect(
        binding?.project(incomplete, {
          fetchedStreams: ["nutrition", "order_items"],
        }),
      ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
    }
  });

  it("reports incomplete Whole Foods order snapshots as partial, and rejects an order with no usable line", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("wholefoods.orders");
    const order = { stream: "orders", data: { id: "order-1", item_count: 2 } };
    const item = {
      stream: "order_items",
      data: {
        id: "line-1",
        order_id: "order-1",
        name: "Oats",
        product_id: "B000000001",
      },
    };
    const project = (records: (typeof order)[]) =>
      binding?.project(records, { fetchedStreams: ["orders", "order_items"] });
    // Short of, or without, a known line count: delivered, never complete.
    for (const shortOrUnknown of [
      [order, item],
      [{ ...order, data: { id: "order-1" } }, item],
    ]) {
      expect(project(shortOrUnknown)).toMatchObject({
        ok: true,
        payload: { orders: [{ orderId: "order-1" }] },
        diagnostics: [
          {
            kind: "records_partial",
            stream: "orders",
            count: 1,
            reasons: ["projection_order_item_count_mismatch"],
          },
        ],
      });
    }
    expect(
      project([order, { ...item, data: { ...item.data, product_id: null } }]),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
  });
});

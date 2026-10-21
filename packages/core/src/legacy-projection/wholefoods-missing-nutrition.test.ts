import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import schema from "./__fixtures__/desktop-schemas/wholefoods.nutrition.json";
import profile from "./declarations/wholefoods.collection-profile.json";
import type { PdppRecord } from "./types.js";
import sparse from "./__fixtures__/wholefoods-sparse-nutrition.json";

// Record shape: data-connectors fe25d7a12, connectors/wholefoods/schemas.ts.
// A read page with no panel and an unread page both produce no nutrition row.
const orderedItem = sparse.orderItems[0];

describe("Whole Foods products without nutrition records", () => {
  it("keeps the read panel facts alongside no-panel and unread products", () => {
    const records: PdppRecord[] = [
      ...sparse.orderItems.map((data) => ({ stream: "order_items", data })),
      ...sparse.nutrition.map((data) => ({ stream: "nutrition", data })),
    ];
    const ajv = new Ajv({ strict: false });
    for (const { stream, data } of records) {
      expect(
        ajv.validate(
          profile.streams.find((s) => s.name === stream)!.schema,
          data,
        ),
      ).toBe(true);
    }
    const result = projectPdppRecordsToLegacyPayload(
      "wholefoods.nutrition",
      records,
      {
        fetchedStreams: ["order_items", "nutrition"],
      },
    );
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    const items = result.payload.items as Record<
      string,
      Record<string, unknown>
    >;
    expect(Object.keys(items).sort()).toEqual([
      "B000000001",
      "B000000002",
      "B000000003",
    ]);
    expect(items.B000000001).toEqual({
      name: "Sea Salt",
      source: "not_found",
      productUrl: orderedItem.product_url,
      images: { thumbnail: "", full: "" },
      "@type": "https://schema.org/NutritionInformation",
    });
    expect(items.B000000003).toEqual({
      name: "Apples",
      source: "not_found",
      images: { thumbnail: "", full: "" },
      "@type": "https://schema.org/NutritionInformation",
    });
    expect(items.B000000002).toMatchObject({
      name: "Oats",
      source: "wholefoods_product_page",
      confidence: "high",
      calories: 150,
      protein_g: 5,
      carbs_g: 27,
      fat_g: 3,
      servingSize: "40 g",
      servingsPerContainer: "10",
      images: { thumbnail: sparse.orderItems[1].image_url, full: "" },
    });
    expect(result.payload.coverage).toEqual({
      total: 3,
      found: 1,
      foundUSDA: 0,
      blocked: 0,
      percentCovered: 33,
    });
    expect(ajv.validate(schema.schema, result.payload)).toBe(true);
  });
  it("projects the frozen legacy not_found shape without inventing nutrition facts", () => {
    const records: PdppRecord[] = [
      { stream: "order_items", data: orderedItem },
    ];
    const ajv = new Ajv({ strict: false });
    expect(
      ajv.validate(
        profile.streams.find((s) => s.name === "order_items")!.schema,
        orderedItem,
      ),
    ).toBe(true);
    const result = projectPdppRecordsToLegacyPayload(
      "wholefoods.nutrition",
      records,
      {
        fetchedStreams: ["order_items", "nutrition"],
      },
    );
    expect(result).toEqual({
      ok: true,
      payload: {
        items: {
          B000000001: {
            name: "Sea Salt",
            source: "not_found",
            productUrl: "https://www.amazon.com/dp/B000000001",
            images: { thumbnail: "", full: "" },
            "@type": "https://schema.org/NutritionInformation",
          },
        },
        coverage: {
          total: 1,
          found: 0,
          foundUSDA: 0,
          blocked: 0,
          percentCovered: 0,
        },
      },
    });
    if (result.ok)
      expect(ajv.validate(schema.schema, result.payload)).toBe(true);
  });
});

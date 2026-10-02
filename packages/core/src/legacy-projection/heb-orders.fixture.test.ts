import { describe, expect, it } from "vitest";
import fixture from "./__fixtures__/heb.orders.pdpp-input.json";
import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import type { PdppRecord } from "./types.js";

describe("heb.orders legacy projection fixture", () => {
  it("preserves nested items when the collected count meets H-E-B's declared count", () => {
    const result = LEGACY_SCOPE_BINDINGS.get("heb.orders")?.project(
      [
        {
          stream: "orders",
          data: { id: "order-1", order_date: "2026-09-15", item_count: 1 },
        },
        {
          stream: "order_items",
          data: {
            id: "line-1",
            order_id: "order-1",
            name: "Apples",
            product_id: "12345678",
          },
        },
      ],
      { fetchedStreams: ["orders", "order_items"] },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        orders: [
          {
            orderId: "order-1",
            items: [
              {
                name: "Apples",
                productId: "12345678",
                productUrl: null,
                imageUrl: null,
                quantity: null,
              },
            ],
            orderDate: "September 15, 2026",
            itemCount: 1,
          },
        ],
        totalOrders: 1,
        totalItems: 1,
      },
    });
  });

  it("rejects an empty item stream when H-E-B reports items on an order", () => {
    const result = LEGACY_SCOPE_BINDINGS.get("heb.orders")?.project(
      [
        {
          stream: "orders",
          data: { id: "order-1", order_date: "2026-09-15", item_count: 1 },
        },
      ],
      { fetchedStreams: ["orders", "order_items"] },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "heb.orders" },
    });
  });

  it("rejects valid source lines that the retained Desktop payload cannot represent", () => {
    const result = LEGACY_SCOPE_BINDINGS.get("heb.orders")?.project(
      fixture.records as PdppRecord[],
      { fetchedStreams: ["orders", "order_items"] },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "heb.orders" },
    });
  });
});

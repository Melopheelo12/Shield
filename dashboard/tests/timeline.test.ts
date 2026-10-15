import { describe, expect, it } from "vitest";
import { bucketize } from "../src/utils/timeline";
import type { ServiceName } from "../src/types/events";

const at = (iso: string, service: ServiceName = "ssh") => ({ occurred_at: iso, service });

describe("bucketize — chronologie", () => {
  it("ne produit rien sans événement", () => {
    expect(bucketize([]).buckets).toEqual([]);
  });

  it("compte par service dans la bonne tranche d'une minute", () => {
    const { step, buckets } = bucketize([
      at("2026-10-09T10:00:05Z", "ssh"),
      at("2026-10-09T10:00:40Z", "http"),
      at("2026-10-09T10:02:10Z", "ssh"),
    ]);
    expect(step).toBe(60_000);
    expect(buckets.map(({ ssh, http, ftp }) => [ssh, http, ftp])).toEqual([
      [1, 1, 0],
      [0, 0, 0],
      [1, 0, 0],
    ]);
  });

  it("garde les tranches vides : une accalmie reste visible", () => {
    const { buckets } = bucketize([at("2026-10-09T10:00:00Z"), at("2026-10-09T10:30:00Z")]);
    expect(buckets.length).toBe(31);
    expect(buckets.slice(1, -1).every((b) => b.ssh + b.http + b.ftp === 0)).toBe(true);
  });

  it("élargit le pas pour ne jamais dépasser 60 tranches", () => {
    const { step, buckets } = bucketize([at("2026-10-01T00:00:00Z"), at("2026-10-09T00:00:00Z")]);
    expect(step).toBe(6 * 3_600_000);
    expect(buckets.length).toBeLessThanOrEqual(60);
  });

  it("ignore un horodatage illisible au lieu de casser la courbe", () => {
    const { buckets } = bucketize([
      at("2026-10-09T10:00:00Z", "ssh"),
      at("pas une date", "ftp"),
      at("2026-10-09T10:01:00Z", "http"),
    ]);
    expect(buckets.map(({ ssh, http, ftp }) => [ssh, http, ftp])).toEqual([
      [1, 0, 0],
      [0, 1, 0],
    ]);
  });
});

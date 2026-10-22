import { describe, expect, it } from "vitest";
import { DEFAULT_FILTERS, parseFilters, serializeFilters } from "../src/hooks/useFilters";

describe("filtres ↔ URL", () => {
  it("retombe sur les valeurs par défaut pour une URL vide", () => {
    expect(parseFilters("")).toEqual(DEFAULT_FILTERS);
  });

  it("lit période, service, pays et score minimal", () => {
    expect(parseFilters("?periode=7d&service=ssh&pays=fr&score=60")).toEqual({
      period: "7d",
      service: "ssh",
      country: "FR",
      minScore: 60,
    });
  });

  it("n'accepte que les paliers de score 30 et 60", () => {
    expect(parseFilters("?score=45").minScore).toBe(0);
    expect(parseFilters("?score=-1").minScore).toBe(0);
    expect(parseFilters("?score=30").minScore).toBe(30);
  });

  it("ignore les valeurs inconnues ou malformées", () => {
    expect(parseFilters("?periode=1an&service=telnet&pays=<script>&score=abc")).toEqual(DEFAULT_FILTERS);
  });

  it("aller-retour sans perte", () => {
    const filters = { period: "1h", service: "ftp", country: "CN", minScore: 30 } as const;
    expect(parseFilters(serializeFilters(filters))).toEqual(filters);
  });

  it("n'écrit pas les valeurs par défaut et conserve les autres paramètres", () => {
    expect(serializeFilters(DEFAULT_FILTERS, "?vue=journal&pays=FR")).toBe("?vue=journal");
  });
});

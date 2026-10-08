import { describe, expect, it } from "vitest";
import { DEFAULT_FILTERS, parseFilters, serializeFilters } from "../src/hooks/useFilters";

describe("filtres ↔ URL", () => {
  it("retombe sur les valeurs par défaut pour une URL vide", () => {
    expect(parseFilters("")).toEqual(DEFAULT_FILTERS);
  });

  it("lit période, service et pays", () => {
    expect(parseFilters("?periode=7d&service=ssh&pays=fr")).toEqual({
      period: "7d",
      service: "ssh",
      country: "FR",
    });
  });

  it("ignore les valeurs inconnues ou malformées", () => {
    expect(parseFilters("?periode=1an&service=telnet&pays=<script>")).toEqual(DEFAULT_FILTERS);
  });

  it("aller-retour sans perte", () => {
    const filters = { period: "1h", service: "ftp", country: "CN" } as const;
    expect(parseFilters(serializeFilters(filters))).toEqual(filters);
  });

  it("n'écrit pas les valeurs par défaut et conserve les autres paramètres", () => {
    expect(serializeFilters(DEFAULT_FILTERS, "?vue=journal&pays=FR")).toBe("?vue=journal");
  });
});

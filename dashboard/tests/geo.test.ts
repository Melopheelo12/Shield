import { describe, expect, it } from "vitest";
import { countryName, fromCountryCounts } from "../src/utils/geo";

const row = (country_code: string | null, events: number, unique_ips = 1) => ({ country_code, events, unique_ips });

describe("fromCountryCounts — carte des origines", () => {
  it("classe les pays du plus actif au moins actif", () => {
    const { countries } = fromCountryCounts([row("FR", 1), row("CN", 2), row("BR", 2)]);
    expect(countries.map((c) => [c.code, c.events])).toEqual([
      ["BR", 2],
      ["CN", 2],
      ["FR", 1],
    ]);
  });

  it("donne le code numérique du fond de carte et le nom français", () => {
    const [france] = fromCountryCounts([row("FR", 4, 3)]).countries;
    expect(france).toMatchObject({ numeric: "250", name: "France", events: 4, uniqueIps: 3 });
  });

  it("compte à part les tentatives non situées, en nombre de tentatives", () => {
    const result = fromCountryCounts([row(null, 40), row("FR", 2), row("zz9", 5)]);
    expect(result.unlocated).toBe(45);
    expect(result.countries).toHaveLength(1);
  });

  it("accepte un code en minuscules et fusionne les doublons de casse", () => {
    const { countries } = fromCountryCounts([row("de", 1, 1), row("DE", 2, 2)]);
    expect(countries).toHaveLength(1);
    expect(countries[0]).toMatchObject({ code: "DE", events: 3, uniqueIps: 3 });
  });

  it("retombe sur le code pour un pays inconnu", () => {
    expect(countryName("XX")).toBe("XX");
  });
});

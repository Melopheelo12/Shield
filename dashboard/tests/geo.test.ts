import { describe, expect, it } from "vitest";
import { aggregateByCountry, countryName } from "../src/utils/geo";

const event = (country_code: string | null, source_ip = "192.0.2.1", threat_score = 10) => ({
  country_code,
  source_ip,
  threat_score,
});

describe("aggregateByCountry — carte des origines", () => {
  it("compte par pays, du plus actif au moins actif", () => {
    const { countries } = aggregateByCountry([
      event("FR"),
      event("CN", "198.51.100.1"),
      event("CN", "198.51.100.2"),
    ]);
    expect(countries.map((c) => [c.code, c.events])).toEqual([
      ["CN", 2],
      ["FR", 1],
    ]);
  });

  it("donne le code numérique du fond de carte et le nom français", () => {
    const [france] = aggregateByCountry([event("FR")]).countries;
    expect(france.numeric).toBe("250");
    expect(france.name).toBe("France");
  });

  it("garde le score maximal et des adresses sans doublon", () => {
    const [cn] = aggregateByCountry([
      event("CN", "198.51.100.1", 20),
      event("CN", "198.51.100.1", 80),
      event("CN", "198.51.100.2", 40),
    ]).countries;
    expect(cn.maxScore).toBe(80);
    expect(cn.ips).toEqual(["198.51.100.1", "198.51.100.2"]);
  });

  it("compte à part les événements sans pays au lieu de les cacher", () => {
    const result = aggregateByCountry([event(null), event(""), event("FR"), event("zz9")]);
    expect(result.unlocated).toBe(3);
    expect(result.countries).toHaveLength(1);
  });

  it("accepte un code en minuscules", () => {
    expect(aggregateByCountry([event("de")]).countries[0].code).toBe("DE");
  });

  it("retombe sur le code pour un pays inconnu", () => {
    expect(countryName("XX")).toBe("XX");
  });
});

import countries from "i18n-iso-countries";
import fr from "i18n-iso-countries/langs/fr.json";
import type { CountryCount } from "../api/stats";

countries.registerLocale(fr);

export interface CountryActivity {
  /** Code ISO 3166-1 alpha-2, en majuscules. */
  code: string;
  /** Code numérique ISO 3166-1 : l'identifiant des pays dans le fond de carte. */
  numeric: string | undefined;
  name: string;
  events: number;
  uniqueIps: number;
}

/** Nom français d'un pays, ou le code s'il est inconnu. */
export function countryName(code: string): string {
  return countries.getName(code, "fr") ?? code;
}

/**
 * Met en forme le décompte par pays du collecteur (`GET /api/v1/stats/by-country`),
 * du plus actif au moins actif.
 *
 * Les adresses non situées (`country_code: null`, GeoIP absente ou adresse inconnue)
 * sont comptées à part : les cacher ferait croire que la carte couvre toute l'activité.
 */
export function fromCountryCounts(items: CountryCount[]): { countries: CountryActivity[]; unlocated: number } {
  const byCode = new Map<string, CountryActivity>();
  let unlocated = 0;

  for (const item of items) {
    const code = item.country_code?.toUpperCase();
    if (!code || !/^[A-Z]{2}$/.test(code)) {
      unlocated += item.events;
      continue;
    }
    const entry = byCode.get(code) ?? {
      code,
      numeric: countries.alpha2ToNumeric(code),
      name: countryName(code),
      events: 0,
      uniqueIps: 0,
    };
    entry.events += item.events;
    entry.uniqueIps += item.unique_ips;
    byCode.set(code, entry);
  }

  const sorted = [...byCode.values()].sort((a, b) => b.events - a.events || a.code.localeCompare(b.code));
  return { countries: sorted, unlocated };
}

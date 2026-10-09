import countries from "i18n-iso-countries";
import fr from "i18n-iso-countries/langs/fr.json";

countries.registerLocale(fr);

export interface CountryActivity {
  /** Code ISO 3166-1 alpha-2, en majuscules. */
  code: string;
  /** Code numérique ISO 3166-1 : l'identifiant des pays dans le fond de carte. */
  numeric: string | undefined;
  name: string;
  events: number;
  maxScore: number;
  ips: string[];
}

/** Nom français d'un pays, ou le code s'il est inconnu. */
export function countryName(code: string): string {
  return countries.getName(code, "fr") ?? code;
}

/**
 * Agrège des événements par pays d'origine, du plus actif au moins actif.
 *
 * Les événements sans pays — enrichissement GeoIP pas encore passé — sont comptés
 * à part : les cacher ferait croire que la carte couvre toute l'activité.
 */
export function aggregateByCountry(
  events: { country_code: string | null; source_ip: string; threat_score: number }[],
): { countries: CountryActivity[]; unlocated: number } {
  const byCode = new Map<string, CountryActivity>();
  let unlocated = 0;

  for (const event of events) {
    const code = event.country_code?.toUpperCase();
    if (!code || !/^[A-Z]{2}$/.test(code)) {
      unlocated += 1;
      continue;
    }
    let entry = byCode.get(code);
    if (!entry) {
      entry = {
        code,
        numeric: countries.alpha2ToNumeric(code),
        name: countryName(code),
        events: 0,
        maxScore: 0,
        ips: [],
      };
      byCode.set(code, entry);
    }
    entry.events += 1;
    entry.maxScore = Math.max(entry.maxScore, event.threat_score);
    if (!entry.ips.includes(event.source_ip)) entry.ips.push(event.source_ip);
  }

  const sorted = [...byCode.values()].sort((a, b) => b.events - a.events || a.code.localeCompare(b.code));
  return { countries: sorted, unlocated };
}

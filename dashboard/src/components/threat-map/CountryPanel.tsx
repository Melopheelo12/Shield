import type { CountryActivity } from "../../utils/geo";
import { formatCountry } from "../../utils/format";
import { ThreatScore } from "../common/ThreatScore";

interface Props {
  countries: CountryActivity[];
  selected: string | null;
  onSelect: (code: string | null) => void;
}

/**
 * Classement des pays, alternative clavier et lecteur d'écran à la carte. Le pays
 * sélectionné déplie ses adresses et mène au journal filtré sur lui.
 */
export function CountryPanel({ countries, selected, onSelect }: Props) {
  return (
    <ol className="country-list">
      {countries.slice(0, 15).map((country) => {
        const open = country.code === selected;
        return (
          <li key={country.code} className={open ? "is-selected" : undefined}>
            <button
              type="button"
              className="country-list__row"
              aria-expanded={open}
              onClick={() => onSelect(open ? null : country.code)}
            >
              <span className="truncate">
                {formatCountry(country.code)} <span className="muted">{country.name}</span>
              </span>
              <span className="num">{country.events.toLocaleString("fr-FR")}</span>
              <ThreatScore score={country.maxScore} />
            </button>
            {open && (
              <div className="country-list__detail">
                <ul className="mono">
                  {country.ips.slice(0, 10).map((ip) => (
                    <li key={ip}>{ip}</li>
                  ))}
                </ul>
                {country.ips.length > 10 && (
                  <p className="muted">et {country.ips.length - 10} autre(s) adresse(s)</p>
                )}
                <a href={`?pays=${country.code}#/journal`}>Voir ses tentatives dans le journal →</a>
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

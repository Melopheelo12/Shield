import type { NormalizedEvent } from "../../types/events";
import { useApi } from "../../hooks/useApi";
import type { CountryActivity } from "../../utils/geo";
import { formatCountry } from "../../utils/format";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

interface Props {
  countries: CountryActivity[];
  selected: string | null;
  onSelect: (code: string | null) => void;
}

const DETAIL_SAMPLE = 200;

/** Les adresses d'un pays, tirées de ses dernières tentatives, la plus menaçante d'abord. */
function CountryDetail({ code }: { code: string }) {
  const events = useApi<{ items: NormalizedEvent[] }>(`/api/v1/events?country=${code}&limit=${DETAIL_SAMPLE}`);
  if (events.status === "loading") return <LoadingState />;
  if (events.status === "error") return <ErrorState message={events.message} onRetry={events.reload} />;

  const worst = new Map<string, number>();
  for (const event of events.status === "ready" ? events.data.items : []) {
    worst.set(event.source_ip, Math.max(worst.get(event.source_ip) ?? 0, event.threat_score));
  }
  const ips = [...worst.entries()].sort((a, b) => b[1] - a[1]);

  return (
    <>
      <ul className="ip-list">
        {ips.slice(0, 10).map(([ip, score]) => (
          <li key={ip}>
            <span className="mono">{ip}</span>
            <ThreatScore score={score} />
          </li>
        ))}
      </ul>
      {ips.length > 10 && <p className="muted">et {ips.length - 10} autre(s) adresse(s)</p>}
      <p className="muted">Sur ses {DETAIL_SAMPLE} dernières tentatives au plus.</p>
    </>
  );
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
              <span className="num muted">{country.uniqueIps.toLocaleString("fr-FR")} IP</span>
            </button>
            {open && (
              <div className="country-list__detail">
                <CountryDetail code={country.code} />
                <a href={`?pays=${country.code}#/journal`}>Voir ses tentatives dans le journal →</a>
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

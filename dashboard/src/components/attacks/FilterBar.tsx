import { useEffect, useState } from "react";
import type { EventFilters } from "../../hooks/useFilters";
import { PERIODS, SERVICES, type PeriodKey } from "../../utils/constants";

interface Props {
  filters: EventFilters;
  onChange: (patch: Partial<EventFilters>) => void;
  onReset: () => void;
}

/** Période, service, pays. L'état vit dans l'URL (voir `useFilters`). */
export function FilterBar({ filters, onChange, onReset }: Props) {
  // Le pays se saisit lettre par lettre : on ne pousse dans l'URL qu'un code complet.
  const [country, setCountry] = useState(filters.country);
  useEffect(() => setCountry(filters.country), [filters.country]);

  const onCountryInput = (value: string) => {
    const code = value.toUpperCase().replace(/[^A-Z]/g, "").slice(0, 2);
    setCountry(code);
    if (code.length === 2 || code.length === 0) onChange({ country: code });
  };

  return (
    <form className="filter-bar" role="search" onSubmit={(event) => event.preventDefault()}>
      <label>
        Période
        <select
          value={filters.period}
          onChange={(event) => onChange({ period: event.target.value as PeriodKey })}
        >
          {Object.entries(PERIODS).map(([key, { label }]) => (
            <option key={key} value={key}>
              {label}
            </option>
          ))}
        </select>
      </label>

      <label>
        Service
        <select
          value={filters.service}
          onChange={(event) => onChange({ service: event.target.value as EventFilters["service"] })}
        >
          <option value="">Tous</option>
          {SERVICES.map((service) => (
            <option key={service} value={service}>
              {service.toUpperCase()}
            </option>
          ))}
        </select>
      </label>

      <label>
        Pays
        <input
          type="text"
          inputMode="text"
          autoComplete="off"
          placeholder="FR"
          maxLength={2}
          size={3}
          value={country}
          onChange={(event) => onCountryInput(event.target.value)}
          aria-describedby="filter-country-hint"
        />
        <span id="filter-country-hint" className="visually-hidden">
          Code pays à deux lettres (ISO 3166-1)
        </span>
      </label>

      <button type="button" onClick={onReset}>
        Réinitialiser
      </button>
    </form>
  );
}

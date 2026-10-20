import { EventTable } from "../components/attacks/EventTable";
import { FilterBar } from "../components/attacks/FilterBar";
import { useEventsPage } from "../hooks/useEventsPage";
import { useFilters } from "../hooks/useFilters";

/** Journal des attaques : barre de filtres + tableau paginé (US-27). */
export function Attacks() {
  const [filters, updateFilters, resetFilters] = useFilters();
  const events = useEventsPage(filters);

  return (
    <section className="grid" aria-label="Journal des attaques">
      <FilterBar filters={filters} onChange={updateFilters} onReset={resetFilters} />
      <EventTable {...events} />
    </section>
  );
}

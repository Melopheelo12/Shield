import { useCallback, useState } from "react";
import { AttackDetailDrawer } from "../components/attacks/AttackDetailDrawer";
import { EventTable } from "../components/attacks/EventTable";
import { FilterBar } from "../components/attacks/FilterBar";
import { useEventsPage } from "../hooks/useEventsPage";
import { useFilters } from "../hooks/useFilters";
import type { NormalizedEvent } from "../types/events";

/** Journal des attaques : filtres, tableau paginé (US-27) et détail d'une tentative (US-26). */
export function Attacks() {
  const [filters, updateFilters, resetFilters] = useFilters();
  const events = useEventsPage(filters);
  const [selected, setSelected] = useState<NormalizedEvent | null>(null);
  const close = useCallback(() => setSelected(null), []);

  return (
    <section className="grid" aria-label="Journal des attaques">
      <FilterBar filters={filters} onChange={updateFilters} onReset={resetFilters} />
      <EventTable {...events} onSelect={setSelected} />
      {selected && <AttackDetailDrawer event={selected} onClose={close} />}
    </section>
  );
}

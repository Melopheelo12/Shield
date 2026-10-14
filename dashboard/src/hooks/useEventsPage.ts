import { useCallback, useEffect, useState } from "react";
import { fetchEventsPage } from "../api/attacks";
import type { NormalizedEvent } from "../types/events";
import { EVENTS_PAGE_SIZE } from "../utils/constants";
import type { LoadState } from "./useApi";
import type { EventFilters } from "./useFilters";

export interface CursorPagination {
  /** Index de la page affichée, à partir de 0. */
  page: number;
  hasPrevious: boolean;
  hasNext: boolean;
  next: () => void;
  previous: () => void;
}

/**
 * Pagination par curseur. On garde la pile des curseurs déjà visités : revenir en
 * arrière ne demande pas au serveur de « reculer », il suffit de rejouer le curseur
 * de la page précédente.
 */
export function useEventsPage(
  filters: EventFilters,
  pageSize = EVENTS_PAGE_SIZE,
): LoadState<NormalizedEvent[]> & CursorPagination & { reload: () => void } {
  const { period, service, country } = filters;
  const filtersKey = `${period}|${service}|${country}`;
  const [stack, setStack] = useState<{ key: string; cursors: (string | null)[] }>({
    key: filtersKey,
    cursors: [null],
  });
  // Pile liée aux filtres : un changement de filtre repart de la première page
  // sans jamais rejouer un curseur obtenu avec d'anciens filtres.
  const cursors = stack.key === filtersKey ? stack.cursors : [null];
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [state, setState] = useState<LoadState<NormalizedEvent[]>>({ status: "loading" });
  const [reloadKey, setReloadKey] = useState(0);

  const cursor = cursors[cursors.length - 1];
  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    fetchEventsPage({ period, service, country }, cursor, pageSize, controller.signal)
      .then((result) => {
        setNextCursor(result.nextCursor);
        setState(result.items.length === 0 ? { status: "empty" } : { status: "ready", data: result.items });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : String(error) });
      });
    return () => controller.abort();
  }, [period, service, country, cursor, pageSize, reloadKey]);

  const next = useCallback(() => {
    if (nextCursor) setStack({ key: filtersKey, cursors: [...cursors, nextCursor] });
  }, [nextCursor, filtersKey, cursors]);
  const previous = useCallback(() => {
    if (cursors.length > 1) setStack({ key: filtersKey, cursors: cursors.slice(0, -1) });
  }, [filtersKey, cursors]);
  const reload = useCallback(() => setReloadKey((key) => key + 1), []);

  return {
    ...state,
    page: cursors.length - 1,
    hasPrevious: cursors.length > 1,
    hasNext: state.status === "ready" && nextCursor !== null,
    next,
    previous,
    reload,
  };
}

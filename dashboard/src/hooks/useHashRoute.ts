import { useEffect, useState } from "react";

/** Route courante, lue dans le fragment de l'URL : `#/journal` → `"journal"`. */
function readRoute(): string {
  return window.location.hash.replace(/^#\/?/, "").split("?")[0] ?? "";
}

/**
 * Routage par fragment (`#/carte`), sans dépendance.
 *
 * Le fragment ne part jamais au serveur : nginx sert toujours `index.html`, et les
 * filtres du journal restent dans la query string (`?service=ssh#/journal`), donc
 * un lien filtré se partage tel quel.
 */
export function useHashRoute(): string {
  const [route, setRoute] = useState(readRoute);
  useEffect(() => {
    const onChange = () => setRoute(readRoute());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

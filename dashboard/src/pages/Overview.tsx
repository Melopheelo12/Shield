import { useApi } from "../hooks/useApi";
import type { Overview as OverviewStats } from "../types/events";

/**
 * Vue d'ensemble — squelette du sprint 0.
 *
 * Volontairement minimal : il prouve que la chaîne API → types partagés → rendu
 * fonctionne, et il tourne sur le générateur d'événements factices sans qu'aucun
 * leurre ne soit déployé. Les cinq visualisations arrivent au sprint 3 (S3-08).
 */
export function Overview() {
  const stats = useApi<OverviewStats>("/api/v1/stats/overview", 5000);

  if (stats.status === "loading") return <p>Chargement…</p>;
  if (stats.status === "error") return <p>Erreur : {stats.message}</p>;
  if (stats.status === "empty" || stats.data.events === 0) {
    return (
      <main>
        <h1>SHIELD</h1>
        <p>
          La collecte a commencé. Aucune tentative n'a encore été enregistrée — c'est
          normal sur une instance neuve : les premiers balayages arrivent généralement
          dans l'heure.
        </p>
      </main>
    );
  }

  const { events, unique_ips, sessions, max_threat_score } = stats.data;
  return (
    <main>
      <h1>SHIELD</h1>
      <dl>
        <div><dt>Événements</dt><dd>{events.toLocaleString("fr-FR")}</dd></div>
        <div><dt>IP uniques</dt><dd>{unique_ips.toLocaleString("fr-FR")}</dd></div>
        <div><dt>Sessions</dt><dd>{sessions.toLocaleString("fr-FR")}</dd></div>
        <div><dt>Menace max</dt><dd>{max_threat_score}/100</dd></div>
      </dl>
    </main>
  );
}

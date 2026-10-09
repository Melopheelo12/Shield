import { AttackFeed } from "../components/attacks/AttackFeed";
import { ErrorState } from "../components/common/ErrorState";
import { StatCard } from "../components/common/StatCard";
import { ByService } from "../components/charts/ByService";
import { Timeline } from "../components/charts/Timeline";
import { TopCredentials } from "../components/charts/TopCredentials";
import { TopSourceIps } from "../components/charts/TopSourceIps";
import { useApi } from "../hooks/useApi";
import type { Overview as OverviewStats } from "../types/events";

const number = new Intl.NumberFormat("fr-FR");

/** Vue d'ensemble : chiffres clés, chronologie, classements et flux en direct. */
export function Overview() {
  const stats = useApi<OverviewStats>("/api/v1/stats/overview", 5000);
  const data = stats.status === "ready" ? stats.data : null;
  const show = (value: number | undefined) => (value === undefined ? "—" : number.format(value));

  return (
    <>
      {stats.status === "error" && <ErrorState message={stats.message} onRetry={stats.reload} />}

      <section className="grid grid--stats" aria-label="Chiffres clés">
        <StatCard label="Tentatives enregistrées" value={show(data?.events)} />
        <StatCard label="Adresses IP uniques" value={show(data?.unique_ips)} />
        <StatCard label="Sessions d'attaque" value={show(data?.sessions)} />
        <StatCard
          label="Menace maximale"
          value={data ? `${data.max_threat_score}/100` : "—"}
          hint={data?.rejected ? `${number.format(data.rejected)} événement(s) rejeté(s)` : undefined}
        />
      </section>

      {data?.events === 0 && (
        <p className="panel muted">
          La collecte a commencé. Aucune tentative n'a encore été enregistrée — c'est normal
          sur une instance neuve : les premiers balayages arrivent généralement dans l'heure.
        </p>
      )}

      <section className="panel" aria-labelledby="timeline-title">
        <div className="panel__head">
          <h2 id="timeline-title">Chronologie</h2>
          <span className="panel__hint">500 dernières tentatives</span>
        </div>
        <Timeline />
      </section>

      <div className="grid grid--2">
        <section className="panel" aria-labelledby="feed-title">
          <div className="panel__head">
            <h2 id="feed-title">En direct</h2>
            <span className="panel__hint">actualisé toutes les 3 s</span>
          </div>
          <AttackFeed />
        </section>

        <div className="grid">
          <section className="panel" aria-labelledby="services-title">
            <div className="panel__head">
              <h2 id="services-title">Par service</h2>
            </div>
            <ByService />
          </section>
          <section className="panel" aria-labelledby="ips-title">
            <div className="panel__head">
              <h2 id="ips-title">Adresses les plus actives</h2>
            </div>
            <TopSourceIps />
          </section>
        </div>
      </div>

      <section className="panel" aria-labelledby="creds-title">
        <div className="panel__head">
          <h2 id="creds-title">Identifiants les plus essayés</h2>
        </div>
        <TopCredentials />
      </section>
    </>
  );
}

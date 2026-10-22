import { AttackFeed } from "../components/attacks/AttackFeed";
import { ErrorState } from "../components/common/ErrorState";
import { StatCard } from "../components/common/StatCard";
import { ByService } from "../components/charts/ByService";
import { Timeline } from "../components/charts/Timeline";
import { TopCredentials } from "../components/charts/TopCredentials";
import { TopSourceIps } from "../components/charts/TopSourceIps";
import { CountryOrigins } from "../components/threat-map/CountryOrigins";
import { useApi } from "../hooks/useApi";
import type { Overview as OverviewStats } from "../types/events";

const number = new Intl.NumberFormat("fr-FR");
const ratio = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 2 });

/** Seuil du score au-delà duquel une tentative est traitée en alerte. */
const ALERT_SCORE = 60;

/** Vue d'ensemble : indicateurs, activité, répartition, flux en direct et origines. */
export function Overview() {
  const stats = useApi<OverviewStats>("/api/v1/stats/overview", 5000);
  const alerts = useApi<{ items: unknown[] }>("/api/v1/alerts?limit=500", 30_000);
  const data = stats.status === "ready" ? stats.data : null;
  const alertCount = alerts.status === "ready" ? alerts.data.items.length : null;
  const show = (value: number | undefined) => (value === undefined ? "—" : number.format(value));

  return (
    <>
      {stats.status === "error" && <ErrorState message={stats.message} onRetry={stats.reload} />}

      <section className="grid grid--stats" aria-label="Indicateurs">
        <StatCard label="Tentatives" value={show(data?.events)} hint="depuis la mise en service" />
        <StatCard label="IP uniques" value={show(data?.unique_ips)} hint="adresses sources distinctes" />
        <StatCard
          label="Sessions"
          value={show(data?.sessions)}
          hint={data?.sessions ? `${ratio.format(data.events / data.sessions)} tentative(s) par session` : undefined}
        />
        <StatCard
          label="Score de menace max"
          value={data ? data.max_threat_score : "—"}
          unit="/100"
          tone={data && data.max_threat_score >= ALERT_SCORE ? "danger" : undefined}
          hint={alertCount === null ? undefined : `${number.format(alertCount)} alerte(s) déclenchée(s)`}
        />
        <StatCard
          label="Rejetés à l'ingestion"
          value={show(data?.rejected)}
          hint={data ? (data.rejected ? "à examiner dans les journaux" : "aucune perte détectée") : undefined}
        />
      </section>

      {data?.events === 0 && (
        <p className="panel muted">
          La collecte a commencé. Aucune tentative n'a encore été enregistrée — c'est normal
          sur une instance neuve : les premiers balayages arrivent généralement dans l'heure.
        </p>
      )}

      <div className="grid grid--wide">
        <section className="panel" aria-labelledby="activity-title">
          <div className="panel__head">
            <h2 id="activity-title">Activité</h2>
            <span className="panel__hint">rouge : tranche avec une menace ≥ {ALERT_SCORE}</span>
          </div>
          <Timeline />
        </section>
        <section className="panel" aria-labelledby="services-title">
          <div className="panel__head">
            <h2 id="services-title">Répartition par leurre</h2>
          </div>
          <ByService />
        </section>
      </div>

      <div className="grid grid--wide">
        <section className="panel panel--flush" aria-labelledby="feed-title">
          <div className="panel__head">
            <h2 id="feed-title">Flux en direct</h2>
            <a className="panel__hint" href="#/journal">
              Tous les événements →
            </a>
          </div>
          <AttackFeed />
        </section>

        <div className="grid">
          <section className="panel" aria-labelledby="origins-title">
            <div className="panel__head">
              <h2 id="origins-title">Origine des IP</h2>
            </div>
            <CountryOrigins />
          </section>
          <section className="panel" aria-labelledby="ips-title">
            <div className="panel__head">
              <h2 id="ips-title">Adresses les plus actives</h2>
              <a className="panel__hint" href="#/defense">
                bloquer →
              </a>
            </div>
            <TopSourceIps />
          </section>
          <section className="panel" aria-labelledby="creds-title">
            <div className="panel__head">
              <h2 id="creds-title">Identifiants les plus essayés</h2>
            </div>
            <TopCredentials />
          </section>
        </div>
      </div>
    </>
  );
}

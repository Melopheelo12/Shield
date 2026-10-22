import { useEffect, useRef, type ReactNode } from "react";
import { useApi } from "../../hooks/useApi";
import type { NormalizedEvent, Verdict } from "../../types/events";
import { decodePayload } from "../../utils/base64";
import { PROFILES, TECHNIQUES } from "../../utils/constants";
import { formatTimestamp } from "../../utils/format";
import { countryName } from "../../utils/geo";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { threatLevel } from "../common/ThreatScore";
import { RuleContributions } from "./RuleContributions";
import { SessionSummary } from "./SessionSummary";

/** Seuil du score au-delà duquel une tentative est traitée en alerte. */
const ALERT_SCORE = 60;

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** Score de menace avec sa jauge et le repère du seuil d'alerte, comme dans le design. */
function ScoreGauge({ score }: { score: number }) {
  return (
    <div className="gauge">
      <span className="muted">Score de menace</span>
      <span className={`gauge__value gauge__value--${threatLevel(score)}`}>
        {score}
        <small>/100</small>
      </span>
      <div className="gauge__track" role="img" aria-label={`Score ${score} sur 100, seuil d'alerte à ${ALERT_SCORE}`}>
        <div className={`gauge__fill rules__segment--${threatLevel(score)}`} style={{ width: `${score}%` }} />
        <div className="gauge__mark" style={{ left: `${ALERT_SCORE}%` }} />
      </div>
      <span className="muted gauge__note">Repère blanc : seuil d'alerte à {ALERT_SCORE}</span>
    </div>
  );
}

/** Détail d'une tentative et son verdict explicable (US-26). Échap ou le bouton ferment. */
export function AttackDetailDrawer({ event, onClose }: { event: NormalizedEvent; onClose: () => void }) {
  const verdict = useApi<Verdict>(`/api/v1/events/${encodeURIComponent(event.event_id)}/verdict`);
  const closeButton = useRef<HTMLButtonElement>(null);
  const payload = decodePayload(event.payload);

  useEffect(() => {
    closeButton.current?.focus();
    const onKey = (key: KeyboardEvent) => key.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} aria-hidden="true" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <header className="drawer__head">
          <div className="drawer__title">
            <h2 id="drawer-title" className="mono">
              {event.source_ip}
            </h2>
            <span className="pill">Leurre {event.service.toUpperCase()}</span>
            {verdict.status === "ready" && (
              <span className={`pill pill--${threatLevel(verdict.data.threat_score)}`}>
                {PROFILES[verdict.data.profile] ?? verdict.data.profile}
              </span>
            )}
          </div>
          <button ref={closeButton} type="button" onClick={onClose} aria-label="Fermer le détail">
            ✕
          </button>
        </header>

        <ScoreGauge score={event.threat_score} />

        <section className="drawer__section" aria-labelledby="verdict-title">
          <h3 id="verdict-title">Verdict de l'agent défenseur</h3>
          {verdict.status === "loading" && <LoadingState />}
          {verdict.status === "error" && <ErrorState message={verdict.message} onRetry={verdict.reload} />}
          {verdict.status === "ready" && <RuleContributions verdict={verdict.data} />}
        </section>

        <section className="drawer__section" aria-labelledby="attempt-title">
          <h3 id="attempt-title">Tentative</h3>
          <dl className="fields">
            <Field label="Horodatage">
              <span className="mono">{formatTimestamp(event.occurred_at)}</span>
            </Field>
            <Field label="Source">
              <span className="mono">
                {event.source_ip}:{event.source_port}
              </span>
            </Field>
            <Field label="Port visé">
              <span className="mono">{event.dest_port}</span>
            </Field>
            <Field label="Identifiant">
              <span className="mono">{event.username || "—"}</span>
            </Field>
            <Field label="Mot de passe">
              <span className="mono">{event.password || "—"}</span>
            </Field>
          </dl>
        </section>

        <section className="drawer__section" aria-labelledby="enrich-title">
          <h3 id="enrich-title">Enrichissement</h3>
          <dl className="fields">
            <Field label="Pays">{event.country_code ? countryName(event.country_code) : "non situé"}</Field>
            <Field label="Opérateur">
              <span className="mono">
                {event.asn ? `AS${event.asn}${event.as_org ? ` · ${event.as_org}` : ""}` : "—"}
              </span>
            </Field>
            <Field label="Réputation">
              {event.reputation_score === null ? (
                <span className="muted">non évaluée</span>
              ) : (
                <>
                  <span className={`mono gauge__value--${threatLevel(event.reputation_score)}`}>
                    {event.reputation_score}/100
                  </span>{" "}
                  <span className="muted">AbuseIPDB</span>
                </>
              )}
            </Field>
            <Field label="ATT&CK">
              {event.technique_id ? (
                <>
                  <span className="pill mono">{event.technique_id}</span> {TECHNIQUES[event.technique_id] ?? ""}
                </>
              ) : (
                "non classé"
              )}
            </Field>
          </dl>
        </section>

        {event.session_id && (
          <section className="drawer__section" aria-labelledby="session-title">
            <h3 id="session-title">Session de cet attaquant</h3>
            <SessionSummary sessionId={event.session_id} />
          </section>
        )}

        <section className="drawer__section" aria-labelledby="payload-title">
          <h3 id="payload-title">
            Charge capturée <span className="muted">· {payload.bytes} octets</span>
            {event.payload_truncated && <span className="muted"> · tronquée</span>}
          </h3>
          <p className="muted drawer__note">Stockée inerte · jamais interprétée ni exécutée</p>
          {event.payload_sha256 && (
            <p className="muted mono truncate" title={event.payload_sha256}>
              SHA-256 {event.payload_sha256}
            </p>
          )}
          {payload.bytes === 0 ? (
            <p className="muted">Aucune donnée envoyée.</p>
          ) : (
            <pre className="payload">{payload.text}</pre>
          )}
        </section>
      </aside>
    </>
  );
}

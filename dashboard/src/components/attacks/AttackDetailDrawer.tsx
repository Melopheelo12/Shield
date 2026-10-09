import { useEffect, useRef, type ReactNode } from "react";
import { useApi } from "../../hooks/useApi";
import type { AttackerProfile, NormalizedEvent, Verdict } from "../../types/events";
import { decodePayload } from "../../utils/base64";
import { formatCountry, formatTimestamp } from "../../utils/format";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { RuleContributions } from "./RuleContributions";

const PROFILES: Record<AttackerProfile, string> = {
  balayage_opportuniste: "Balayage opportuniste",
  force_brute_ciblee: "Force brute ciblée",
  tentative_exploitation: "Tentative d'exploitation",
  indetermine: "Indéterminé",
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
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
          <h2 id="drawer-title">
            Tentative <span className={`service service--${event.service}`}>{event.service.toUpperCase()}</span>
          </h2>
          <button ref={closeButton} type="button" onClick={onClose} aria-label="Fermer le détail">
            ✕
          </button>
        </header>

        <dl className="fields">
          <Field label="Horodatage">{formatTimestamp(event.occurred_at)}</Field>
          <Field label="Source">
            <span className="mono">
              {event.source_ip}:{event.source_port}
            </span>
            {event.country_code && <> {formatCountry(event.country_code)}</>}
          </Field>
          <Field label="Port visé">{event.dest_port}</Field>
          <Field label="Identifiant">
            <span className="mono">{event.username || "—"}</span>
          </Field>
          <Field label="Mot de passe">
            <span className="mono">{event.password || "—"}</span>
          </Field>
          <Field label="Technique ATT&CK">{event.technique_id ?? "—"}</Field>
          <Field label="Session">
            <span className="mono">{event.session_id ?? "—"}</span>
          </Field>
        </dl>

        <section className="drawer__section" aria-labelledby="verdict-title">
          <h3 id="verdict-title">Verdict de l'agent défenseur</h3>
          {verdict.status === "loading" && <LoadingState />}
          {verdict.status === "error" && <ErrorState message={verdict.message} onRetry={verdict.reload} />}
          {verdict.status === "ready" && (
            <>
              <p>
                Profil : <strong>{PROFILES[verdict.data.profile] ?? verdict.data.profile}</strong>
              </p>
              <RuleContributions verdict={verdict.data} />
            </>
          )}
        </section>

        <section className="drawer__section" aria-labelledby="payload-title">
          <h3 id="payload-title">
            Charge utile <span className="muted">· {payload.bytes} octets</span>
            {event.payload_truncated && <span className="muted"> · tronquée</span>}
          </h3>
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

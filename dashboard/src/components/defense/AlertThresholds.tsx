import { useEffect, useState } from "react";
import {
  ALERTS,
  fieldFromServerError,
  METRICS,
  validateThresholds,
  type ChannelResult,
  type Metric,
  type Threshold,
  type ThresholdField,
  type ThresholdsResponse,
} from "../../api/alerts";
import { ApiError, sendJson } from "../../api/client";
import { useApi } from "../../hooks/useApi";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

const FIELD_LABELS: Record<ThresholdField, string> = {
  id: "identifiant",
  metric: "mesure",
  threshold: "seuil",
  window_seconds: "fenêtre",
  silence_seconds: "silence",
};

const NEW_THRESHOLD: Threshold = {
  id: "",
  metric: "events",
  threshold: 100,
  window_seconds: 300,
  silence_seconds: 3600,
  enabled: true,
};

type TestState = { status: "idle" | "pending" } | { status: "done"; channels: Record<string, ChannelResult> };

/**
 * Seuils d'alerte (US-31) : modifiables, enregistrés en base par le collecteur, et un
 * bouton « Tester » qui envoie une notification factice sur chaque canal configuré.
 */
export function AlertThresholds() {
  const config = useApi<ThresholdsResponse>(ALERTS.thresholds);
  const [items, setItems] = useState<Threshold[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [test, setTest] = useState<TestState>({ status: "idle" });

  const loaded = config.status === "ready" ? config.data : null;
  useEffect(() => {
    if (loaded) setItems(loaded.items);
  }, [loaded]);

  if (config.status === "loading" || (loaded && items === null)) return <LoadingState />;
  if (config.status === "error") return <ErrorState message={config.message} onRetry={config.reload} />;
  if (!loaded || items === null) return null;

  const errors = validateThresholds(items);
  const invalid = errors.some((fieldErrors) => Object.keys(fieldErrors).length > 0);
  const channels = loaded.channels;

  const update = (index: number, patch: Partial<Threshold>) => {
    setMessage(null);
    setItems(items.map((item, position) => (position === index ? { ...item, ...patch } : item)));
  };

  const save = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const saved = await sendJson<ThresholdsResponse>("PUT", ALERTS.thresholds, {
        items: items.map((item) => ({ ...item, id: item.id.trim() })),
      });
      setItems(saved.items);
      setMessage({ tone: "ok", text: "Seuils enregistrés." });
    } catch (error) {
      const detail = error instanceof ApiError ? error.detail : undefined;
      const field = fieldFromServerError(detail);
      setMessage({
        tone: "error",
        text: `Refusé par le collecteur${field ? ` (champ ${FIELD_LABELS[field]})` : ""} : ${detail ?? String(error)}`,
      });
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTest({ status: "pending" });
    try {
      const result = await sendJson<{ channels: Record<string, ChannelResult> }>("POST", ALERTS.test);
      setTest({ status: "done", channels: result.channels });
    } catch (error) {
      setTest({ status: "idle" });
      setMessage({ tone: "error", text: `Test impossible : ${String(error)}` });
    }
  };

  const numberField = (index: number, field: "threshold" | "window_seconds" | "silence_seconds", label: string) => (
    <td>
      <input
        type="number"
        min={field === "silence_seconds" ? 0 : 1}
        step={field === "threshold" ? "any" : 1}
        value={Number.isNaN(items[index][field]) ? "" : items[index][field]}
        aria-label={`${label} du seuil ${index + 1}`}
        aria-invalid={Boolean(errors[index][field])}
        onChange={(event) => update(index, { [field]: event.target.valueAsNumber })}
      />
      {errors[index][field] && <span className="field-error">{errors[index][field]}</span>}
    </td>
  );

  return (
    <div className="grid">
      <div className="table-scroll">
        <table className="data-table alert-table">
          <thead>
            <tr>
              <th scope="col">Identifiant</th>
              <th scope="col">Mesure</th>
              <th scope="col">Seuil</th>
              <th scope="col">Fenêtre (s)</th>
              <th scope="col">Silence (s)</th>
              <th scope="col">Actif</th>
              <th scope="col">
                <span className="visually-hidden">Supprimer</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, index) => (
              <tr key={index}>
                <td>
                  <input
                    value={item.id}
                    maxLength={64}
                    aria-label={`Identifiant du seuil ${index + 1}`}
                    aria-invalid={Boolean(errors[index].id)}
                    onChange={(event) => update(index, { id: event.target.value })}
                  />
                  {errors[index].id && <span className="field-error">{errors[index].id}</span>}
                </td>
                <td>
                  <select
                    value={item.metric}
                    aria-label={`Mesure du seuil ${index + 1}`}
                    onChange={(event) => update(index, { metric: event.target.value as Metric })}
                  >
                    {Object.entries(METRICS).map(([key, label]) => (
                      <option key={key} value={key}>
                        {label}
                      </option>
                    ))}
                  </select>
                </td>
                {numberField(index, "threshold", "Seuil")}
                {numberField(index, "window_seconds", "Fenêtre")}
                {numberField(index, "silence_seconds", "Silence")}
                <td>
                  <input
                    type="checkbox"
                    checked={item.enabled}
                    aria-label={`Seuil ${index + 1} actif`}
                    onChange={(event) => update(index, { enabled: event.target.checked })}
                  />
                </td>
                <td>
                  <button
                    type="button"
                    aria-label={`Supprimer le seuil ${item.id || index + 1}`}
                    onClick={() => setItems(items.filter((_, position) => position !== index))}
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="filter-bar">
        <button type="button" onClick={() => setItems([...items, { ...NEW_THRESHOLD }])}>
          Ajouter un seuil
        </button>
        <button type="button" onClick={save} disabled={saving || invalid}>
          {saving ? "Enregistrement…" : "Enregistrer"}
        </button>
        <button type="button" onClick={runTest} disabled={test.status === "pending" || channels.length === 0}>
          {test.status === "pending" ? "Envoi…" : "Tester les canaux"}
        </button>
      </div>

      <p role="status" aria-live="polite" className={message ? `export-result export-result--${message.tone === "ok" ? "ok" : "warn"}` : undefined}>
        {message?.text}
      </p>

      {channels.length === 0 ? (
        <p className="notice" role="note">
          Aucun canal configuré : les alertes sont seulement tracées dans l'historique. Renseignez
          DISCORD_WEBHOOK_URL ou SMTP_HOST et ALERT_EMAIL_TO dans le .env du collecteur.
        </p>
      ) : (
        <p className="muted">Canaux configurés : {channels.join(", ")}</p>
      )}
      {test.status === "done" && (
        <ul className="ip-list" aria-label="Résultat du test">
          {Object.entries(test.channels).map(([channel, result]) => (
            <li key={channel}>
              <span>{channel}</span>
              <span className={result === "sent" ? "muted" : "export-result--warn"}>
                {result === "sent" ? "envoyée ✓" : "échec ✕"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

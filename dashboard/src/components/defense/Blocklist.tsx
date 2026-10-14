import { useEffect, useMemo, useState } from "react";
import { getText } from "../../api/client";
import { buildBlocklist, FORMATS, parseBlocklist, type BlocklistFormat } from "../../utils/blocklist";
import { saveBlob } from "../../utils/download";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

const DAYS = [1, 7, 30, 90] as const;

type ListState = { status: "loading" } | { status: "ready"; text: string } | { status: "error"; message: string };

/**
 * Liste de blocage calculée par le collecteur (`GET /api/v1/blocklist`, US-43) :
 * les adresses dont le score atteint le seuil sur la période, les pires d'abord.
 *
 * Rien n'est appliqué depuis le navigateur : l'opérateur relit, copie et exécute.
 * Bloquer se décide humainement — un faux positif sur une adresse partagée coupe
 * aussi des utilisateurs légitimes.
 */
export function Blocklist() {
  const [minScore, setMinScore] = useState(60);
  const [days, setDays] = useState<number>(7);
  const [format, setFormat] = useState<BlocklistFormat>("ufw");
  const [copied, setCopied] = useState(false);
  const [list, setList] = useState<ListState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      getText("/api/v1/blocklist", { min_score: minScore, days }, controller.signal)
        .then((text) => setList({ status: "ready", text }))
        .catch((error: unknown) => {
          if (!controller.signal.aborted) setList({ status: "error", message: String(error) });
        });
    }, 250); // le curseur envoie une valeur par cran : on attend qu'il s'arrête
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [minScore, days, attempt]);

  const parsed = useMemo(() => parseBlocklist(list.status === "ready" ? list.text : ""), [list]);
  const output = buildBlocklist(parsed.ips, format);

  const copy = async () => {
    await navigator.clipboard.writeText(output);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="grid">
      <div className="filter-bar">
        <label>
          Score minimal : {minScore}
          <input
            type="range"
            min={1}
            max={100}
            value={minScore}
            onChange={(event) => setMinScore(Number(event.target.value))}
          />
        </label>
        <label>
          Vues depuis
          <select value={days} onChange={(event) => setDays(Number(event.target.value))}>
            {DAYS.map((value) => (
              <option key={value} value={value}>
                {value} jour{value > 1 ? "s" : ""}
              </option>
            ))}
          </select>
        </label>
        <label>
          Format
          <select value={format} onChange={(event) => setFormat(event.target.value as BlocklistFormat)}>
            {Object.entries(FORMATS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <button type="button" onClick={copy} disabled={!output}>
          {copied ? "Copié ✓" : "Copier"}
        </button>
        <button
          type="button"
          onClick={() => saveBlob(new Blob([output], { type: "text/plain" }), `shield-blocage-${format}.txt`)}
          disabled={!output}
        >
          Télécharger
        </button>
      </div>

      {list.status === "loading" && <LoadingState />}
      {list.status === "error" && <ErrorState message={list.message} onRetry={() => setAttempt((n) => n + 1)} />}
      {list.status === "ready" && parsed.rejected > 0 && (
        <p className="notice" role="note">
          {parsed.rejected} ligne(s) reçue(s) ne sont pas des adresses IP : écartées.
        </p>
      )}
      {list.status === "ready" &&
        (parsed.ips.length === 0 ? (
          <EmptyState title={`Aucune adresse avec un score ≥ ${minScore} sur ${days} jour(s).`} />
        ) : (
          <div className="grid grid--split">
            <div>
              <p className="muted">
                {parsed.ips.length.toLocaleString("fr-FR")} adresse(s), les plus menaçantes d'abord
              </p>
              <ul className="ip-list">
                {parsed.ips.slice(0, 50).map((ip) => (
                  <li key={ip}>
                    <span className="mono">{ip}</span>
                  </li>
                ))}
              </ul>
              {parsed.ips.length > 50 && <p className="muted">et {parsed.ips.length - 50} autre(s)</p>}
            </div>
            <pre className="payload payload--tall" aria-label="Commandes de blocage">
              {output}
            </pre>
          </div>
        ))}
    </div>
  );
}

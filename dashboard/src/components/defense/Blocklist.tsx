import { useMemo, useState } from "react";
import { STATS, type TopIpItem } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { buildBlocklist, FORMATS, type BlocklistFormat } from "../../utils/blocklist";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

/**
 * Générateur de liste de blocage à partir des adresses les plus actives.
 *
 * Rien n'est appliqué automatiquement : l'opérateur relit, copie et exécute. Bloquer
 * se décide humainement — un faux positif sur une adresse partagée coupe aussi des
 * utilisateurs légitimes. L'application par l'API viendra avec US-42 à US-44.
 */
export function Blocklist() {
  const stats = useApi<{ items: TopIpItem[] }>(STATS.topIps(100), 15_000);
  const [minScore, setMinScore] = useState(50);
  const [format, setFormat] = useState<BlocklistFormat>("ufw");
  const [copied, setCopied] = useState(false);

  const data = stats.status === "ready" ? stats.data : null;
  const candidates = useMemo(
    () => (data?.items ?? []).filter((item) => item.threat_score >= minScore),
    [data, minScore],
  );
  const output = buildBlocklist(
    candidates.map((item) => item.source_ip),
    format,
  );

  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;

  const copy = async () => {
    await navigator.clipboard.writeText(output);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  const download = () => {
    const url = URL.createObjectURL(new Blob([output], { type: "text/plain" }));
    const link = Object.assign(document.createElement("a"), { href: url, download: `shield-blocage-${format}.txt` });
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="grid">
      <div className="filter-bar">
        <label>
          Score minimal : {minScore}
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={minScore}
            onChange={(event) => setMinScore(Number(event.target.value))}
          />
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
        <button type="button" onClick={download} disabled={!output}>
          Télécharger
        </button>
      </div>

      {candidates.length === 0 ? (
        <EmptyState title={`Aucune adresse avec un score ≥ ${minScore}.`} />
      ) : (
        <div className="grid grid--split">
          <ul className="ip-list">
            {candidates.map((item) => (
              <li key={item.source_ip}>
                <span className="mono">{item.source_ip}</span>
                <span className="muted num">{item.events} tent.</span>
                <ThreatScore score={item.threat_score} />
              </li>
            ))}
          </ul>
          <pre className="payload payload--tall" aria-label="Commandes de blocage">
            {output}
          </pre>
        </div>
      )}
    </div>
  );
}

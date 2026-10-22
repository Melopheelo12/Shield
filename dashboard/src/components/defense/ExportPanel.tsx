import { useState } from "react";
import { EXPORT_RESULT as RESULT, exportEvents, type ExportFormat } from "../../api/exports";
import type { PseudonymizationState } from "../../utils/download";

/**
 * Export de tous les événements (US-42). Le mode réel est lu dans la réponse et
 * affiché après chaque export (US-47) : ce que le serveur a fait, pas ce qui était coché.
 */
export function ExportPanel() {
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [pseudonymize, setPseudonymize] = useState(true);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<{ state: PseudonymizationState; file: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setPending(true);
    setError(null);
    setResult(null);
    try {
      setResult(await exportEvents(format, pseudonymize));
    } catch (caught) {
      setError(`Export impossible : ${String(caught)}`);
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="grid">
      <div className="filter-bar">
        <label>
          Format
          <select value={format} onChange={(event) => setFormat(event.target.value as ExportFormat)}>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={pseudonymize} onChange={(event) => setPseudonymize(event.target.checked)} />
          Pseudonymiser
        </label>
        <button type="button" onClick={run} disabled={pending}>
          {pending ? "Export en cours…" : "Exporter"}
        </button>
      </div>
      <p role="status" aria-live="polite" className={result ? `export-result export-result--${RESULT[result.state].tone}` : undefined}>
        {result && (
          <>
            {RESULT[result.state].text} <span className="muted mono">{result.file}</span>
          </>
        )}
        {error && <span className="export-result--warn">{error}</span>}
      </p>
    </div>
  );
}

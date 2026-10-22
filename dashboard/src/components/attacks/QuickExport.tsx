import { useState } from "react";
import { EXPORT_RESULT, exportEvents } from "../../api/exports";
import type { PseudonymizationState } from "../../utils/download";

/**
 * « Exporter (IP pseudonymisées) » du design : export CSV pseudonymisé en un clic.
 * Le mode réel, lu dans la réponse, est annoncé après coup (US-47). Les autres
 * formats et l'export en clair restent sur la page Défense.
 */
export function QuickExport() {
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "warn"; text: string } | null>(null);

  const run = async () => {
    setPending(true);
    setMessage(null);
    try {
      const { state, file } = await exportEvents("csv", true);
      const result = EXPORT_RESULT[state as PseudonymizationState];
      setMessage({ tone: result.tone, text: `${result.text} (${file})` });
    } catch (caught) {
      setMessage({ tone: "warn", text: `Export impossible : ${String(caught)}` });
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="quick-export">
      <button type="button" onClick={run} disabled={pending}>
        {pending ? "Export en cours…" : "Exporter (IP pseudonymisées)"}
      </button>
      <p role="status" aria-live="polite" className={message ? `export-result export-result--${message.tone}` : undefined}>
        {message?.text}
      </p>
    </div>
  );
}

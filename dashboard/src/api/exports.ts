import { filenameFromDisposition, pseudonymizationState, saveBlob, type PseudonymizationState } from "../utils/download";
import { authorizedFetch } from "./client";

export type ExportFormat = "csv" | "json";

/** Message affiché après un export, selon le mode que le serveur a réellement appliqué (US-47). */
export const EXPORT_RESULT: Record<PseudonymizationState, { tone: "ok" | "warn"; text: string }> = {
  on: {
    tone: "ok",
    text: "Export pseudonymisé : adresses tronquées (IPv4 au /24, IPv6 au /48), mots de passe testés retirés.",
  },
  off: {
    tone: "warn",
    text: "Export NON pseudonymisé : adresses IP complètes et mots de passe testés, donc des données personnelles.",
  },
  unknown: { tone: "warn", text: "Mode inconnu : le collecteur n'a pas indiqué si l'export est pseudonymisé." },
};

/**
 * Exporte tous les événements (US-42) et propose le fichier. Le mode retourné est lu
 * dans `X-Shield-Pseudonymized` : ce que le serveur a fait, pas ce qui était demandé.
 */
export async function exportEvents(
  format: ExportFormat,
  pseudonymize: boolean,
): Promise<{ state: PseudonymizationState; file: string }> {
  const response = await authorizedFetch("/api/v1/export", { format, pseudonymize: String(pseudonymize) }, undefined, "*/*");
  const file = filenameFromDisposition(response.headers.get("Content-Disposition"), `shield-export.${format}`);
  saveBlob(await response.blob(), file);
  return { state: pseudonymizationState(response.headers.get("X-Shield-Pseudonymized")), file };
}

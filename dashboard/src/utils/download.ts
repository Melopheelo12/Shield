/** Nom de fichier annoncé par `Content-Disposition`, ou `fallback`. Jamais de chemin. */
export function filenameFromDisposition(header: string | null, fallback: string): string {
  const match = header?.match(/filename="?([^";]+)"?/i);
  const name = match?.[1].split(/[\\/]/).pop()?.trim();
  return name || fallback;
}

export type PseudonymizationState = "on" | "off" | "unknown";

/**
 * Mode réel de l'export, lu dans `X-Shield-Pseudonymized` (US-47, « jamais
 * silencieux ») : c'est le serveur qui fait foi, pas la case cochée.
 */
export function pseudonymizationState(header: string | null): PseudonymizationState {
  if (header === "true") return "on";
  if (header === "false") return "off";
  return "unknown";
}

/** Propose un fichier au téléchargement. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = Object.assign(document.createElement("a"), { href: url, download: filename });
  link.click();
  URL.revokeObjectURL(url);
}

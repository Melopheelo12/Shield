const timestampFormat = new Intl.DateTimeFormat("fr-FR", {
  dateStyle: "short",
  timeStyle: "medium",
});

/** Horodatage lisible, dans le fuseau du navigateur. */
export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : timestampFormat.format(date);
}

/** Drapeau emoji + code pays ; tiret tant que l'enrichissement n'est pas passé. */
export function formatCountry(code: string | null): string {
  if (!code || !/^[A-Z]{2}$/.test(code)) return "—";
  const flag = String.fromCodePoint(...[...code].map((char) => 0x1f1a5 + char.charCodeAt(0)));
  return `${flag} ${code}`;
}

/** Valeur saisie par l'attaquant : affichée telle quelle, jamais interprétée. */
export function formatAttackerText(value: string, max = 40): string {
  if (!value) return "—";
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

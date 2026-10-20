import type { ReactNode } from "react";

export interface BarItem {
  key: string;
  label: ReactNode;
  value: number;
  /** Texte à droite ; par défaut la valeur formatée. */
  detail?: ReactNode;
  /** Couleur de la barre (variable CSS), par défaut l'accent. */
  color?: string;
}

const number = new Intl.NumberFormat("fr-FR");

/**
 * Classement horizontal en CSS pur : plus lisible qu'un graphique pour un top 8,
 * et lu correctement par un lecteur d'écran (une liste, des nombres).
 */
export function BarList({ items, label }: { items: BarItem[]; label: string }) {
  const max = Math.max(1, ...items.map((item) => item.value));
  return (
    <ol className="bar-list" aria-label={label}>
      {items.map((item) => (
        <li key={item.key}>
          <div className="bar-list__row">
            <span className="truncate">{item.label}</span>
            <span className="num">{item.detail ?? number.format(item.value)}</span>
          </div>
          <div className="bar-list__track" aria-hidden="true">
            <div
              className="bar-list__fill"
              style={{
                width: `${(item.value / max) * 100}%`,
                background: item.color ?? "var(--accent)",
              }}
            />
          </div>
        </li>
      ))}
    </ol>
  );
}

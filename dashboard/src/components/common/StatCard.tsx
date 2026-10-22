import type { ReactNode } from "react";

interface Props {
  label: string;
  value: ReactNode;
  /** Unité affichée en petit après la valeur (« /100 »). */
  unit?: string;
  hint?: ReactNode;
  /** `danger` : la valeur passe en rouge (score au-dessus du seuil d'alerte). */
  tone?: "danger";
}

export function StatCard({ label, value, unit, hint, tone }: Props) {
  return (
    <div className="panel stat">
      <span className="stat__label">{label}</span>
      <span className={tone ? `stat__value stat__value--${tone}` : "stat__value"}>
        {value}
        {unit && <small className="stat__unit">{unit}</small>}
      </span>
      {hint && <span className="stat__hint">{hint}</span>}
    </div>
  );
}

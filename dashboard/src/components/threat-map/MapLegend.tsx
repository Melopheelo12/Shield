import { mapIntensity } from "./AttackMap";

/** Légende de l'échelle de couleur : sans elle, une teinte ne dit rien d'un nombre. */
export function MapLegend({ max }: { max: number }) {
  const steps = [1, Math.round(max / 4), Math.round(max / 2), max].filter(
    (value, index, all) => value > 0 && all.indexOf(value) === index,
  );
  return (
    <div className="map-legend" aria-label="Échelle : nombre de tentatives par pays">
      {steps.map((value) => (
        <span key={value} className="map-legend__step">
          <span
            className="map-legend__swatch"
            style={{ background: `color-mix(in srgb, var(--sev-critical) ${mapIntensity(value, max)}%, var(--surface-2))` }}
          />
          {value.toLocaleString("fr-FR")}
        </span>
      ))}
      <span className="muted">tentatives</span>
    </div>
  );
}

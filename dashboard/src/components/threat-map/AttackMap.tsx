import { geoEqualEarth, geoPath } from "d3-geo";
import { useMemo } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import type { CountryActivity } from "../../utils/geo";

const WIDTH = 960;
const HEIGHT = 470;

/** Part de rouge (en %) d'un pays : racine carrée, de 12 % (1 tentative) à 95 % (le maximum). */
export function mapIntensity(events: number, max: number): number {
  return 12 + Math.round(Math.sqrt(events / Math.max(1, max)) * 83);
}

// Fond de carte embarqué dans le bundle : la CSP de nginx interdit tout chargement externe.
const topology = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
const shapes = feature(topology, topology.objects.countries).features;
const projection = geoEqualEarth().fitSize([WIDTH, HEIGHT], { type: "Sphere" });
const path = geoPath(projection);

interface Props {
  countries: CountryActivity[];
  selected: string | null;
  onSelect: (code: string | null) => void;
}

/**
 * Carte des origines (US-21) : intensité de couleur proportionnelle au nombre de
 * tentatives, sur une échelle racine carrée pour qu'un pays très actif n'écrase pas
 * tous les autres dans la même teinte pâle.
 */
export function AttackMap({ countries, selected, onSelect }: Props) {
  const byNumeric = useMemo(
    () => new Map(countries.filter((c) => c.numeric).map((c) => [c.numeric as string, c])),
    [countries],
  );
  const max = Math.max(1, ...countries.map((c) => c.events));

  return (
    <svg
      className="attack-map"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="img"
      aria-label="Carte des pays d'origine des attaques"
    >
      <path className="attack-map__sphere" d={path({ type: "Sphere" }) ?? undefined} />
      {shapes.map((shape) => {
        const activity = byNumeric.get(String(shape.id));
        const intensity = activity ? mapIntensity(activity.events, max) : 0;
        const isSelected = activity && activity.code === selected;
        return (
          <path
            key={String(shape.id ?? shape.properties.name)}
            d={path(shape) ?? undefined}
            className={`attack-map__country${activity ? " attack-map__country--hit" : ""}${isSelected ? " is-selected" : ""}`}
            style={
              activity
                ? { fill: `color-mix(in srgb, var(--sev-critical) ${intensity}%, var(--surface-2))` }
                : undefined
            }
            onClick={activity ? () => onSelect(isSelected ? null : activity.code) : undefined}
          >
            <title>
              {activity
                ? `${activity.name} — ${activity.events.toLocaleString("fr-FR")} tentative(s)`
                : shape.properties.name}
            </title>
          </path>
        );
      })}
    </svg>
  );
}
